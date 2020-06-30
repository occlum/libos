use std::ffi::{CStr, CString};
use std::path::Path;

use self::aux_vec::{AuxKey, AuxVec};
use self::exec_loader::{load_exec_file_to_vec, load_file_to_vec};
use self::spawn_attr::{spawn_attr_flags, spawnattr_t};
use super::elf_file::{ElfFile, ElfHeader, ProgramHeader, ProgramHeaderExt};
use super::process::ProcessBuilder;
use super::task::Task;
use super::thread::ThreadName;
use super::{table, task, ProcessRef, ThreadRef};
use crate::fs::{
    CreationFlags, File, FileDesc, FileTable, FsView, HostStdioFds, StdinFile, StdoutFile,
    ROOT_INODE,
};
use crate::prelude::*;
use crate::vm::ProcessVM;

mod aux_vec;
mod exec_loader;
mod init_stack;
mod init_vm;
pub mod spawn_attr;

/// Spawn a new process and execute it in a new host thread.
pub fn do_spawn(
    elf_path: &str,
    argv: &[CString],
    envp: &[CString],
    file_actions: &[FileAction],
    attr: Option<spawnattr_t>,
    current_ref: &ThreadRef,
) -> Result<pid_t> {
    let exec_now = true;
    do_spawn_common(
        elf_path,
        argv,
        envp,
        file_actions,
        attr,
        None,
        current_ref,
        exec_now,
    )
}

/// Spawn a new process but execute it later.
pub fn do_spawn_without_exec(
    elf_path: &str,
    argv: &[CString],
    envp: &[CString],
    file_actions: &[FileAction],
    host_stdio_fds: &HostStdioFds,
    current_ref: &ThreadRef,
) -> Result<pid_t> {
    let exec_now = false;
    do_spawn_common(
        elf_path,
        argv,
        envp,
        file_actions,
        None,
        Some(host_stdio_fds),
        current_ref,
        exec_now,
    )
}

fn do_spawn_common(
    elf_path: &str,
    argv: &[CString],
    envp: &[CString],
    file_actions: &[FileAction],
    attr: Option<spawnattr_t>,
    host_stdio_fds: Option<&HostStdioFds>,
    current_ref: &ThreadRef,
    exec_now: bool,
) -> Result<pid_t> {
    let new_process_ref = new_process(
        elf_path,
        argv,
        envp,
        file_actions,
        host_stdio_fds,
        current_ref,
    )?;

    let new_main_thread = new_process_ref
        .main_thread()
        .expect("the main thread is just created; it must exist");

    // Check spawn attribute here before exec.
    // Now only POSIX_SPAWN_SETPGROUP is supported for posix_spawnattr_t.
    // More attribute checker can be put here.
    if attr.is_some()
        && attr
            .unwrap()
            .is_set(spawn_attr_flags::POSIX_SPAWN_SETPGROUP)
    {
        // Process hasn't enqueued for exec yet.
        let is_executing = false;
        // We directly call trusted do_setpgid because the new process must be the child process
        // of this calling process.
        super::pgrp::do_setpgid(
            new_process_ref.pid(),
            attr.unwrap().get_pgrp(),
            is_executing,
        )?;
    } else {
        // By default, add new process to parent process group (child has the same process group as parent).
        let pgrp_ref = new_process_ref.pgrp();
        pgrp_ref.add_new_process(new_process_ref.clone());
    }
    debug!("process group:{:?}", new_process_ref.pgrp());
    debug!("non idle process all pgrp: {:?}", table::get_all_pgrp());

    if exec_now {
        task::enqueue_and_exec(new_main_thread);
    } else {
        task::enqueue(new_main_thread);
    };

    let new_pid = new_process_ref.pid();
    Ok(new_pid)
}

/// Create a new process and its main thread.
fn new_process(
    file_path: &str,
    argv: &[CString],
    envp: &[CString],
    file_actions: &[FileAction],
    host_stdio_fds: Option<&HostStdioFds>,
    current_ref: &ThreadRef,
) -> Result<ProcessRef> {
    let mut argv = argv.clone().to_vec();
    let (is_script, elf_buf) = load_exec_file_to_vec(file_path, current_ref)?;

    // elf_path might be different from file_path because file_path could lead to a script text file.
    // And intepreter will be the loaded ELF.
    let elf_path = if let Some(interpreter_path) = is_script {
        if argv.len() == 0 {
            return_errno!(EINVAL, "argv[0] not found");
        }
        argv.insert(0, CString::new(interpreter_path.as_str())?);
        argv[1] = CString::new(file_path)?; // script file needs to be the full path
        interpreter_path
    } else {
        file_path.to_string()
    };

    let ldso_path = "/lib/ld-musl-x86_64.so.1";
    let ldso_elf_buf = load_file_to_vec(ldso_path, current_ref)
        .cause_err(|e| errno!(e.errno(), "cannot load ld.so"))?;

    let exec_elf_file =
        ElfFile::new(&elf_buf).cause_err(|e| errno!(e.errno(), "invalid executable"))?;
    let ldso_elf_file =
        ElfFile::new(&ldso_elf_buf).cause_err(|e| errno!(e.errno(), "invalid ld.so"))?;

    let new_process_ref = {
        let process_ref = current_ref.process().clone();

        let vm = init_vm::do_init(&exec_elf_file, &ldso_elf_file)?;
        let auxvec = init_auxvec(&vm, &exec_elf_file)?;

        // Notify debugger to load the symbols from elf file
        let ldso_elf_base = vm.get_elf_ranges()[1].start() as u64;
        unsafe {
            occlum_gdb_hook_load_elf(
                ldso_elf_base,
                ldso_path.as_ptr() as *const u8,
                ldso_path.len() as u64,
            );
        }
        let exec_elf_base = vm.get_elf_ranges()[0].start() as u64;
        unsafe {
            occlum_gdb_hook_load_elf(
                exec_elf_base,
                elf_path.as_ptr() as *const u8,
                elf_path.len() as u64,
            );
        }

        let task = {
            let ldso_entry = {
                let ldso_range = vm.get_elf_ranges()[1];
                let ldso_entry =
                    ldso_range.start() + ldso_elf_file.elf_header().entry_point() as usize;
                if !ldso_range.contains(ldso_entry) {
                    return_errno!(EINVAL, "Invalid program entry");
                }
                ldso_entry
            };
            let user_stack_base = vm.get_stack_base();
            let user_stack_limit = vm.get_stack_limit();
            let user_rsp = init_stack::do_init(user_stack_base, 4096, &argv, envp, &auxvec)?;
            unsafe {
                Task::new(
                    ldso_entry,
                    user_rsp,
                    user_stack_base,
                    user_stack_limit,
                    None,
                )?
            }
        };
        let vm_ref = Arc::new(vm);
        let files_ref = {
            let files = init_files(current_ref, file_actions, host_stdio_fds)?;
            Arc::new(SgxMutex::new(files))
        };
        let fs_ref = Arc::new(SgxMutex::new(current_ref.fs().lock().unwrap().clone()));
        let sched_ref = Arc::new(SgxMutex::new(current_ref.sched().lock().unwrap().clone()));
        let rlimit_ref = Arc::new(SgxMutex::new(current_ref.rlimits().lock().unwrap().clone()));

        // Make the default thread name to be the process's corresponding elf file name
        let elf_name = elf_path.rsplit('/').collect::<Vec<&str>>()[0];
        let thread_name = ThreadName::new(elf_name);

        // By default, use parent process's process group.
        let pgrp_ref = process_ref.pgrp();

        ProcessBuilder::new()
            .vm(vm_ref)
            .exec_path(&elf_path)
            .parent(process_ref)
            .task(task)
            .sched(sched_ref)
            .rlimits(rlimit_ref)
            .fs(fs_ref)
            .pgrp(pgrp_ref)
            .files(files_ref)
            .name(thread_name)
            .build()?
    };

    table::add_process(new_process_ref.clone());
    table::add_thread(new_process_ref.main_thread().unwrap());

    info!(
        "Process created: elf = {}, pid = {}",
        elf_path,
        new_process_ref.pid()
    );

    Ok(new_process_ref)
}

#[derive(Debug)]
pub enum FileAction {
    /// open(path, oflag, mode) had been called, and the returned file
    /// descriptor, if not `fd`, had been changed to `fd`.
    Open {
        path: String,
        mode: u32,
        oflag: u32,
        fd: FileDesc,
    },
    Dup2(FileDesc, FileDesc),
    Close(FileDesc),
}

fn init_files(
    current_ref: &ThreadRef,
    file_actions: &[FileAction],
    host_stdio_fds: Option<&HostStdioFds>,
) -> Result<FileTable> {
    // Usually, we just inherit the file table from the current process
    let should_inherit_file_table = current_ref.process().pid() > 0;
    if should_inherit_file_table {
        // Fork: clone file table
        let mut cloned_file_table = current_ref.files().lock().unwrap().clone();
        // Perform file actions to modify the cloned file table
        for file_action in file_actions {
            match file_action {
                &FileAction::Open {
                    ref path,
                    mode,
                    oflag,
                    fd,
                } => {
                    let file =
                        current_ref
                            .fs()
                            .lock()
                            .unwrap()
                            .open_file(path.as_str(), oflag, mode)?;
                    let file_ref: Arc<Box<dyn File>> = Arc::new(file);
                    let creation_flags = CreationFlags::from_bits_truncate(oflag);
                    cloned_file_table.put_at(fd, file_ref, creation_flags.must_close_on_spawn());
                }
                &FileAction::Dup2(old_fd, new_fd) => {
                    let file = cloned_file_table.get(old_fd)?;
                    if old_fd != new_fd {
                        cloned_file_table.put_at(new_fd, file, false);
                    }
                }
                &FileAction::Close(fd) => {
                    // ignore error
                    cloned_file_table.del(fd);
                }
            }
        }
        // Exec: close fd with close_on_spawn
        cloned_file_table.close_on_spawn();
        return Ok(cloned_file_table);
    }

    // But, for init process, we initialize file table for it
    let mut file_table = FileTable::new();
    let stdin: Arc<Box<dyn File>> = Arc::new(Box::new(StdinFile::new(
        host_stdio_fds.unwrap().stdin_fd as FileDesc,
    )));
    let stdout: Arc<Box<dyn File>> = Arc::new(Box::new(StdoutFile::new(
        host_stdio_fds.unwrap().stdout_fd as FileDesc,
    )));
    let stderr: Arc<Box<dyn File>> = Arc::new(Box::new(StdoutFile::new(
        host_stdio_fds.unwrap().stderr_fd as FileDesc,
    )));

    file_table.put(stdin, false);
    file_table.put(stdout, false);
    file_table.put(stderr, false);
    Ok(file_table)
}

fn init_auxvec(process_vm: &ProcessVM, exec_elf_file: &ElfFile) -> Result<AuxVec> {
    let mut auxvec = AuxVec::new();
    auxvec.set(AuxKey::AT_PAGESZ, 4096)?;
    auxvec.set(AuxKey::AT_UID, 0)?;
    auxvec.set(AuxKey::AT_GID, 0)?;
    auxvec.set(AuxKey::AT_EUID, 0)?;
    auxvec.set(AuxKey::AT_EGID, 0)?;
    auxvec.set(AuxKey::AT_SECURE, 0)?;
    auxvec.set(AuxKey::AT_SYSINFO, 0)?;

    let exec_elf_base = process_vm.get_elf_ranges()[0].start() as u64;
    let exec_elf_header = exec_elf_file.elf_header();
    auxvec.set(AuxKey::AT_PHENT, exec_elf_header.ph_entry_size() as u64)?;
    auxvec.set(AuxKey::AT_PHNUM, exec_elf_header.ph_count() as u64)?;
    auxvec.set(AuxKey::AT_PHDR, exec_elf_base + exec_elf_header.ph_offset())?;
    auxvec.set(
        AuxKey::AT_ENTRY,
        exec_elf_base + exec_elf_header.entry_point(),
    )?;

    let ldso_elf_base = process_vm.get_elf_ranges()[1].start() as u64;
    auxvec.set(AuxKey::AT_BASE, ldso_elf_base)?;

    let syscall_addr = __occlum_syscall_linux_abi as *const () as u64;
    auxvec.set(AuxKey::AT_OCCLUM_ENTRY, syscall_addr)?;
    // TODO: init AT_EXECFN
    // auxvec.set_val(AuxKey::AT_EXECFN, "program_name")?;

    Ok(auxvec)
}

extern "C" {
    fn __occlum_syscall_linux_abi() -> i64;
    fn occlum_gdb_hook_load_elf(elf_base: u64, elf_path: *const u8, elf_path_len: u64);
}
