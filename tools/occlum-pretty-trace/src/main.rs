use std::collections::{HashSet, HashMap};
use std::fs::{self, File};
use std::io::{Write, Read};
use std::str::FromStr;
use std::path::PathBuf;
use clap::{App, Arg, ArgMatches};
use regex::Regex;
#[macro_use]
extern crate lazy_static;
//regexes for pattern match
static TIME_PATTERN: &'static str = r"\[(?P<time>(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z)\]";
static LOG_LEVEL_PATTERN: &'static str = r"\[(TRACE|DEBUG|ERROR| INFO| WARN)\]";
static THREAD_PATTERN: &'static str = r"\[T(?P<thread_id>\d{1,})\]";
static SYSCALL_NUMBER_PATTERN: &'static str = r"\[#(?P<syscall_number>\d{1,})\]";
static SYSCALL_NAME_PATTERN: &'static str = r"\[·*(?P<syscall_name>[a-zA-Z]{1,}[0-9]*)\]";
static SYSCALL_ENTRY_PATTERN: &'static str = r"Syscall \{(?P<syscall_name> num = [a-zA-Z]+[0-9]*,?) ";
static SYSCALL_RETURN_PATTERN: &'static str = r"Retval = (?P<return_value>-?\d+)";
static DECORATOR_PATTERN: &'static str = r"\u{1b}\[\d+m";
static OPEN_AT_ABSOLUTE_PATTERN: &'static str = r"openat: fs_path: FsPath \{ (Absolute|CwdRelative)\((?P<file_path>.+)\) \},";
static OPEN_AT_RELATIVE_PATTERN: &'static str = r"openat: fs_path: FsPath \{ FdRelative\((?P<file_path>.+), \d+\) \}";
static FILENAME_PATTERN: &'static str = r".*/(?P<file_name>.*)$";
//compile regexes in advance
lazy_static! {
    static ref TIME_REGEX: Regex = {
        Regex::new(TIME_PATTERN).unwrap()
    };
    static ref LOG_LEVEL_REGEX: Regex = {
        Regex::new(LOG_LEVEL_PATTERN).unwrap()
    };
    static ref THREAD_REGEX: Regex = {
        Regex::new(THREAD_PATTERN).unwrap()
    };
    static ref SYSCALL_NUMBER_REGEX: Regex = {
        Regex::new(SYSCALL_NUMBER_PATTERN).unwrap()
    };
    static ref SYSCALL_NAME_REGEX: Regex = {
        Regex::new(SYSCALL_NAME_PATTERN).unwrap()
    };
    static ref DECORATOR_REGEX: Regex = {
        Regex::new(DECORATOR_PATTERN).unwrap()
    };
    static ref SYSCALL_ENTRY_REGEX: Regex = {
        Regex::new(SYSCALL_ENTRY_PATTERN).unwrap()
    };
    static ref SYSCALL_RETURN_REGEX: Regex = {
        Regex::new(SYSCALL_RETURN_PATTERN).unwrap()
    };
    static ref OPEN_AT_ABSOLUTE_REGEX: Regex = {
        Regex::new(OPEN_AT_ABSOLUTE_PATTERN).unwrap()
    };
    static ref OPEN_AT_RELATIVE_REGEX: Regex = {
        Regex::new(OPEN_AT_RELATIVE_PATTERN).unwrap()
    };
    static ref FILENAME_REGEX: Regex = {
        Regex::new(FILENAME_PATTERN).unwrap()
    };
}

#[derive(Debug, Clone)]
struct TraceOption {
    trace_filename: String,
    output_filename: String,
    filter_syscalls: HashSet<String>,
}

impl TraceOption {
    fn new(trace_filename: String, output_filename: String, filter_syscalls: HashSet<String>) -> Self {
        TraceOption {trace_filename, output_filename, filter_syscalls}
    }
}

impl TraceOption {
    //parse command line option with clap
    fn parse_option() -> Self {
        let matched = App::new("occlum-trace")
            .version("v1.0")
            .about("Tool to output strace-like log with occlum system log as input")
            .arg(Arg::with_name("trace-filename")
                .short("i")
                .long("input")
                .help("the input trace file name(required)")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("output-filename")
                .short("o")
                .long("output")
                .help("the output file name(required)")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("filter-syscall-name")
                .short("f")
                .long("filter")
                .help("syscall names to be filtered (case intensive). Example: -f Ioctl,Futex,Madvise")
                .takes_value(true)
            )
            .get_matches();
        parse_arg_matches(&matched)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum OcclumLogLevel {
    ERROR,
    WARN,
    INFO,
    DEBUG,
    TRACE,
}

impl OcclumLogLevel {
    fn from_str(log_level: &str) -> Self{
        if log_level.contains("ERROR") {
            OcclumLogLevel::ERROR
        } else if log_level.contains("WARN"){
            OcclumLogLevel::WARN
        } else if log_level.contains("INFO") {
            OcclumLogLevel::INFO
        } else if log_level.contains("DEBUG") {
            OcclumLogLevel::DEBUG
        } else if log_level.contains("TRACE") {
            OcclumLogLevel::TRACE
        } else {
            unreachable!()
        }
    }
}

//represents an occlum log. The resumed field is used to deal with delayed syscall.
#[derive(Debug, Clone)]
struct OcclumLog {
    log_time: String,
    log_level: OcclumLogLevel,
    thread_number: usize,
    syscall_number: usize,
    syscall_name: Option<String>,
    log_content: String,
    resumed: bool,
}

impl OcclumLog {
    fn parse_log_line(log_line: &str) -> Option<Self>{
        let mut start_index = 0;
        let time = find_matched_str(log_line, &TIME_REGEX, &mut start_index);
        let log_level = find_matched_str(log_line, &LOG_LEVEL_REGEX, &mut start_index);
        let thread_number = find_matched_str(log_line, &THREAD_REGEX, &mut start_index);
        let syscall_number = find_matched_str(log_line, &SYSCALL_NUMBER_REGEX, &mut start_index);
        let syscall_name = find_matched_str(log_line, &SYSCALL_NAME_REGEX, &mut start_index);
    
        if time == None || log_level == None || thread_number == None || syscall_number == None {
            return None;
        }
    
        let time = read_content_from_text::<String>(time.unwrap(), &TIME_REGEX, "time");
        let log_level = OcclumLogLevel::from_str(log_level.unwrap());
        let thread_number = read_content_from_text::<usize>(thread_number.unwrap(), &THREAD_REGEX, "thread_id");
        let syscall_number = read_content_from_text::<usize>(syscall_number.unwrap(), &SYSCALL_NUMBER_REGEX, "syscall_number");
        let syscall_name = match syscall_name {
            None => None,
            Some(name) => {
                let syscall_name = read_content_from_text::<String>(name, &SYSCALL_NAME_REGEX, "syscall_name");
                Some(syscall_name)
            }
        };
    
        let mut log_content = log_line.split_at(start_index).1.to_string();
        let decorator = find_matched_str(log_line, &DECORATOR_REGEX, &mut start_index);
        if let Some(decorator_str) = decorator {
            log_content = log_content.replace(decorator_str, "").trim().to_string();
        }
        
        Some(OcclumLog {
            log_time: time,
            log_level: log_level,
            thread_number: thread_number,
            syscall_number: syscall_number,
            syscall_name: syscall_name,
            log_content: log_content,
            resumed: false,
        })
    }

    //how to format a log to a string, which depends on what information we want to keep in the log
    fn format_string(&self, with_time: bool, with_log_level: bool, with_thread_number: bool, with_syscall_number: bool, with_syscall_name: bool) -> String {
        let time_str = format!("[{}]", self.log_time);
        let log_level_str = format!("[{:?}]", self.log_level);
        let thread_number_str = format!("[T{}]", self.thread_number);
        let syscall_number_str = format!("[#{}]", self.syscall_number);
        let syscall_name_str = match &self.syscall_name {
            None => "".to_string(),
            Some(syscall_name) => format!("[{}] ", syscall_name),
        };

        let mut res = String::new();
        if with_time {
            res.push_str(&time_str);
        }
        if with_log_level {
            res.push_str(&log_level_str);
        }
        if with_thread_number || self.resumed {
            res.push_str(&thread_number_str);
        }
        if with_syscall_number || self.resumed {
            res.push_str(&syscall_number_str);
        }
        if with_syscall_name {
            res.push_str(&syscall_name_str);
        }
        res.push_str(&self.log_content);

        if self.log_level == OcclumLogLevel::ERROR {
            return decorate(FontColor::RedForError, &res);
        } else if self.log_level == OcclumLogLevel::WARN {
            return decorate(FontColor::YellowForWarn, &res);
        } else if self.log_level == OcclumLogLevel::INFO {
            return decorate(FontColor::GreenForInfo, &res);
        } else {
            return decorate(FontColor::NormalForTrace, &res);
        }
    }

    fn to_string(&self) -> String {
        if self.level_above_info() {
            self.format_string(false, true, true, false, true)
        }else {
            self.format_string(false, false, true, false, true)
        }
    }

    fn level_above_info(&self) -> bool {
        if self.log_level == OcclumLogLevel::INFO || self.log_level == OcclumLogLevel::WARN || self.log_level == OcclumLogLevel::ERROR {
            true
        } else {
            false
        }
    }

    fn resume_log(&mut self) {
        self.resumed = true;
    }
}

enum FontColor {
    GreenForInfo,
    YellowForWarn,
    RedForError,
    NormalForTrace,
    Blue,
}

//print string with color decorated.
fn decorate(color: FontColor, content: &str) -> String{
    let decorator_color = match color {
        FontColor::YellowForWarn => "33",
        FontColor::GreenForInfo => "32",
        FontColor::RedForError => "31",
        FontColor::NormalForTrace => "0",
        FontColor::Blue => "34",
    };
    let csi = "\u{1b}";
    let formatted_string = format!("{}[{}m{}{}[0m", csi, decorator_color, content, csi);
    formatted_string
}

fn parse_arg_matches(matched: &ArgMatches) -> TraceOption {
    if let Some(filename) = matched.value_of("trace-filename") {
        if let Some(output) = matched.value_of("output-filename") {
            let syscall_name_list:HashSet<String> = match matched.value_of("filter-syscall-name") {
                Some(syscall_names) => {
                    parse_syacall_name_list(syscall_names)
                },
                None => HashSet::new()
            };

            return TraceOption::new(
                filename.to_string(), 
                output.to_string(),
                syscall_name_list,
            );
        }
    } 
    println!("Invalid options");
    std::process::exit(-1);
}

fn parse_syacall_name_list(syscall_names: &str) -> HashSet<String> {
    let mut res = HashSet::new();
    let syscall_name_spilt: Vec<&str> = syscall_names.split(',').collect();
    for syscall_name in syscall_name_spilt {
        let to_filter = syscall_name.trim().to_string().to_ascii_lowercase();
        if to_filter.len() > 0 {
            res.insert(to_filter);
        }
    }
    res
}

fn read_trace_file(filename: &str) -> Vec<OcclumLog>{
    let mut input_file = std::fs::File::open(filename).expect(format!("Invalid file name: {}", filename).as_str());
    let mut s = String::new();
    input_file.read_to_string(&mut s).expect(format!("cannot read content from {}", filename).as_str());
    let input_lines : Vec<_> = s.split('\n').collect();

    let mut res = Vec::new();
    for line in input_lines {
        let log = OcclumLog::parse_log_line(line);
        if let Some(log) = log {
            res.push(log);
        }
    }
    res
}

fn find_matched_str<'a>(line: &'a str, regex_: &Regex, start_index: &mut usize) -> Option<&'a str> {
    let match_ = regex_.find_at(line, *start_index);
    let res = {
        if let Some(match_str) = match_ {
            *start_index = match_str.start();
            match_str.as_str()
        } else {
            return None;
        }
    };
    *start_index = *start_index + res.len();
    Some(res)
}

fn read_content_from_text<T>(text: &str, regex_: &Regex, content_name: &str) -> T where T: FromStr{
    let caps = regex_.captures(text).unwrap();
    (&caps[content_name]).to_string().parse::<T>().ok().unwrap()
}

//This function inputs raw occlum logs and outputs strace-style logs
//This function will (1) delete unuseful information (time, syscall number, extra syscall names)
// (2) marge syscall entry and return value in one line
// (3) For delayed syscall, print the enrty line and the return line in two seperate lines.
fn simplify_trace(logs: &Vec<OcclumLog>) -> Vec<OcclumLog>{
    let mut syscall_entry: HashMap<(usize, usize), OcclumLog> = HashMap::new();
    let mut syscall_resume = HashSet::new();
    let mut reduced_logs = Vec::new();
    
    for log in logs {
        //logs above info are kept
        if log.level_above_info() {
            reduced_logs.push(log.clone());
        } else {
            if let Some(matched_entry) = find_matched_str(&log.log_content, &SYSCALL_ENTRY_REGEX, &mut 0){
                //syscall entry: the entry of a syscall. This log will be stored in a Hashmap(until we meet the corresponding syscall return). 
                //If the syscall_entry map is not empty, the entries in the map stands for entries of delayed syscalls. This entries are moved to syscall_resume.
                for ((thread_number,syscall_number), log) in &syscall_entry {
                    let mut resumed_log = log.clone();
                    resumed_log.resume_log();
                    syscall_resume.insert((thread_number.clone(), syscall_number.clone()));
                    resumed_log.log_content = format!("{} <unfinished ...>", resumed_log.log_content);
                    reduced_logs.push(resumed_log);
                }
                syscall_entry.clear();

                //remove extra syscall names from the entry log.
                let to_replace = read_content_from_text::<String>(matched_entry, &SYSCALL_ENTRY_REGEX, "syscall_name");
                let mut new_log = log.clone();
                new_log.log_content = new_log.log_content.replace(&to_replace, "").replace("Syscall ", "");
                syscall_entry.insert((log.thread_number, log.syscall_number), new_log);
            }else if let Some(matched_return) = find_matched_str(&log.log_content, &SYSCALL_RETURN_REGEX, &mut 0){
                //syscall return: the return log of a syscall. First, we will see the syscall_entry hashmap. 
                //If there are entries in the map but not corresponding to the return log, they are entries of delayed syscalls.
                //Move these delayed syscalls to syscall_resume
                let return_value = read_content_from_text::<isize>(matched_return, &SYSCALL_RETURN_REGEX, "return_value");

                for ((thread_number,syscall_number), entry_log) in &syscall_entry {
                    if entry_log.thread_number == log.thread_number && entry_log.syscall_number == log.syscall_number {
                        continue;
                    }
                    let mut resumed_log = entry_log.clone();
                    resumed_log.resume_log();
                    syscall_resume.insert((thread_number.clone(), syscall_number.clone()));
                    resumed_log.log_content = format!("{} <unfinished ...>", resumed_log.log_content);
                    reduced_logs.push(resumed_log);
                }

                let entry_log = syscall_entry.get(&(log.thread_number, log.syscall_number));
                
                if let Some(entry_log) = entry_log {
                    let entry_log = entry_log.clone();
                    syscall_entry.clear();
                    syscall_entry.insert((log.thread_number, log.syscall_number), entry_log);
                }else {
                    syscall_entry.clear();   
                }

                //Find the corresponding syscall entry. If we find the entry in syscall_resume, this is the return log of a delayed syscall.
                //If we find the entry in syscall entry, merge the return log and entry log in one line. Otherwise, the return log has no corresponding log.
                // It's an error that should be dealt with.
                if syscall_resume.contains(&(log.thread_number, log.syscall_number)) {
                    let mut reduced_log = log.clone();
                    reduced_log.resume_log();
                    reduced_log.log_content = format!("<...resumed> = {}", return_value);
                    reduced_logs.push(reduced_log);
                    syscall_resume.remove(&(log.thread_number, log.syscall_number));
                }else if syscall_entry.contains_key(&(log.thread_number, log.syscall_number)) {
                    let mut reduced_log = syscall_entry.get(&(log.thread_number, log.syscall_number)).unwrap().clone();
                    reduced_log.log_content = format!("{} = {}", reduced_log.log_content, return_value);
                    reduced_logs.push(reduced_log);
                    syscall_entry.remove(&(log.thread_number, log.syscall_number));
                } else {
                    println!("unknown return log: {:?}", log);
                    unreachable!();
                }

            }else {
                //logs which are not above info and are not syscall entry or return
                //for logs do not represent syscall(syscall_name==None) or debug log, we just skip these logs.
                if log.syscall_name == None || log.log_level == OcclumLogLevel::DEBUG {
                    continue;
                }
                //for trace logs in other syscalls, current we don't want to deal with them, and put these syscalls in a white list.
                //However, if new trace logs are added, these should be re-considered.
                if let Some(s) = &log.syscall_name {
                    match s.as_str() {
                        "Clone" | "SpawnMusl" | "Pipe" | "Bind" | "Listen" | "Connect" | 
                        "Accept" | "Close" | "Statfs" | "Execve" | "Fstatfs" | "SpawnGlibc" | "Pipe2" => {},
                        _ => {
                            println!("{} is not covered", s.as_str());
                            unreachable!()
                        }
                    }
                }
            }
        }
    }

    //If there are more syscall entry logs than syscall return logs, there should be something wrong.
    if syscall_entry.len() != 0 && syscall_resume.len() != 0 {
        println!("Some syscall does not return.");
        unreachable!();
    }

    reduced_logs
}

fn _print_logs(logs: &Vec<OcclumLog>) {
    for log in logs {
        println!("{}", log.to_string());
    }
}

//create an empty file
fn ensure_empty_file(filename: &str) -> File{
    let path = PathBuf::from(filename);
    if path.is_dir(){
        let _ = fs::remove_dir_all(&path);
    }
    if path.is_file() {
        let _ = fs::remove_file(&path);
    }
    let file= fs::File::create(path).expect(format!("create file {} failed.", filename).as_str());
    file
}

//write log files
fn write_to_file(logs: &Vec<OcclumLog>, opt: &TraceOption) {
    let filename = opt.output_filename.as_str();
    let path = PathBuf::from(filename);
    if path.is_dir(){
        let _ = fs::remove_dir_all(&path);
    }
    if path.is_file() {
        let _ = fs::remove_file(&path);
    }
    let mut output_file= ensure_empty_file(filename);
    for log in logs {
        output_file.write(log.to_string().as_bytes()).expect(format!("write file {} failed.", filename).as_str());
        output_file.write("\n".as_bytes()).unwrap();
    }
}

//obtain the log related to open file: if syscall name = Open or OpenAt
//trace logs: syscall entry and syscall return
//debug logs: logs about file name
fn filter_open_logs(logs: &Vec<OcclumLog>) -> Vec<OcclumLog> {
    let mut open_logs = Vec::new();

    for log in logs {
        if let Some(syscall_name) = &log.syscall_name {
            match syscall_name.as_str() {
                "Open" | "Openat" => {
                    if log.log_level == OcclumLogLevel::TRACE {
                        if find_matched_str(&log.log_content, &SYSCALL_ENTRY_REGEX, &mut 0) != None ||
                        find_matched_str(&log.log_content, &SYSCALL_RETURN_REGEX, &mut 0) != None {
                            open_logs.push(log.clone());
                        }
                    }
                    if log.log_level == OcclumLogLevel::DEBUG {
                        if let Some(_) = find_matched_str(&log.log_content, &OPEN_AT_ABSOLUTE_REGEX, &mut 0){
                            open_logs.push(log.clone());
                        } else if let Some(_) = find_matched_str(&log.log_content, &OPEN_AT_RELATIVE_REGEX, &mut 0) {
                            open_logs.push(log.clone());
                        }
                    }
                },
                _ => {},
            }
        }
    }
    open_logs
}

//get the last filename from file path
fn get_filename_from_full_path(matched_string: &str, regex_: &Regex) -> String{
    let raw_filename = read_content_from_text::<String>(matched_string, regex_, "file_path").replace("\"", "");
    let filename = if raw_filename.contains("/") {
        read_content_from_text::<String>(&raw_filename, &FILENAME_REGEX, "file_name")
    } else {
        raw_filename
    };

    filename
}

//reserve for file alias use
fn file_alias(filename: &str) -> &str {
    lazy_static! {
        static ref ALIASES: HashMap<&'static str, &'static str> = {
            let m = HashMap::new();
            //m.insert("ld.so.cache", "libc.so.6");
            //m.insert("ld-musl-x86_64.path", "libgcc_s.so.1");
            m
        };
    }

    if ALIASES.contains_key(filename) {
        return ALIASES.get(filename).unwrap();
    } else {
        return filename;
    }
}

fn check_openfile_error(logs: &Vec<OcclumLog>) {
    println!("{}", decorate(FontColor::Blue, "----------------check open file error----------------"));
    let open_logs = filter_open_logs(logs);

    let mut unchecked_open = HashSet::new();
    let mut open_filename:HashMap<(usize, usize), String> = HashMap::new();
    let mut failed_open = HashSet::new();

    //if log.level=debug, read the filename
    //if log is syscall entry, add the log to unchecked_open
    //if log is syscall return: (1) if return value >=0(success), remove file from unchecked_open; remove file from failed_open(the file reopens successfully). 
    //(2) if return value <0, remove file from unchecked_open and add file to failed_open
    for open_log in &open_logs {
        if open_log.log_level == OcclumLogLevel::TRACE {
            if let Some(_) = find_matched_str(&open_log.log_content, &SYSCALL_ENTRY_REGEX, &mut 0) {
                unchecked_open.insert((open_log.thread_number, open_log.syscall_number));
            } else if let Some(matched_return) = find_matched_str(&open_log.log_content, &SYSCALL_RETURN_REGEX, &mut 0) {
                let return_value = read_content_from_text::<isize>(matched_return, &SYSCALL_RETURN_REGEX, "return_value");
                if unchecked_open.contains(&(open_log.thread_number, open_log.syscall_number)) {
                    if return_value >= 0 {
                        unchecked_open.remove(&(open_log.thread_number, open_log.syscall_number));
                        let filename = open_filename.get(&(open_log.thread_number, open_log.syscall_number)).unwrap().clone();
                        open_filename.remove(&(open_log.thread_number, open_log.syscall_number));
                        failed_open.remove(&filename);
                    } else {
                        unchecked_open.remove(&(open_log.thread_number, open_log.syscall_number));
                        let filename = open_filename.get(&(open_log.thread_number, open_log.syscall_number)).unwrap();
                        let filename = file_alias(filename).to_string();
                        failed_open.insert(filename);
                    }
                } else {
                    println!("dangling return log in open syscall.");
                    unreachable!()
                }
            } else {
                unreachable!();
            }
        } else if open_log.log_level == OcclumLogLevel::DEBUG {
            if let Some(matched_filename) = find_matched_str(&open_log.log_content, &OPEN_AT_ABSOLUTE_REGEX, &mut 0){
                let filename = get_filename_from_full_path(matched_filename, &OPEN_AT_ABSOLUTE_REGEX);
                open_filename.insert((open_log.thread_number, open_log.syscall_number), filename);
            } else if let Some(matched_filename) = find_matched_str(&open_log.log_content, &OPEN_AT_RELATIVE_REGEX, &mut 0) {
                let filename = get_filename_from_full_path(matched_filename, &OPEN_AT_RELATIVE_REGEX);
                open_filename.insert((open_log.thread_number, open_log.syscall_number), filename);
            } else {
                unreachable!();
            }
        } else {
            unreachable!();
        }
    }

    if failed_open.len() != 0 {
        println!("{}", decorate(FontColor::YellowForWarn, "files fail to open:"));
        for filename in &failed_open {
            println!("{}", filename);
        }
    }
}

//If one trace file contains logs from multiple test cases, there will be multiple threads of the same thread id.
//When we check logs on thread exit, since there are multiple cases in each process.
//If we mix different processes, we will miss some cases.
fn split_log_based_on_processes(logs: &Vec<OcclumLog>) -> Vec<Vec<OcclumLog>>{
    let mut res = Vec::new();
    let mut one_process:Vec<&OcclumLog> = Vec::new();
    let mut in_syscall_flag = false;

    for log in logs {
        let current_syscall_number = log.syscall_number;

        if current_syscall_number == 0 {
            if in_syscall_flag {
                in_syscall_flag = false;

                let mut one_res = Vec::new();
                for one_log in &one_process {
                    one_res.push((*one_log).clone());
                }
                one_process.clear();
                res.push(one_res);
            }
        } else {
            if !in_syscall_flag {
                in_syscall_flag = true;
            }
            if log.thread_number != 0 {
                one_process.push(log);
            }
        }
    }

    if one_process.len() != 0 {
        let mut one_res = Vec::new();
        for one_log in &one_process {
            one_res.push((*one_log).clone());
        }
        res.push(one_res);
    }
    res
}

fn find_first_log_by_thread_number(logs: &Vec<OcclumLog>, thread_number: &usize) -> OcclumLog {
    for log in logs {
        if log.thread_number == *thread_number {
            return log.clone();
        }
    }
    unreachable!()
}

//Some syscalls other than exit will also cause the threads to exit. We add these syscalls to the white list.
//current only "Execve"
fn check_white_list_thread(logs: &Vec<OcclumLog>, thread_number: &usize) -> bool{
    lazy_static! {
        static ref WHITE_LIST: Vec<&'static str> = {
            //Execve, Futex, Nanosleep, SetRobustList witnesses directly exit
            //ArchPrctl, Brk: Kill -9
            //vec!["Execve", "Futex", "Nanosleep", "SetRobustList", "ArchPrctl", "Brk"]
            vec!["Execve"]
        };
    }

    for log in logs {
        let syscall_name = log.syscall_name.clone().unwrap();
        if log.thread_number == *thread_number && WHITE_LIST.contains(&syscall_name.as_str()) {
            return true;
        } 
    }

    return false;
}

//In each process, if a thread id occurs, add it to all_threads; if we find an Exit/ExitGroup syscall, add it to exit_threads.
//if a thread id occurs when exit_threads contains such an id, then there's a run-after-exit error?
//If a thread finally does not exit, this thread may be hung out.
fn check_thread_exit_in_each_process(process_log: &Vec<OcclumLog>) {
    let mut all_threads: HashSet<usize> = HashSet::new();
    let mut exit_threads: HashSet<usize> = HashSet::new();

    for log in process_log {
        if let Some(syscall_name) = &log.syscall_name {
            if syscall_name.as_str() == "ExitGroup" || syscall_name.as_str() == "Exit" || log.log_content.contains("Thread exited") {
                if all_threads.contains(&log.thread_number) {
                    exit_threads.insert(log.thread_number);
                } else {
                    println!("{:?}", log);
                    unreachable!();
                }
            } else {
                all_threads.insert(log.thread_number);
                if exit_threads.contains(&log.thread_number) {
                    println!("thread log exists after exit :{:?}", log);
                    unreachable!()
                }
            }
        } else {
            unreachable!()
        }
    }

    let mut not_exit_thread_logs = Vec::new();
    if all_threads.len() != exit_threads.len() {  
        for thread in &all_threads {
            if !exit_threads.contains(thread) {
                if check_white_list_thread(process_log, thread) {
                    continue;
                }
                let found_log = find_first_log_by_thread_number(process_log, thread);
                not_exit_thread_logs.push(found_log);
            }
        }
    }

    if not_exit_thread_logs.len() != 0 {
        println!("Threads not exit:");
        for not_exit_thread_log in &not_exit_thread_logs {
            println!("{:?}", not_exit_thread_log);
        }
    }
}

fn check_thread_exit(logs: &Vec<OcclumLog>) {
    println!("{}", decorate(FontColor::Blue, "----------------check thread exit(not precise due to kill -9(thread killed))-------------------"));
    let process_logs = split_log_based_on_processes(logs);
    for process_log in &process_logs {
        check_thread_exit_in_each_process(process_log);
    }
}

fn count_unimplemented_syscalls(logs: &Vec<OcclumLog>) {
    println!("{}", decorate(FontColor::Blue, "----------------unimplemented syscalls statistics: ----------------"));
    let mut unimplemented_syscalls = HashMap::new();
    
    for log in logs {
        if log.log_level == OcclumLogLevel::ERROR && log.log_content.contains("(#38, Function not implemented)") {
            if let Some(ref syscall_name) = log.syscall_name {
                if !unimplemented_syscalls.contains_key(syscall_name) {
                    unimplemented_syscalls.insert(syscall_name.clone(), 1);
                } else {
                    let count = unimplemented_syscalls.get(syscall_name).unwrap().clone();
                    unimplemented_syscalls.insert(syscall_name.clone(), count + 1);
                }
            }
        }
    }

    for (syscall_name, count) in &unimplemented_syscalls {
        println!("{} : {}", syscall_name, count);
    }
}

fn filter_logs(logs: &Vec<OcclumLog>, opt: &TraceOption) -> Vec<OcclumLog> {
    println!("{}", decorate(FontColor::Blue, &format!("filtered syscalls: {:?}", opt.filter_syscalls)));
    let mut res = Vec::new();
    for log in logs.into_iter() {
        match &log.syscall_name {
            None => {
                res.push(log.clone());
            },  
            Some(syscall_name) => {
                if !opt.filter_syscalls.contains(&syscall_name.to_lowercase()) {
                    res.push(log.clone());
                }
            }
        }
    }
    res
}

fn main() {
    let opt = TraceOption::parse_option();
    println!("{}", decorate(FontColor::GreenForInfo, &format!("Trace file name: {}", opt.trace_filename)));

    let logs = read_trace_file(&opt.trace_filename);
    if logs.len() == 0 {
        println!("No logs can be found in trace file");
        std::process::exit(-1);
    }
    
    check_openfile_error(&logs);
    check_thread_exit(&logs);
    count_unimplemented_syscalls(&logs);

    let reduced_logs = simplify_trace(&logs);
    let filtered_logs = filter_logs(&reduced_logs, &opt);
    //_print_logs(&filtered_logs);
    write_to_file(&filtered_logs, &opt);
}
