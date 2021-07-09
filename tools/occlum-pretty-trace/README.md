### occlum-pretty-trace

This tool is aimed to 
1. Simplify occlum's trace log(OCCLUM_LOG_LEVEL=trace) to output strace-style logs. 
    - Delete unuseful information (time, syscall number, extra syscall names)
    - Merge the entry and return value of the same syacall in one line (except delayed sycall,e.g. Wait4). Example: `[Getpid] { } = 113` 
    - For delayed syscall, print the enrty line and the return line in two seperate lines. Example: 
    `[T113][#10][Wait4] { pid = -1, _exit_status = 0x7f9955b73e8c, options = 0 } <unfinished ...>`  
    `................(other logs)`
    `[T113][#10][Wait4] <...resumed> = 122`
    - TODO: IO-related syscalls need more information(filename, etc.)
2. Check common bugs found in log.
    - File can't be found. This is done by following steps. (1) Find all error logs related to syscall `open` and `openAt`. (2) Find the corresponding filename in Debug log. (3) Determine which files are finally opened successfully, and the remaining ones are not opened.
    - Thread not exits normally.  This checks following points: (1)detect whether a thread will eventually call Exit(ExitGroup); and (2) whether a thread will perform other calls after calling Exit(ExitGroup) (3)special cases: A thread calling Execve will directly exit. <font color="#dd0000">Known Limitations：Threads may exit in signal handler , which may be false positive cases.</font><br />
3. Statistic on unimplemented syscalls. Count the number of occurrences of unimplement message in the error message
4. Filter logs by syscall name. Remove logs of specific syscalls.

### Usage example: `occlum-pretty-trace -i trace-file-name -o output-file-name -f futex,exit`


