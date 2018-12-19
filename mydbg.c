#include <sys/ptrace.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <ctype.h>
#include "pmparser.h"

#define uint64_t unsigned long long

struct Breakpoints{
	uint64_t addr;
	uint64_t data;
} breakpoints[20];
struct Flags {
	uint64_t addr;
	char *name;
	int isnull;
} flags[20];
uint64_t prev_rip = 0;
const char *filename;
Elf64_Ehdr header;
struct user_regs_struct regs;
uint64_t baseaddr;

const char *name[] = {
    "read",
    "write",
    "open",
    "close",
    "stat",
    "fstat",
    "lstat",
    "poll",
    "lseek",
    "mmap",
    "mprotect",
    "munmap",
    "brk",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "ioctl",
    "pread",
    "pwrite",
    "readv",
    "writev",
    "access",
    "pipe",
    "select",
    "sched_yield",
    "mremap",
    "msync",
    "mincore",
    "madvise",
    "shmget",
    "shmat",
    "shmctl",
    "dup",
    "dup2",
    "pause",
    "nanosleep",
    "getitimer",
    "alarm",
    "setitimer",
    "getpid",
    "sendfile",
    "socket",
    "connect",
    "accept",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "shutdown",
    "bind",
    "listen",
    "getsockname",
    "getpeername",
    "socketpair",
    "setsockopt",
    "getsockopt",
    "clone",
    "fork",
    "vfork",
    "execve",
    "exit",
    "wait4",
    "kill",
    "uname",
    "semget",
    "semop",
    "semctl",
    "shmdt",
    "msgget",
    "msgsnd",
    "msgrcv",
    "msgctl",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "truncate",
    "ftruncate",
    "getdents",
    "getcwd",
    "chdir",
    "fchdir",
    "rename",
    "mkdir",
    "rmdir",
    "creat",
    "link",
    "unlink",
    "symlink",
    "readlink",
    "chmod",
    "fchmod",
    "chown",
    "fchown",
    "lchown",
    "umask",
    "gettimeofday",
    "getrlimit",
    "getrusage",
    "sysinfo",
    "times",
    "ptrace",
    "getuid",
    "syslog",
    "getgid",
    "setuid",
    "setgid",
    "geteuid",
    "getegid",
    "setpgid",
    "getppid",
    "getpgrp",
    "setsid",
    "setreuid",
    "setregid",
    "getgroups",
    "setgroups",
    "setresuid",
    "getresuid",
    "setresgid",
    "getresgid",
    "getpgid",
    "setfsuid",
    "setfsgid",
    "getsid",
    "capget",
    "capset",
    "rt_sigpending",
    "rt_sigtimedwait",
    "rt_sigqueueinfo",
    "rt_sigsuspend",
    "sigaltstack",
    "utime",
    "mknod",
    "uselib",
    "personality",
    "ustat",
    "statfs",
    "fstatfs",
    "sysfs",
    "getpriority",
    "setpriority",
    "sched_setparam",
    "sched_getparam",
    "sched_setscheduler",
    "sched_getscheduler",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_rr_get_interval",
    "mlock",
    "munlock",
    "mlockall",
    "munlockall",
    "vhangup",
    "modify_ldt",
    "pivot_root",
    "_sysctl",
    "prctl",
    "arch_prctl",
    "adjtimex",
    "setrlimit",
    "chroot",
    "sync",
    "acct",
    "settimeofday",
    "mount",
    "umount2",
    "swapon",
    "swapoff",
    "reboot",
    "sethostname",
    "setdomainname",
    "iopl",
    "ioperm",
    "create_module",
    "init_module",
    "delete_module",
    "get_kernel_syms",
    "query_module",
    "quotactl",
    "nfsservctl",
    "getpmsg",
    "putpmsg",
    "afs_syscall",
    "tuxcall",
    "security",
    "gettid",
    "readahead",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "getxattr",
    "lgetxattr",
    "fgetxattr",
    "listxattr",
    "llistxattr",
    "flistxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "tkill",
    "time",
    "futex",
    "sched_setaffinity",
    "sched_getaffinity",
    "set_thread_area",
    "io_setup",
    "io_destroy",
    "io_getevents",
    "io_submit",
    "io_cancel",
    "get_thread_area",
    "lookup_dcookie",
    "epoll_create",
    "epoll_ctl_old",
    "epoll_wait_old",
    "remap_file_pages",
    "getdents64",
    "set_tid_address",
    "restart_syscall",
    "semtimedop",
    "fadvise64",
    "timer_create",
    "timer_settime",
    "timer_gettime",
    "timer_getoverrun",
    "timer_delete",
    "clock_settime",
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "exit_group",
    "epoll_wait",
    "epoll_ctl",
    "tgkill",
    "utimes",
    "vserver",
    "mbind",
    "set_mempolicy",
    "get_mempolicy",
    "mq_open",
    "mq_unlink",
    "mq_timedsend",
    "mq_timedreceive",
    "mq_notify",
    "mq_getsetattr",
    "kexec_load",
    "waitid",
    "add_key",
    "request_key",
    "keyctl",
    "ioprio_set",
    "ioprio_get",
    "inotify_init",
    "inotify_add_watch",
    "inotify_rm_watch",
    "migrate_pages",
    "openat",
    "mkdirat",
    "mknodat",
    "fchownat",
    "futimesat",
    "newfstatat",
    "unlinkat",
    "renameat",
    "linkat",
    "symlinkat",
    "readlinkat",
    "fchmodat",
    "faccessat",
    "pselect6",
    "ppoll",
    "unshare",
    "set_robust_list",
    "get_robust_list",
    "splice",
    "tee",
    "sync_file_range",
    "vmsplice",
    "move_pages",
    "utimensat",
    "epoll_pwait",
    "signalfd",
    "timerfd",
    "eventfd",
    "fallocate",
    "timerfd_settime",
    "timerfd_gettime",
    "accept4",
    "signalfd4",
    "eventfd2",
    "epoll_create1",
    "dup3",
    "pipe2",
    "inotify_init1",
    "preadv",
    "pwritev",
    "rt_tgsigqueueinfo",
    "perf_event_open",
    "recvmmsg",
    "fanotify_init",
    "fanotify_mark",
    "prlimit64",
    "name_to_handle_at",
    "open_by_handle_at",
    "clock_adjtime",
    "syncfs",
    "sendmmsg",
    "setns",
    "getcpu",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    "finit_module",
    "sched_setattr",
    "sched_getattr",
    "renameat2",
    "seccomp",
    "getrandom",
    "memfd_create",
    "kexec_file_load",
    "bpf",
    "execveat",
};

void wait_for_signal(pid_t m_pid){
	int wait_status, options = 0;
	waitpid(m_pid, &wait_status, options);
}

uint64_t read_memory(pid_t m_pid, uint64_t address){
	return ptrace(PTRACE_PEEKTEXT, m_pid, address, NULL);
}

void write_memory(pid_t m_pid, uint64_t address, uint64_t value){
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

void dump_regs(pid_t m_pid, int print){
	if (ptrace(PTRACE_GETREGS, m_pid, NULL, (void *)&regs) < 0){
	    perror("regs");
	    exit(1);
	}
	if (print){
		printf("rip: 0x%08llx\n", regs.rip);
		printf("rax: 0x%08llx\n", regs.rax);
		printf("rbx: 0x%08llx\n", regs.rbx);
		printf("rcx: 0x%08llx\n", regs.rcx);
		printf("rdx: 0x%08llx\n", regs.rdx);
		printf("rsp: 0x%08llx\n", regs.rsp);
		printf("rbp: 0x%08llx\n", regs.rbp);
		printf("rsi: 0x%08llx\n", regs.rsi);
		printf("rdx: 0x%08llx\n", regs.rdx);
	}

	printf("rip: 0x%08llx\t\top : 0x%016llx\n", regs.rip, read_memory(m_pid, regs.rip));
	prev_rip = regs.rip;
}

void single_step(pid_t m_pid){
	dump_regs(m_pid, 0);

	if (ptrace(PTRACE_SINGLESTEP, m_pid, NULL, NULL) < 0){
		perror("step");
		return;
	}
	wait_for_signal(m_pid);
}

void continue_execution(pid_t m_pid){
	ptrace(PTRACE_CONT, m_pid, NULL, NULL);
	wait_for_signal(m_pid);
	write_memory(m_pid, breakpoints[0].addr, breakpoints[0].data);
}

void set_breakpoint(pid_t m_pid, uint64_t addr){
	breakpoints[0].addr = addr;
	breakpoints[0].data = read_memory(m_pid, addr);
	uint64_t data_with_trap = (breakpoints[0].data & 0xFFFFFF00) | 0xCC;
	write_memory(m_pid, addr, data_with_trap);
}

int read_elf_header() {
	FILE* file = fopen(filename, "rb");
	if(file) {
		fread(&header, 1, sizeof(header), file);

		// check so its really an elf file
		if (memcmp(header.e_ident, ELFMAG, SELFMAG) == 0) {
			fclose(file);
			return 1;
		}
	}
	return 0;
}

int virtual_memory(pid_t m_pid, int print){
	procmaps_struct* maps = pmparser_parse(m_pid);
	if (maps == NULL){
		printf("maps: cannot parse\n");
		return 0;
	}
	if (print){
		procmaps_struct* maps_tmp = NULL;

		while ((maps_tmp = pmparser_next()) != NULL){
			pmparser_print(maps_tmp,0);
			printf("------\n");
		}
	}

	baseaddr =(uint64_t) maps[0].addr_start;
	pmparser_free(maps);
	return 1;
}

void print_disas(int len, uint64_t addr){
	FILE *f;
	f = fopen(filename, "rb");
	uint64_t *data;
	printf("entry: %lx\n",header.e_entry);
	fseek(f, addr, SEEK_SET);
	fread(&data, sizeof(uint64_t), 1, f);
	for (int i=0; i<len; i++)
		printf("%llx\n", data[i]);
}

void add_flag(char* flag, uint64_t addr){
	for (int i=0; i<20; i++){
		if (flags[i].isnull){

			flags[i].name = (char *) malloc(strlen(flag));
			strcpy(flags[i].name, flag);
			flags[i].addr = addr;
			flags[i].isnull = 0;
			return;
		}
	}
	perror("no breakpoints free left");
}

uint64_t flag_to_addr(char *flag){
	for (int i=0; i<20; i++){
		if (!flags[i].isnull && strcmp(flag, flags[i].name) == 0)
			return flags[i].addr;
	}
	perror("unmapped memory");
	return 0;
}

int parent_main(pid_t pid) {
	int wait_status;
	char command[255];

	waitpid(pid, &wait_status, 0);
	ptrace(PTRACE_GETREGS, pid, NULL, (void *)&regs);
	read_elf_header();
	printf("entrypoint is at 0x%lx\n", header.e_entry);
	virtual_memory(pid, 0);
	printf("base address is at 0x%08llx\n", baseaddr);
	flags[0].name = (char *) malloc(strlen("entry0"));
	strcpy(flags[0].name, "entry0");
	flags[0].isnull = 0;
	flags[0].addr = baseaddr + header.e_entry;

	printf("\ndbg> ");
	while(scanf("%s", command) > 0){

		if (strcmp(command, "ds") == 0){
			single_step(pid);
		}
		else if (strcmp(command, "dr") == 0){
			dump_regs(pid, 1);
		}
		else if (strcmp(command, "dc") == 0){
			continue_execution(pid);
		}
		else if (strcmp(command, "db") == 0){
			uint64_t addr;
			char input[255];
			scanf("%s", input);
			int l = strlen(input);
			int found = 0;
			for (int i=0; i<l; i++){
				if (!isdigit(input[i])){
					found = 1;
				}
			}
			if (found){
				addr = flag_to_addr(input);
				if (addr != 0)
					printf("%s -> 0x%8llx\n",input, addr);
			}
			else
				addr = atol(input);
			set_breakpoint(pid, addr);
		}
		else if (strcmp(command, "pd") == 0){
			int len;
			uint64_t addr;
			scanf("%d %llx", &len, &addr);
			print_disas(len, addr);
		}

		else if (strcmp(command, "f") == 0){
			char name[255];
			uint64_t addr;
			scanf("%s %llx", name, &addr);
			add_flag(name, addr);
		}
		else if (strcmp(command, "q") == 0){
			kill(pid, SIGKILL);
			wait(&wait_status);
			exit(0);
		}
		else {
			printf("command not found\n");
		}
		char a;
		while ((a = getchar()) != 0xa);
		printf("\ndbg> ");
	}
	return 0;
}

int child_main(const char *filename, char *argv[]) {
	int result;

	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	result = execvp(filename, argv);

	if (result) {
		perror("execvp");
		return result;
	}
	printf("[bug] never reached here.\n");
	return 0;
}

int main(int argc, char *argv[]) {
  pid_t pid;
  int result;

  for (int i=0; i<20; i++){
	  flags[i].isnull = 1;
  }

  if (argc < 2) {
    printf("usage: \n%s execfile [options]\n", argv[0]);
    return 0;
  }

  filename = argv[1];

  pid = fork();
  if (pid) {
    // parent
    fprintf(stderr, "%5d: child started\n", pid);

    result = parent_main(pid);
  } else {
    // child
    result = child_main(filename, &argv[1]);
  }

  return result;
}
