#include "mydbg.h"

siginfo_t get_signal_info(pid_t m_pid){
	siginfo_t info;
	ptrace(PTRACE_GETSIGINFO, m_pid, NULL, &info);
	return info;
}

void wait_for_signal(pid_t m_pid){
	int wait_status, options = 0;

	waitpid(m_pid, &wait_status, options);
	ptrace(PTRACE_GETREGS, m_pid, NULL, &regs);
	switch (get_signal_info(m_pid).si_code){
	case SI_KERNEL:
	{
		struct Breakpoint breakpoint = breakpoint_addr_to_data(regs.rip-1);
		if (!breakpoint.is_null && breakpoint.is_enabled){
			write_memory(m_pid, breakpoint.addr, breakpoint.data);
			breakpoint.is_enabled=0;
			regs.rip = regs.rip-1;
			set_regs(m_pid, regs);
		}
		break;
	}
	}
	return;
}

uint64_t read_memory(pid_t m_pid, uint64_t address){
	return ptrace(PTRACE_PEEKTEXT, m_pid, address, NULL);
}

void write_memory(pid_t m_pid, uint64_t address, uint64_t value){
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

void dump_regs(pid_t m_pid, int print){
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
	return;
}

void set_regs(pid_t m_pid, struct user_regs_struct new_regs){
	ptrace(PTRACE_SETREGS, m_pid, NULL, &new_regs);
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
	dump_regs(m_pid, 0);
}

struct Breakpoint breakpoint_addr_to_data(uint64_t addr){
	for (int i=0; i<20; i++){
		if (!breakpoints[i].is_null && breakpoints[i].addr == addr){
			return breakpoints[i];
		}
	}
	struct Breakpoint breakpoint = {.addr=0, .data=0, .is_null=1};
	return breakpoint;
}

void add_breakpoint(pid_t m_pid, uint64_t addr){
	for (int i=0; i<20; i++){
		if (breakpoints[i].is_null){
			breakpoints[i].is_enabled = 1;
			breakpoints[i].is_null = 0;
			breakpoints[i].addr = addr;
			breakpoints[i].data = read_memory(m_pid, addr);
			uint64_t data_with_trap = (breakpoints[i].data & 0xFFFFFF00) | 0xCC;
			write_memory(m_pid, addr, data_with_trap);
			return;
		}
	}
	perror("no breakpoints free left");
	return;
}

void show_breakpoints(){
	for (int i=0; i<20; i++){
		if (!breakpoints[i].is_null){
			printf("breakpoint %d: %llx\n", i, breakpoints[i].addr);
		}
	}
	return;
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

void print_disas(pid_t m_pid, uint64_t addr, int len){
	for (int i=0; i < len; i++){
		printf("0x%16llx\n", read_memory(m_pid, addr+sizeof(uint64_t)*i));
	}
	return;
}

void add_flag(char* flag, uint64_t addr){
	for (int i=0; i<20; i++){
		if (flags[i].is_null){
			flags[i].name = (char *) malloc(strlen(flag));
			strcpy(flags[i].name, flag);
			flags[i].addr = addr;
			flags[i].is_null = 0;
			return;
		}
	}
	perror("no flags free left");
	return;
}

struct Flag find_flag(char *flag){
	for (int i=0; i<20; i++){
		if (!flags[i].is_null && strcmp(flag, flags[i].name) == 0)
			return flags[i];
	}
	perror("unmapped memory");
	struct Flag f = {.is_null=1};
	return f;
}

void show_flags(){
	for (int i=0; i<20; i++){
		if (!flags[i].is_null){
			printf("flag%d: %s\t0x%llx\n", i, flags[i].name, flags[i].addr);
		}
	}
	return;
}

int parent_main(pid_t pid) {
	int wait_status;

	waitpid(pid, &wait_status, 0);
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	read_elf_header();
	printf("entrypoint is at 0x%lx\n", header.e_entry);
	virtual_memory(pid, 0);
	printf("base address is at 0x%08llx\n", baseaddr);
	flags[0].name = (char *) malloc(strlen("entry0"));
	strcpy(flags[0].name, "entry0");
	flags[0].is_null = 0;
	flags[0].addr = baseaddr + header.e_entry;

	vector input;

	printf("\ndbg> ");
	while(1){
		vector_init(&input);
		char tmp[255];
		int i = 0;
		while((tmp[i++] = getchar()) != '\n');
		char stmp[255];
		i = 0;
		int j = 0;
		do{
			if (tmp[j] != ' ' && tmp[j] != '\n'){
				stmp[i++] = tmp[j];
			}
			else {
				stmp[i]='\0';
				if(strlen(stmp) > 0){
					char *no_ref = (char*) malloc(strlen(stmp));
					strcpy(no_ref, stmp);
					vector_add(&input, no_ref);
					i = 0;
				}
			}
		}while(tmp[j++] != '\n');

		char *command = (char*)vector_get(&input, 0);
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
			uint64_t addr = -1;
			if (vector_total(&input) > 1){
				char *tmp = (char *) vector_get(&input, 1);
				if (!is_hex(tmp)){
					struct Flag f = find_flag(tmp);
					if (!f.is_null)
						addr = f.addr;
					if (addr != 0)
						printf("%s -> 0x%8llx\n", tmp, addr);
				}
				else{
					addr = atol(tmp);
				}
				if (addr != (uint64_t)-1)
					add_breakpoint(pid, addr);
			}
			else{
				show_breakpoints();
			}
		}
		else if (strcmp(command, "pxq") == 0){
			int len = 0x20;
			uint64_t addr = regs.rip;
			if (vector_total(&input) > 1){
				char *tmp = (char *) vector_get(&input, 1);
				if (is_dec(tmp)){
					len = atoi(tmp);
				}else if(isxdigit(*tmp)){
					sscanf(tmp, "%x", &len);
				}
			}
			if (vector_total(&input) > 2){
				char *tmp = (char *) vector_get(&input, 2);
				if (is_dec(tmp)){
					addr = atoi(tmp);
				}else if(is_hex(tmp)){
					sscanf(tmp, "%llx", &addr);
				}else{
					struct Flag tmp_flag = find_flag(tmp);
					if (!tmp_flag.is_null)
						addr = tmp_flag.addr;
				}
			}
			print_disas(pid, addr, len);
		}
		else if (strcmp(command, "f") == 0){
			uint64_t addr = regs.rip;
			char *name;
			if (vector_total(&input) > 2){
				char *tmp = (char *) vector_get(&input, 2);
				if (is_dec(tmp)){
					addr = atoi(tmp);
				}else if(isxdigit(*tmp)){
					sscanf(tmp, "%llx", &addr);
				}
			}
			if (vector_total(&input) > 1){
				name = (char *) vector_get(&input, 1);
				add_flag(name, addr);
			}
			if (vector_total(&input) == 1){
				show_flags();
			}
		}
		else if (strcmp(command, "dm") == 0){
			virtual_memory(pid, 1);
		}
		else if (strcmp(command, "q") == 0){
			kill(pid, SIGKILL);
			wait_for_signal(pid);
			vector_free(&input);
			exit(0);
		}
		else {
			printf("command not found\n");
		}
		vector_free(&input);
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
		flags[i].is_null = 1;
		breakpoints[i].is_null = 1;
		breakpoints[i].is_enabled = 0;
	}

	if (argc < 2) {
		printf("usage: \n%s execfile [options]\n", argv[0]);
		return 0;
	}

	filename = argv[1];

	pid = fork();
	if (pid) {
		fprintf(stderr, "%5d: child started\n", pid);
		result = parent_main(pid);
	} else {
		result = child_main(filename, &argv[1]);
	}

	return result;
}

int is_dec(char *src){
	int found = 0;
	int l = strlen(src);
	for (int i=0; i<l; i++){
		if (!isdigit(src[i])){
			found = 1;
		}
	}
	return !found;
}

int is_hex(char *src){
	int found = 0;
	int l = strlen(src);
	for (int i=0; i<l; i++){
		if (!isxdigit(src[i])){
			found = 1;
		}
	}
	return !found;
}

