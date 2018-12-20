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

void show_breakpoint(){
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

uint64_t flag_to_addr(char *flag){
	for (int i=0; i<20; i++){
		if (!flags[i].is_null && strcmp(flag, flags[i].name) == 0)
			return flags[i].addr;
	}
	perror("unmapped memory");
	return 0;
}

int parent_main(pid_t pid) {
	int wait_status;
	char command[255];

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
			int i = 0;
			while((input[i++] = getchar())!='\n');
			input[i]='\0';
			char *trimmed_input = trim(input);
			int l = strlen(trimmed_input);
			if (l > 0){
				int found = 0;
				for (int i=0; i<l; i++){
					if (!isdigit(trimmed_input[i])){
						found = 1;
					}
				}
				if (found){
					addr = flag_to_addr(trimmed_input);
					if (addr != 0)
						printf("%s -> 0x%8llx\n",trimmed_input, addr);
				}
				else
					addr = atol(trimmed_input);
				add_breakpoint(pid, addr);
			}
			else{
				show_breakpoint();
			}
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
		//char a;
		//while ((a = getchar()) != 0xa);
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

char *trim(char *str){
	size_t len = 0;
	char *frontp = str;
	char *endp = NULL;

	if( str == NULL ) { return NULL; }
	if( str[0] == '\0' ) { return str; }

	len = strlen(str);
	endp = str + len;

	/* Move the front and back pointers to address the first non-whitespace
	* characters from each end.
	*/
	while( isspace((unsigned char) *frontp) ) { ++frontp; }
	if( endp != frontp )
	{
	while( isspace((unsigned char) *(--endp)) && endp != frontp ) {}
	}

	if( str + len - 1 != endp )
		*(endp + 1) = '\0';
	else if( frontp != str &&  endp == frontp )
		*str = '\0';

	/* Shift the string so that it starts at str so that if it's dynamically
	* allocated, we can still free it on the returned pointer.  Note the reuse
	* of endp to mean the front of the string buffer now.
	*/
	endp = str;
	if( frontp != str )
	{
		while( *frontp ) { *endp++ = *frontp++; }
		*endp = '\0';
	}
	return str;
}
