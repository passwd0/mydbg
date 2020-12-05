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

struct Instruction *dump_code(pid_t m_pid, uint64_t addr, int8_t ninstr){
	struct Instruction *instructions = (struct Instruction *) malloc(sizeof(*instructions) * ninstr);
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return instructions;

	uint8_t *code = (uint8_t *) malloc(sizeof(uint8_t) * 8);
	
	uint32_t offset = 0;
	do {
		uint64_t mem = read_memory(m_pid, addr+offset);
		code[7] = (mem & 0xff00000000000000) >> 56;
		code[6] = (mem & 0xff000000000000) >> 48;
		code[5] = (mem & 0xff0000000000) >> 40;
		code[4] = (mem & 0xff00000000) >> 32;
		code[3] = (mem & 0xff000000) >> 24;
		code[2] = (mem & 0xff0000) >> 16;
		code[1] = (mem & 0xff00) >> 8;
		code[0] = (mem & 0xff);

		count = cs_disasm(handle, code, 8, addr, 0, &insn);
		if (count > 0) { // assert
			size_t curr_byte = 0;
			uint64_t offset_tmp = 0;
			for (size_t j = 0; j < count && j < ninstr; j++) {
				printf("0x%"PRIx64":\t\t", insn[j].address + offset);
				size_t sum_byte = curr_byte + insn[j].size;
				for (; curr_byte < sum_byte; curr_byte++)
					printf("%02x ", code[curr_byte]);
				for (int i=insn[j].size; i<8; i++){
					printf("   ");
				}
				printf("\t%s %s\n", insn[j].mnemonic, insn[j].op_str);

				instructions[j].addr = insn[j].address;
				instructions[j].type = insn[j].mnemonic;
				
				offset_tmp += insn[j].size;
			}

			offset += offset_tmp;
			ninstr -= count;
			
			cs_free(insn, count);
		} else {
			printf("ERROR: Failed to disassemble given code!\n");
			break;
		}

	} while (ninstr > 0);

	cs_close(&handle);
	return instructions;
}

void dump_regs(pid_t m_pid, char *reg){
	if (reg == NULL || !strcmp(reg, "rip"))
		printf("rip: 0x%08llx\n", regs.rip);
	if (reg == NULL || !strcmp(reg, "rax"))
		printf("rax: 0x%08llx\n", regs.rax);
	if (reg == NULL || !strcmp(reg, "rbx"))
		printf("rbx: 0x%08llx\n", regs.rbx);
	if (reg == NULL || !strcmp(reg, "rcx"))
		printf("rcx: 0x%08llx\n", regs.rcx);
	if (reg == NULL || !strcmp(reg, "rdx"))
		printf("rdx: 0x%08llx\n", regs.rdx);
	if (reg == NULL || !strcmp(reg, "rsp"))
		printf("rsp: 0x%08llx\n", regs.rsp);
	if (reg == NULL || !strcmp(reg, "rbp"))
		printf("rbp: 0x%08llx\n", regs.rbp);
	if (reg == NULL || !strcmp(reg, "rsi"))
		printf("rsi: 0x%08llx\n", regs.rsi);
	if (reg == NULL || !strcmp(reg, "rdi"))
		printf("rdx: 0x%08llx\n", regs.rdi);
}

void set_regs(pid_t m_pid, struct user_regs_struct new_regs){
	ptrace(PTRACE_SETREGS, m_pid, NULL, &new_regs);
}

void single_step(pid_t m_pid){
	// printf("rip: 0x%08llx\t\top : 0x%016llx\n", regs.rip, read_memory(m_pid, regs.rip));
	// dump_code(m_pid, regs.rip, 8);

	if (ptrace(PTRACE_SINGLESTEP, m_pid, NULL, NULL) < 0){
		perror("step");
		return;
	}
	wait_for_signal(m_pid);
}

void continue_execution(pid_t m_pid){
	ptrace(PTRACE_CONT, m_pid, NULL, NULL);
	wait_for_signal(m_pid);

	printf("rip: 0x%08llx\t\top : 0x%016llx\n", regs.rip, read_memory(m_pid, regs.rip));
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

// int read_elf_header() {
// 	FILE* file = fopen(filename, "rb");
// 	if(file) {
// 		fread(&header, 1, sizeof(header), file);

// 		// check so its really an elf file
// 		if (memcmp(header.e_ident, ELFMAG, SELFMAG) == 0) {
// 			fclose(file);
// 			return 1;
// 		}
// 	}
// 	return 0;
// }


int virtual_memory(pid_t m_pid, int print){
	// procmaps_struct* maps = pmparser_parse(m_pid);
	// if (maps == NULL){
	// 	printf("maps: cannot parse\n");
	// 	return 0;
	// }
	// if (print){
	// 	procmaps_struct* maps_tmp = NULL;

	// 	while ((maps_tmp = pmparser_next()) != NULL){
	// 		pmparser_print(maps_tmp,0);
	// 		printf("------\n");
	// 	}
	// }

	// baseaddr = (uint64_t) maps[0].addr_start;
	// pmparser_free(maps);
	return 1;
}

void print_hex_quad(pid_t m_pid, uint64_t addr, int len){
	for (int i=0; i < len; i++){
		printf("0x%016llx\n", read_memory(m_pid, addr+sizeof(uint64_t)*i));
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
		if (!flags[i].is_null && !strcmp(flag, flags[i].name))
			return flags[i];
	}
	perror("unmapped memory");
	struct Flag f = {.is_null=1};
	return f;
}

void show_flags(){
	for (int i=0; i<20; i++){
		if (!flags[i].is_null){
			printf("%s: \t0x%llx\n", flags[i].name, flags[i].addr);
		}
	}
	return;
}

uint64_t get_addr_or_flag(char *str){
	uint64_t addr = 0;
	if (!is_hex(str)){
		struct Flag f = find_flag(str);
		if (!f.is_null)
			addr = f.addr;
	}
	else{
		addr = (uint64_t)strtol(str, NULL, 0);
	}
	return addr;
}

uint64_t get_temporary_seek(char *tmp_seek) {
	uint64_t addr = 0;
	if (tmp_seek == NULL)
		return 0;
	if (tmp_seek[0] == '@'){
		tmp_seek++;
		addr = get_addr_or_flag(tmp_seek);
	}
	return addr;
}

int parent_main(pid_t pid) {
	int wait_status;

	waitpid(pid, &wait_status, 0);
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);

	printf("entrypoint is at 0x%lx\n", header.e_entry);
	virtual_memory(pid, 0);
	printf("base address is at 0x%08llx\n", baseaddr);
	flags[0].name = (char *) malloc(strlen("entry0"));
	strcpy(flags[0].name, "entry0");
	flags[0].is_null = 0;
	flags[0].addr = baseaddr + header.e_entry;


	fputs("\ndbg> ", stdout);
	fflush(stdout);

	vector input;
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

		char *command = "";
		if (vector_total(&input) > 0)
			command = (char*)vector_get(&input, 0);
		
		int is_helper = 0;
		if (command[0] == '?'){
			if (strlen(command) > 1){
				is_helper = 1;
				command++;
			} else {
				printf("?<cmd>\n");
				printf("is\n");
				printf("pd <len>\n");
				printf("ds\n");
				printf("dr [reg]\n");
				printf("dc\n");
				printf("dcc\n");
				printf("dcr\n");
				printf("dcu <addr>\n");
				printf("db [addr]\n");
				printf("pxq\n");
				printf("f\n");
				printf("dm\n");
				printf("q\n");
			}
		}

		if (!strcmp(command, "pd")) {
			if (is_helper)
				printf("pd <len>: print dissasembly\n");
			else {
				// len: number bytes to disassembly
				uint8_t len = 0;
				if (vector_total(&input) > 1) {
					char *len_param = (char *) vector_get(&input, 1);
					len = atoi(len_param);
				}
				if (len <= 0) len = 1;

				// @seek
				uint64_t addr = 0;
				if (vector_total(&input) > 2) {
					char *last_param = (char *) vector_get(&input, 2);
					addr = get_temporary_seek(last_param);
				}
				if (addr == 0) addr = regs.rip;

				dump_code(pid, addr, len);
			}
		}
		else if (strcmp(command, "ds") == 0){
			if (is_helper)
				printf("ds: debug step\n");
			else
				single_step(pid);
		}
		else if (strcmp(command, "dr") == 0){
			if (is_helper)
				printf("dr <reg>: debug registers\n");
			else {
				char *tmp = NULL;
				if (vector_total(&input) > 1) {
					tmp = (char *) vector_get(&input, 1);
				}
				dump_regs(pid, tmp);
			}
		}
		else if (strcmp(command, "dc") == 0){
			if (is_helper)
				printf("dc: debug continue\n");
			else
				continue_execution(pid);
		}
		else if (!strcmp(command, "dcc")){
			if (is_helper)
				printf("dcc: debug continue call\n");
			else {
				uint64_t old_rip;
				do {
					old_rip = regs.rip;
					single_step(pid);
					struct Instruction *instructions = dump_code(pid, regs.rip, 1);
					if (!strcmp(instructions->type, "call"))
						break;
				} while(old_rip != regs.rip);
			}
		}
		else if (!strcmp(command, "dcr")){
			if (is_helper)
				printf("dcr: debug continue return\n");
			else {
				uint64_t old_rip;
				do {
					old_rip = regs.rip;
					single_step(pid);
					struct Instruction *instructions = dump_code(pid, regs.rip, 1);
					if (!strcmp(instructions->type, "ret"))
						break;
				} while(old_rip != regs.rip);
			}
		}
		else if (!strcmp(command, "dcu")){
			if (is_helper)
				printf("dcu: debug continue until\n");
			else {
				uint64_t addr_until = 0;
				if (vector_total(&input) > 1) {
					char *until_param = (char *) vector_get(&input, 1);
					addr_until = get_addr_or_flag(until_param);
				}
				if (addr_until <= 0) continue;

				uint64_t old_rip;
				do {
					old_rip = regs.rip;
					single_step(pid);
					struct Instruction *instructions = dump_code(pid, regs.rip, 1);
					if (instructions->addr == addr_until)
						break;
				} while(old_rip != regs.rip);
			}
		}
		else if (strcmp(command, "db") == 0){
			if (is_helper)
				printf("db <addr>: debug breakpoints\n");
			else {
				uint64_t addr = 0;
				if (vector_total(&input) > 1){
					char *tmp = (char *) vector_get(&input, 1);
					addr = get_addr_or_flag(tmp);
					if (addr != 0){
						printf("%s -> 0x%8llx\n", tmp, addr);
						add_breakpoint(pid, addr);
					}
				}
				else{
					show_breakpoints();
				}
			}
		}
		else if (!strcmp(command, "is")){
			if (is_helper)
				printf("is: info symbols");
			else {
				// std::string program((std::string)filename);
				// elf_parser::Elf_parser elf_parser(program);
				// std::vector<elf_parser::symbol_t> syms = elf_parser.get_symbols();
    			// print_symbols(syms);
			}
		}
		else if (strcmp(command, "pxq") == 0){
			if (is_helper)
				printf("pxq: print hex quadword\n");
			else {
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
				print_hex_quad(pid, addr, len);
			}
		}
		else if (strcmp(command, "f") == 0){
			if (is_helper)
				printf("f: flags\n");
			else {
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
		}
		else if (strcmp(command, "dm") == 0){
			if (is_helper)
				printf("dm: debug memory\n");
			else
				virtual_memory(pid, 1);
		}
		else if (strcmp(command, "q") == 0){
			if (is_helper)
				printf("q: quit\n");
			else {
				kill(pid, SIGKILL);
				wait_for_signal(pid);
				vector_free(&input);
				exit(0);
			}
		}
		else {
			if (!is_helper)
				printf("command not found\n");
		}
		vector_free(&input);
		printf("\ndbg> ");
		fflush(stdout);
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

// void print_sections(std::vector<elf_parser::section_t> &sections) {
//     printf("  [Nr] %-16s %-16s %-16s %s\n", "Name", "Type", "Address", "Offset");
//     printf("       %-16s %-16s %5s\n",
//                     "Size", "EntSize", "Align");
    
//     for (auto &section : sections) {
//         printf("  [%2d] %-16s %-16s %016llx %08llx\n", 
//             section.section_index,
//             section.section_name.c_str(),
//             section.section_type.c_str(),
//             section.section_addr, 
//             section.section_offset);

//         printf("       %016zx %016llx %5d\n",
//             section.section_size, 
//             section.section_ent_size,
//             section.section_addr_align);
//     }
// }


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

	get_sections(filename);
	exit(0);

	pid = fork();
	if (pid) {
		fprintf(stderr, "%5d: child started\n", pid);
		result = parent_main(pid);
	} else {
		result = child_main(filename, &argv[1]);
	}

	return result;
}