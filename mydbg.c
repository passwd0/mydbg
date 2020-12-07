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
		struct breakpoint_t breakpoint = breakpoint_addr_to_data(regs.rip-1);
		if (breakpoint.is_enabled){
			write_memory(m_pid, breakpoint.addr, breakpoint.data);
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

		count = cs_disasm(handle, code, 8, addr+offset, 0, &insn);
		if (count > 0) { // assert
			size_t curr_byte = 0;
			uint64_t offset_tmp = 0;
			for (size_t j = 0; j < count && j < ninstr; j++) {
				struct flag_t f = find_flag_by_addr(insn[j].address);
				if (f.addr != 0)
					printf("; %s\n", f.name);
				
				printf("0x%016lx\t\t", insn[j].address + offset);
				size_t sum_byte = curr_byte + insn[j].size;
				for (; curr_byte < sum_byte; curr_byte++)
					printf("%02x ", code[curr_byte]);
				for (int i=insn[j].size; i<8; i++){
					printf("   ");
				}
				if (!strcmp(insn[j].mnemonic, "call")){
					struct flag_t f = find_flag_by_addr(str2ui64(insn[j].op_str));
					printf("\t%s %-25s", insn[j].mnemonic, f.name);
				} else {
					printf("\t%s %-25s", insn[j].mnemonic, insn[j].op_str);
				}
				printf("\n");

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
	free(code);
	cs_close(&handle);
	return instructions;
}

uint64_t get_reg(char *reg){
	if (!strcmp(reg, "rip"))
		return regs.rip;
	if (!strcmp(reg, "rax"))
		return regs.rax;
	if (!strcmp(reg, "rbx"))
		return regs.rbx;
	if (!strcmp(reg, "rcx"))
		return regs.rcx;
	if (!strcmp(reg, "rdx"))
		return regs.rdx;
	if (!strcmp(reg, "rsp"))
		return regs.rsp;
	if (!strcmp(reg, "rbp"))
		return regs.rbp;
	if (!strcmp(reg, "rsi"))
		return regs.rsi;
	if (!strcmp(reg, "rdi"))
		return regs.rdi;
	return 0;
}

void dump_regs(char *reg){
	if (reg == NULL || !strcmp(reg, "rax"))
		printf("%-3s = 0x%08lx\n", "rax", regs.rax);
	if (reg == NULL || !strcmp(reg, "rbx"))
		printf("%-3s = 0x%08lx\n", "rbx", regs.rbx);
	if (reg == NULL || !strcmp(reg, "rcx"))
		printf("%-3s = 0x%08lx\n", "rcx", regs.rcx);
	if (reg == NULL || !strcmp(reg, "rdx"))
		printf("%-3s = 0x%08lx\n", "rdx", regs.rdx);
	if (reg == NULL || !strcmp(reg, "rsi"))
		printf("%-3s = 0x%08lx\n", "rsi", regs.rsi);
	if (reg == NULL || !strcmp(reg, "rdi"))
		printf("%-3s = 0x%08lx\n", "rdi", regs.rdi);
	if (reg == NULL || !strcmp(reg, "r8"))
		printf("%-3s = 0x%08lx\n", "r8", regs.r8);
	if (reg == NULL || !strcmp(reg, "r9"))
		printf("%-3s = 0x%08lx\n", "r9", regs.r9);
	if (reg == NULL || !strcmp(reg, "r10"))
		printf("%-3s = 0x%08lx\n", "r10", regs.r10);
	if (reg == NULL || !strcmp(reg, "r11"))
		printf("%-3s = 0x%08lx\n", "r11", regs.r11);
	if (reg == NULL || !strcmp(reg, "r12"))
		printf("%-3s = 0x%08lx\n", "r12", regs.r12);
	if (reg == NULL || !strcmp(reg, "r13"))
		printf("%-3s = 0x%08lx\n", "r13", regs.r13);
	if (reg == NULL || !strcmp(reg, "r14"))
		printf("%-3s = 0x%08lx\n", "r14", regs.r14);
	if (reg == NULL || !strcmp(reg, "r15"))
		printf("%-3s = 0x%08lx\n", "r15", regs.r15);
	if (reg == NULL || !strcmp(reg, "rip"))
		printf("%-3s = 0x%08lx\n", "rip", regs.rip);
	if (reg == NULL || !strcmp(reg, "rsp"))
		printf("%-3s = 0x%08lx\n", "rsp", regs.rsp);
	if (reg == NULL || !strcmp(reg, "rbp"))
		printf("%-3s = 0x%08lx\n", "rbp", regs.rbp);
}

void set_reg(pid_t pid, char *reg, uint64_t value){
	if (reg == NULL || !strcmp(reg, "rip")) {
		printf("rip: 0x%08lx -> 0x%08lx\n", regs.rip, value);
		regs.rip = value;
	}
	if (reg == NULL || !strcmp(reg, "rax")) {
		printf("rax: 0x%08lx -> 0x%08lx\n", regs.rax, value);
		regs.rax = value;
	}
	if (reg == NULL || !strcmp(reg, "rbx")) {
		printf("rbx: 0x%08lx -> 0x%08lx\n", regs.rbx, value);
		regs.rbx = value;
	}
	if (reg == NULL || !strcmp(reg, "rcx")) {
		printf("rcx: 0x%08lx -> 0x%08lx\n", regs.rcx, value);
		regs.rcx = value;
	}
	if (reg == NULL || !strcmp(reg, "rdx")) {
		printf("rdx: 0x%08lx -> 0x%08lx\n", regs.rdx, value);
		regs.rdx = value;
	}
	if (reg == NULL || !strcmp(reg, "rsp")) {
		printf("rsp: 0x%08lx -> 0x%08lx\n", regs.rsp, value);
		regs.rsp = value;
	}
	if (reg == NULL || !strcmp(reg, "rbp")) {
		printf("rbp: 0x%08lx -> 0x%08lx\n", regs.rbp, value);
		regs.rbp = value;
	}
	if (reg == NULL || !strcmp(reg, "rsi")) {
		printf("rsi: 0x%08lx -> 0x%08lx\n", regs.rsi, value);
		regs.rsi = value;
	}
	if (reg == NULL || !strcmp(reg, "rdi")) {
		printf("rdi: 0x%08lx -> 0x%08lx\n", regs.rdi, value);
		regs.rdi = value;
	}
	if (reg == NULL || !strcmp(reg, "r8")) {
		printf("r8: 0x%08lx -> 0x%08lx\n", regs.r8, value);
		regs.r8 = value;
	}
	if (reg == NULL || !strcmp(reg, "r9")) {
		printf("r9: 0x%08lx -> 0x%08lx\n", regs.r9, value);
		regs.r9 = value;
	}
	if (reg == NULL || !strcmp(reg, "r10")) {
		printf("r10: 0x%08lx -> 0x%08lx\n", regs.r10, value);
		regs.r10 = value;
	}
	if (reg == NULL || !strcmp(reg, "r11")) {
		printf("r11: 0x%08lx -> 0x%08lx\n", regs.r11, value);
		regs.r11 = value;
	}
	if (reg == NULL || !strcmp(reg, "r12")) {
		printf("r12: 0x%08lx -> 0x%08lx\n", regs.r12, value);
		regs.r12 = value;
	}
	if (reg == NULL || !strcmp(reg, "r13")) {
		printf("r13: 0x%08lx -> 0x%08lx\n", regs.r13, value);
		regs.r13 = value;
	}
	if (reg == NULL || !strcmp(reg, "r14")) {
		printf("r14: 0x%08lx -> 0x%08lx\n", regs.r14, value);
		regs.r14 = value;
	}
	if (reg == NULL || !strcmp(reg, "r15")) {
		printf("r15: 0x%08lx -> 0x%08lx\n", regs.r15, value);
		regs.r15 = value;
	}
	set_regs(pid, regs);
}

void set_regs(pid_t m_pid, struct user_regs_struct new_regs){
	ptrace(PTRACE_SETREGS, m_pid, NULL, &new_regs);
}

void single_step(pid_t m_pid){
	if (ptrace(PTRACE_SINGLESTEP, m_pid, NULL, NULL) < 0){
		perror("step");
		return;
	}
	wait_for_signal(m_pid);
}

void continue_execution(pid_t m_pid){
	if (ptrace(PTRACE_CONT, m_pid, NULL, NULL) < 0) {
		perror("cont");
		return;
	}
	wait_for_signal(m_pid);

	printf("rip: 0x%08lx\n", regs.rip);
}

struct breakpoint_t breakpoint_addr_to_data(uint64_t addr){
	int i = 0;
	while(vect_chk_bounds(vect_breakpoints, i)){
		struct breakpoint_t breakpoint = vect_at_breakpoint(vect_breakpoints, i);
		if (breakpoint.is_enabled && breakpoint.addr == addr)
			return breakpoint;
		i++;
	}
	struct breakpoint_t breakpoint = {.addr=-1, .data=0, .is_enabled=0};
	return breakpoint;
}

void add_breakpoint(pid_t m_pid, uint64_t addr){
	uint8_t already_present = 0;

	int i = 0;
	while(vect_chk_bounds(vect_breakpoints, i)){
		struct breakpoint_t breakpoint = vect_at_breakpoint(vect_breakpoints, i);

		if (breakpoint.addr == addr){
			already_present = 1;
		}
		i++;
	}
		
	if (!already_present){
		struct breakpoint_t breakpoint = {
			.addr = addr,
			.data = read_memory(m_pid, addr),
			.is_enabled = 1
		};
		vect_push_breakpoint(vect_breakpoints, breakpoint);
		uint64_t data_with_trap = (breakpoint.data & 0xFFFFFF00) | 0xCC;
		write_memory(m_pid, addr, data_with_trap);
	}
}

void show_breakpoints(){
	int i = 0;
	while(vect_chk_bounds(vect_breakpoints, i)){
		struct breakpoint_t breakpoint = vect_at_breakpoint(vect_breakpoints, i);
		printf("0x%012lx\n", breakpoint.addr);
		i++;
	}
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

	baseaddr = (uint64_t) maps[0].addr_start;
	pmparser_free(maps);
	return 1;
}

void print_hex_quad(pid_t m_pid, uint64_t addr, int len){
	for (int i=0; i < len; i++){
		printf("0x%012lx\t\t", addr+(sizeof(uint64_t)*i*2));
		for (int j=0; j < 2; j++){
			uint64_t mem = read_memory(m_pid, addr+ (sizeof(uint64_t)*i*2) + 8*j);
			printf("0x%016lx\t", mem);
		}
		printf("\n");
	}
	return;
}

void print_hexdump(pid_t m_pid, uint64_t addr, int len){
	printf("%-14s\t\t%s\n", "- offset -", " 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF");
	for (int i=0; i < len; i++){
		uint8_t hexdump[17];
		hexdump[16] = '\0';
		printf("0x%012lx\t\t", addr+(sizeof(uint64_t)*i*2));
		for (int k=0; k < 2; k++){
			uint64_t mem = read_memory(m_pid, addr+ ( 8*(i*2) + 8*k));
			for (int j=0; j < 8; j++) {
				uint8_t c = (mem >> 8*j) & 0xff;
				printf("%02x ", c);
				if (c > 32 && c < 127)
					hexdump[k*8+j] = c;
				else
					hexdump[k*8+j] = '.';
			}
		}
		printf(" %s\n", hexdump);
	}
}

void add_flag(char *name, uint64_t addr){
	if (name == NULL || !strcmp(name, "")) return;

	uint8_t already_present = 0;

	int i = 0;
	while(vect_chk_bounds(vect_flags, i)){
		struct flag_t flag = vect_at_flag(vect_flags, i);

		if (!strcmp(name, flag.name)){
			already_present = 1;
		}
		i++;
	}
		
	if (!already_present){
		struct flag_t flag = {
			.name=name,
			.addr=addr
		};
		vect_push_flag(vect_flags, flag);
	}
}

struct flag_t find_flag(char *name){
	struct flag_t f = {
		.name = "",
		.addr = 0
	};

	if (name == NULL || !(strcmp(name, ""))) return f;

	int i = 0;
	while(vect_chk_bounds(vect_flags, i)){
		struct flag_t flag = vect_at_flag(vect_flags, i);
		if (!strcmp(flag.name, name))
			return flag;
		i++;
	}
	return f;
}

struct flag_t find_flag_by_addr(uint64_t addr){
	struct flag_t f = {
		.name = "",
		.addr = 0
	};

	int i = 0;
	while(vect_chk_bounds(vect_flags, i)){
		struct flag_t flag = vect_at_flag(vect_flags, i);
		if (addr == flag.addr)
			return flag;
		i++;
	}
	return f;
}

void show_flags(){
	int i = 0;
	while (vect_chk_bounds(vect_flags, i)) {
		struct flag_t flag = vect_at_flag(vect_flags, i);
		printf("0x%08lx\t%-30s\n", flag.addr, flag.name);
		i++;
	}
}

uint64_t str2ui64(char *str){
	uint64_t addr = 0;
	if (is_dec(str) || is_hex(str)){
		addr = (uint64_t)strtol(str, NULL, 0);
	} else {
		struct flag_t f = find_flag(str);
		addr = f.addr;
	}
	if (addr == 0){
		addr = get_reg(str);
	}
	return addr;
}

uint64_t get_temporary_seek(char *tmp_seek) {
	uint64_t addr = 0;
	if (tmp_seek == NULL)
		return 0;
	if (tmp_seek[0] == '@'){
		tmp_seek++;
		addr = str2ui64(tmp_seek);
	}
	return addr;
}

void init(){
	uint64_t entrypoint = get_entrypoint();
	printf("base address is at 0x%012lx\n", baseaddr);

	// read symbols
	struct symbol_t *syms = (struct symbol_t *) malloc(sizeof(struct symbol_t) * 1);
	get_symbols(&sections, &syms);
	free(symbols);
	symbols = syms;

	// init-add flags
	vect_flags = vect_init_flag(8);
	add_flag("entry0", baseaddr + entrypoint);

	int i = 0;
	while (symbols[i].symbol_num == i){
		add_flag(symbols[i].symbol_name, baseaddr + symbols[i].symbol_value);
		i++;
	}

	// init breakpoint
	vect_breakpoints = vect_init_breakpoint(8);
}

int parent_main(pid_t pid) {
	int wait_status;

	waitpid(pid, &wait_status, 0);
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);

	virtual_memory(pid, 0);
	init();
	
	// commands
	printf("\ndbg:0x%12lx> ", regs.rip);
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
		
		// check for help
		int is_helper = 0;
		if (strlen(command) > 0 && command[strlen(command)-1] == '?'){
			is_helper = 1;
			if (strlen(command) > 1){
				command[strlen(command)-1] = '\0';
			} else {
				printf("%-20s %s\n", "?", "help");
				printf("%-20s %s\n", "i", "info");
				printf("%-20s %s\n", "f", "flags");
				printf("%-20s %s\n", "p", "print");
				printf("%-20s %s\n", "d", "debug");
				printf("%-20s %s\n", "q", "quit");
			}
		}
		if (!strcmp(command, "d")){
				printf("%-20s %s\n", "db", "breakpoints");
				printf("%-20s %s\n", "dc", "debug continue");
				printf("%-20s %s\n", "dm", "debug memory");
				printf("%-20s %s\n", "dr", "show registers");
				printf("%-20s %s\n", "ds", "debug step");
		}
		else if (!strcmp(command, "i")){
			printf("%-20s %s\n", "is", "info symbols");
			printf("%-20s %s\n", "iS", "info sections");
			printf("%-20s %s\n", "iz", "info strings");
		}
		else if (!strcmp(command, "p")){
			printf("%-20s %s\n", "pd", "print dissasembly");
			printf("%-20s %s\n", "px", "show hexdump");
		}
		else if (!strcmp(command, "pd")) {
			if (is_helper) {
				printf("%-20s %s\n", "pd", "print dissasembly");
				printf("%-20s %s\n", "pd [len]", "disassemble N instructions");
			}
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
				printf("%-20s %s\n", "ds", "debug step");
			else
				single_step(pid);
		}
		else if (strcmp(command, "dr") == 0){
			if (is_helper){
				printf("%-20s %s\n", "dr", "show registers");
				printf("%-20s %s\n", "dr [reg]", "show value of given register");
				printf("%-20s %s\n", "dr [reg] [value]", "set value of given register");
			}
			else {
				char *reg = NULL;
				char *param2 = NULL;
				if (vector_total(&input) > 2) {
					reg = (char *) vector_get(&input, 1);
					param2 = (char *) vector_get(&input, 2);
					uint64_t value = str2ui64(param2);
					set_reg(pid, reg, value);
				} else if (vector_total(&input) > 1) {
					reg = (char *) vector_get(&input, 1);
					dump_regs(reg);
				} else 
					dump_regs(NULL);				
			}
		}
		else if (!strcmp(command, "dc")){
			if (is_helper) {
				printf("%-20s %s\n", "dc", "debug continue");
				printf("%-20s %s\n", "dcc", "debug continue until call");
				printf("%-20s %s\n", "dcr", "debug continue until ret");
				printf("%-20s %s\n", "dcu [addr]", "debug continue until");
			}
			else
				continue_execution(pid);
		}
		else if (!strcmp(command, "dcc")){
			if (is_helper)
				printf("%-20s %s\n", "dcc", "debug continue call");
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
				printf("%-20s %s\n", "dcr", "debug continue return");
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
				printf("%-20s %s\n", "dcu", "debug continue until");
			else {
				uint64_t addr_until = 0;
				if (vector_total(&input) > 1) {
					char *until_param = (char *) vector_get(&input, 1);
					addr_until = str2ui64(until_param);
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
		else if (!strcmp(command, "db")){
			if (is_helper){
				printf("%-20s %s\n", "db", "show breakpoints");
				printf("%-20s %s\n", "db [addr]", "add breakpoints");
			}
			else {
				uint64_t addr = 0;
				if (vector_total(&input) > 1){
					char *tmp = (char *) vector_get(&input, 1);
					addr = str2ui64(tmp);
					if (addr != 0){
						printf("%s -> 0x%08lx\n", tmp, addr);
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
				printf("%-20s %s\n", "is", "info symbols");
			else {
				struct symbol_t *syms = (struct symbol_t *) malloc(sizeof(struct symbol_t) * 1);
				get_symbols(&sections, &syms);
				free(symbols);
				symbols = syms;

				printf("[Symbols]\n");
				printf("%-4s\t%-10s\t%-6s\t%-6s\t%-4s\t%s\n", "nth", "paddr", "bind", "type", "size", "name");
				int i = 0;
				while (symbols[i].symbol_num == i){
					printf("%-4d\t0x%08lx\t%-6s\t%-6s\t%-4x\t%s\n", symbols[i].symbol_num, symbols[i].symbol_value, "type", "bind", symbols[i].symbol_size, symbols[i].symbol_name);
					i++;
				}

			}
		}
		else if (!strcmp(command, "iS")){
			if (is_helper)
				printf("%-20s %s\n", "iS", "info Sections");
			else {
				struct section_t *secs = (struct section_t *) malloc(sizeof(struct section_t) * 1);
				get_sections(&secs);
				free(sections);
				sections = secs;

				printf("[Sections]\n");
				printf("%-4s\t%-10s\t%-6s\t%-4s\t%s\n", "nth", "paddr", "size", "perm", "name");
				int i = 0;
				while(sections[i].section_index == i) {
					printf("%-4d\t0x%08lx\t0x%-4x\t%-4s\t%s\n", i, sections[i].section_addr, sections[i].section_size, sections[i].section_flags, sections[i].section_name);
					i++;
				}
			}
		}
		else if (!strcmp(command, "iz")){
			if (is_helper){
				printf("%-20s %s\n", "iz", "info strings");
				printf("%-20s %s\n", "iz [filter]", "info strings and filter");
			}
			else {
				char *filter = NULL;
				if (vector_total(&input) > 1){
					filter = (char *) vector_get(&input, 1);
				}
				printf("[Strings]\n");
				get_strings(filter);
			}
		}
		else if (strcmp(command, "px") == 0){
			if (is_helper) {
				printf("%-20s %s\n", "px", "show hexdump");
				printf("%-20s %s\n", "px [len]", "show hexdump");
				printf("%-20s %s\n", "pxq", "show hex quadwords");
			}
			else {
				int len = 0x10;
				uint64_t addr = regs.rip;
				if (vector_total(&input) > 1){
					char *param1 = (char *) vector_get(&input, 1);
					len = str2ui64(param1);
				}
				if (vector_total(&input) > 2){
					char *param2 = (char *) vector_get(&input, 2);
					addr = get_temporary_seek(param2);
				}
				print_hexdump(pid, addr, len);
			}
		}
		else if (strcmp(command, "pxq") == 0){
			if (is_helper) {
				printf("%-20s %s\n", "pxq", "show hex quadwords");
				printf("%-20s %s\n", "pxq [len]", "show hex quadwords");
			}
			else {
				int len = 0x10;
				uint64_t addr = regs.rip;
				if (vector_total(&input) > 1){
					char *param1 = (char *) vector_get(&input, 1);
					len = str2ui64(param1);
				}
				if (vector_total(&input) > 2){
					char *param2 = (char *) vector_get(&input, 2);
					addr = get_temporary_seek(param2);
				}
				print_hex_quad(pid, addr, len);
			}
		}
		else if (!strcmp(command, "f")){
			if (is_helper) {
				printf("%-20s %s\n", "f", "show flags");
				printf("%-20s %s\n", "f [name]", "add flag");
			}
			else {
				if (vector_total(&input) > 1) {
					uint64_t addr = regs.rip;
					char *name = (char *) vector_get(&input, 1);					
				
					if (vector_total(&input) > 2){
						char *last_param = (char *) vector_get(&input, 2);
						addr = get_temporary_seek(last_param);
					}
					add_flag(name, addr);
				} else {
					show_flags();
				}
			}
		}
		else if (strcmp(command, "dm") == 0){
			if (is_helper)
				printf("%-20s %s\n", "dm", "list memory maps of target process");
			else
				virtual_memory(pid, 1);
		}
		else if (strcmp(command, "q") == 0){
			if (is_helper)
				printf("%-20s %s\n", "q", "quit");
			else {
				kill(pid, SIGKILL);
				wait_for_signal(pid);
				vector_free(&input);
				vect_free(vect_flags);
				vect_free(vect_breakpoints);
				exit(0);
			}
		}
		else {
			if (!is_helper)
				printf("command not found\n");
		}

		vector_free(&input);
		printf("\ndbg:0x%12lx> ", regs.rip);
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

int main(int argc, char *argv[]) {
	pid_t pid;
	int result;

	if (argc < 2) {
		printf("usage: \n%s execfile [options]\n", argv[0]);
		return 0;
	}

	filename = argv[1];

	parse_elf(filename);

	pid = fork();
	if (pid) {
		fprintf(stderr, "%5d: child started\n", pid);
		result = parent_main(pid);
	} else {
		result = child_main(filename, &argv[1]);
	}

	return result;
}