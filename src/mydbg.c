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
		int i = breakpoint_addr2idx(regs.rip-1);
		if (i < 0){
			printw("Non e' stato trovato alcun breakpoint!");
			exit(1);
		}
		struct breakpoint_t bp = vect_at_breakpoint(vect_breakpoints, i);
		bp.is_enabled = 0;
		if (bp.is_repeat == RREPEAT){
			bp.rtimes--;
		}
		vect_set_breakpoint(vect_breakpoints, i, bp);
		
		uint64_t data = read_memory(m_pid, bp.addr);
		write_memory(m_pid, bp.addr, (data & 0xffffffffffffff00) | bp.data);
		regs.rip = regs.rip-1;
		set_regs(m_pid, regs);
		
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
				char line[255];
				size_t nline = 0;
				struct flag_t f = find_flag_by_addr(insn[j].address);
				if (f.addr != 0)
					nline += sprintf(line+nline, "; %s\n", f.name);
				
				nline += sprintf(line+nline, "0x%012lx\t\t", insn[j].address);
				size_t sum_byte = curr_byte + insn[j].size;
				for (; curr_byte < sum_byte; curr_byte++)
					nline += sprintf(line+nline, "%02x ", code[curr_byte]);
				for (int i=insn[j].size; i<8; i++){
					nline += sprintf(line+nline, "   ");
				}
				if (!strcmp(insn[j].mnemonic, "call")){
					struct flag_t f = find_flag_by_addr(str2ui64(insn[j].op_str));
					nline += sprintf(line+nline, "\t%s %-25s", insn[j].mnemonic, f.name);
				} else {
					nline += sprintf(line+nline, "\t%s %-25s", insn[j].mnemonic, insn[j].op_str);
				}
				printf_filter("%s\n", line);

				instructions[j].addr = insn[j].address;
				instructions[j].type = insn[j].mnemonic;
				
				offset_tmp += insn[j].size;
			}

			offset += offset_tmp;
			ninstr -= count;
			
			cs_free(insn, count);
		} else {
			printf_filter("ERROR: Failed to disassemble given code!\n");
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
		printf_filter("%-3s = 0x%08lx\n", "rax", regs.rax);
	if (reg == NULL || !strcmp(reg, "rbx"))
		printf_filter("%-3s = 0x%08lx\n", "rbx", regs.rbx);
	if (reg == NULL || !strcmp(reg, "rcx"))
		printf_filter("%-3s = 0x%08lx\n", "rcx", regs.rcx);
	if (reg == NULL || !strcmp(reg, "rdx"))
		printf_filter("%-3s = 0x%08lx\n", "rdx", regs.rdx);
	if (reg == NULL || !strcmp(reg, "rsi"))
		printf_filter("%-3s = 0x%08lx\n", "rsi", regs.rsi);
	if (reg == NULL || !strcmp(reg, "rdi"))
		printf_filter("%-3s = 0x%08lx\n", "rdi", regs.rdi);
	if (reg == NULL || !strcmp(reg, "r8"))
		printf_filter("%-3s = 0x%08lx\n", "r8", regs.r8);
	if (reg == NULL || !strcmp(reg, "r9"))
		printf_filter("%-3s = 0x%08lx\n", "r9", regs.r9);
	if (reg == NULL || !strcmp(reg, "r10"))
		printf_filter("%-3s = 0x%08lx\n", "r10", regs.r10);
	if (reg == NULL || !strcmp(reg, "r11"))
		printf_filter("%-3s = 0x%08lx\n", "r11", regs.r11);
	if (reg == NULL || !strcmp(reg, "r12"))
		printf_filter("%-3s = 0x%08lx\n", "r12", regs.r12);
	if (reg == NULL || !strcmp(reg, "r13"))
		printf_filter("%-3s = 0x%08lx\n", "r13", regs.r13);
	if (reg == NULL || !strcmp(reg, "r14"))
		printf_filter("%-3s = 0x%08lx\n", "r14", regs.r14);
	if (reg == NULL || !strcmp(reg, "r15"))
		printf_filter("%-3s = 0x%08lx\n", "r15", regs.r15);
	if (reg == NULL || !strcmp(reg, "rip"))
		printf_filter("%-3s = 0x%08lx\n", "rip", regs.rip);
	if (reg == NULL || !strcmp(reg, "rsp"))
		printf_filter("%-3s = 0x%08lx\n", "rsp", regs.rsp);
	if (reg == NULL || !strcmp(reg, "rbp"))
		printf_filter("%-3s = 0x%08lx\n", "rbp", regs.rbp);
}

void set_reg(pid_t pid, char *reg, uint64_t value){
	if (reg == NULL || !strcmp(reg, "rip")) {
		printf_filter("rip: 0x%08lx -> 0x%08lx\n", regs.rip, value);
		regs.rip = value;
	}
	if (reg == NULL || !strcmp(reg, "rax")) {
		printf_filter("rax: 0x%08lx -> 0x%08lx\n", regs.rax, value);
		regs.rax = value;
	}
	if (reg == NULL || !strcmp(reg, "rbx")) {
		printf_filter("rbx: 0x%08lx -> 0x%08lx\n", regs.rbx, value);
		regs.rbx = value;
	}
	if (reg == NULL || !strcmp(reg, "rcx")) {
		printf_filter("rcx: 0x%08lx -> 0x%08lx\n", regs.rcx, value);
		regs.rcx = value;
	}
	if (reg == NULL || !strcmp(reg, "rdx")) {
		printf_filter("rdx: 0x%08lx -> 0x%08lx\n", regs.rdx, value);
		regs.rdx = value;
	}
	if (reg == NULL || !strcmp(reg, "rsp")) {
		printf_filter("rsp: 0x%08lx -> 0x%08lx\n", regs.rsp, value);
		regs.rsp = value;
	}
	if (reg == NULL || !strcmp(reg, "rbp")) {
		printf_filter("rbp: 0x%08lx -> 0x%08lx\n", regs.rbp, value);
		regs.rbp = value;
	}
	if (reg == NULL || !strcmp(reg, "rsi")) {
		printf_filter("rsi: 0x%08lx -> 0x%08lx\n", regs.rsi, value);
		regs.rsi = value;
	}
	if (reg == NULL || !strcmp(reg, "rdi")) {
		printf_filter("rdi: 0x%08lx -> 0x%08lx\n", regs.rdi, value);
		regs.rdi = value;
	}
	if (reg == NULL || !strcmp(reg, "r8")) {
		printf_filter("r8: 0x%08lx -> 0x%08lx\n", regs.r8, value);
		regs.r8 = value;
	}
	if (reg == NULL || !strcmp(reg, "r9")) {
		printf_filter("r9: 0x%08lx -> 0x%08lx\n", regs.r9, value);
		regs.r9 = value;
	}
	if (reg == NULL || !strcmp(reg, "r10")) {
		printf_filter("r10: 0x%08lx -> 0x%08lx\n", regs.r10, value);
		regs.r10 = value;
	}
	if (reg == NULL || !strcmp(reg, "r11")) {
		printf_filter("r11: 0x%08lx -> 0x%08lx\n", regs.r11, value);
		regs.r11 = value;
	}
	if (reg == NULL || !strcmp(reg, "r12")) {
		printf_filter("r12: 0x%08lx -> 0x%08lx\n", regs.r12, value);
		regs.r12 = value;
	}
	if (reg == NULL || !strcmp(reg, "r13")) {
		printf_filter("r13: 0x%08lx -> 0x%08lx\n", regs.r13, value);
		regs.r13 = value;
	}
	if (reg == NULL || !strcmp(reg, "r14")) {
		printf_filter("r14: 0x%08lx -> 0x%08lx\n", regs.r14, value);
		regs.r14 = value;
	}
	if (reg == NULL || !strcmp(reg, "r15")) {
		printf_filter("r15: 0x%08lx -> 0x%08lx\n", regs.r15, value);
		regs.r15 = value;
	}
	set_regs(pid, regs);
}

void set_regs(pid_t m_pid, struct user_regs_struct new_regs){
	ptrace(PTRACE_SETREGS, m_pid, NULL, &new_regs);
}

void set_breakpoint_in_code(pid_t m_pid){
	int i = 0;
	while (vect_chk_bounds(vect_breakpoints, i)){
		struct breakpoint_t bp = vect_at_breakpoint(vect_breakpoints, i);
		if (bp.addr != regs.rip && !bp.is_enabled && (bp.is_repeat == RALWAYS || (bp.is_repeat == RREPEAT && bp.rtimes > 0))){
			uint64_t data = read_memory(m_pid, bp.addr);
			write_memory(m_pid, bp.addr, (data & 0xffffffffffffff00) | 0xcc);
			bp.is_enabled = 1;
			vect_set_breakpoint(vect_breakpoints, i, bp);
		}
		i++;
	}
}

void single_step(pid_t m_pid){	
	if (ptrace(PTRACE_SINGLESTEP, m_pid, NULL, NULL) < 0){
		printw("error step\n");
		return;
	}
	wait_for_signal(m_pid);
}

void continue_execution(pid_t m_pid){
	if (breakpoint_addr2idx(regs.rip) >= 0)
		single_step(m_pid);

	set_breakpoint_in_code(m_pid);

	if (ptrace(PTRACE_CONT, m_pid, NULL, NULL) < 0) {
		printw("error cont\n");
		return;
	}
	wait_for_signal(m_pid);
}

uint64_t breakpoint_addr2idx(uint64_t addr){
	int i = 0;
	while(vect_chk_bounds(vect_breakpoints, i)){
		struct breakpoint_t breakpoint = vect_at_breakpoint(vect_breakpoints, i);
		if (breakpoint.addr == addr)
			return i;
		i++;
	}
	return -1;
}

void add_breakpoint(pid_t m_pid, uint64_t addr, uint8_t rtimes){
	uint8_t already_present = 0;

	int i = 0;
	while(vect_chk_bounds(vect_breakpoints, i)){
		struct breakpoint_t bp = vect_at_breakpoint(vect_breakpoints, i);

		if (bp.addr == addr){
			already_present = 1;
			if (bp.is_repeat == RREPEAT){
				bp.rtimes = rtimes;
				vect_set_breakpoint(vect_breakpoints, i, bp);
			}
		}
		i++;
	}
		
	if (!already_present){
		struct breakpoint_t bp = {
			.addr = addr,
			.data = read_memory(m_pid, addr) & 0xff,
			.is_enabled = 0,
			.rtimes = rtimes,
			.is_repeat = rtimes > 0
		};
		vect_push_breakpoint(vect_breakpoints, bp);
	}
}

void show_breakpoints(){
	int i = 0;
	printf_filter("%-4s %-14s %-6s %-5s\n", "idx", "address", "rstate", "times");
	while(vect_chk_bounds(vect_breakpoints, i)){
		struct breakpoint_t bp = vect_at_breakpoint(vect_breakpoints, i);
		char *repeat = bp.is_repeat ? "R" : "A";
		printf_filter("%-4d 0x%012lx %-6s %-5d\n", i, bp.addr, repeat, bp.rtimes);
		i++;
	}
}

int virtual_memory(pid_t m_pid, int print){
	procmaps_struct* maps = pmparser_parse(m_pid);
	if (maps == NULL){
		printf_filter("maps: cannot parse\n");
		return 0;
	}
	if (print){
		procmaps_struct* maps_tmp = NULL;

		printf_filter("%-20s %-12s %-12s %-10s %-10s %-10s %-30s\n", "start", "size", "offset", "perm", "inode", "device", "lib");
		while ((maps_tmp = pmparser_next()) != NULL){
			pmparser_print(maps_tmp,0);
		}
	}

	baseaddr = (uint64_t) maps[0].addr_start;
	pmparser_free(maps);
	return 1;
}

void print_hex_quad(pid_t m_pid, uint64_t addr, int len){
	for (int i=0; i < len; i++){
		char buf[255];
		size_t nbuf = 0;

		nbuf += sprintf(buf+nbuf, "0x%012lx\t\t", addr+(sizeof(uint64_t)*i*2));
		for (int j=0; j < 2; j++){
			uint64_t mem = read_memory(m_pid, addr+ (sizeof(uint64_t)*i*2) + 8*j);
			nbuf += sprintf(buf+nbuf, "0x%016lx\t", mem);
		}
		printf_filter("%s\n", buf);
	}
	return;
}

void print_hex_double(pid_t m_pid, uint64_t addr, int len){
	for (int i=0; i < len; i++){
		char buf[255];
		size_t nbuf = 0;

		nbuf += sprintf(buf+nbuf, "0x%012lx\t\t", addr+(sizeof(uint64_t)*i*2));
		for (int j=0; j < 2; j++){
			uint64_t mem = read_memory(m_pid, addr+ (sizeof(uint64_t)*i*2) + 8*j);
			nbuf += sprintf(buf+nbuf, "0x%08lx  0x%08lx  ", mem & 0xffffffff, mem >> 32);
		}
		printf_filter("%s\n", buf);
	}
	return;
}

void print_hexdump(pid_t m_pid, uint64_t addr, int len){
	printf_filter("%-14s\t\t%s\n", "- offset -", " 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF");
	for (int i=0; i < len; i++){
		char buf[255];
		size_t nbuf = 0;
		uint8_t hexdump[17];
		hexdump[16] = '\0';
		nbuf += sprintf(buf+nbuf, "0x%012lx\t\t", addr+(sizeof(uint64_t)*i*2));
		for (int k=0; k < 2; k++){
			uint64_t mem = read_memory(m_pid, addr+ ( 8*(i*2) + 8*k));
			for (int j=0; j < 8; j++) {
				uint8_t c = (mem >> 8*j) & 0xff;
				nbuf += sprintf(buf+nbuf, "%02x ", c);
				if (c > 32 && c < 127)
					hexdump[k*8+j] = c;
				else
					hexdump[k*8+j] = '.';
			}
		}
		nbuf += sprintf(buf+nbuf, " %s\n", hexdump);
		printf_filter(buf);
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
		printf_filter("0x%08lx\t%-30s\n", flag.addr, flag.name);
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
	uint64_t addr = regs.rip;
	if (tmp_seek != NULL && tmp_seek[0] == '@'){
		tmp_seek++;
		addr = str2ui64(tmp_seek);
	}
	return addr;
}

void printf_filter(char *fmt, ...){
	va_list args;
	char buf[255];

	va_start(args, fmt);
	vsprintf(buf, fmt, args);
	va_end(args);

	if (strfilter == NULL || strstr(buf, strfilter)) {
		printw("%s", buf);
	}
}

void init(){
	initscr();
	clear();
	noecho();
	cbreak();	/* Line buffering disabled. pass on everything */
	keypad(stdscr, TRUE);
	scrollok(stdscr, TRUE);
	// refresh();

	uint64_t entrypoint = get_entrypoint();
	printf_filter("base address is at 0x%012lx\n", baseaddr);

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

int parent_main(pid_t pid, const char *script_filename) {
	int wait_status;

	waitpid(pid, &wait_status, 0);
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);

	virtual_memory(pid, 0);

	printf_filter("%5d: child started\n", pid);
	init();

	// commands
	char buf[22];
	snprintf(buf, 22, "\ndbg:0x%12lx> ", regs.rip);
	addstr(buf);

	FILE *source_input = stdin;
	size_t source_input_size = 0;
	if (script_filename != NULL){
		source_input = fopen(script_filename, "r");
		fseek (source_input, 0, SEEK_END);
		source_input_size = ftell(source_input);
		rewind(source_input);
	}

	VECT_GENERATE_NAME(char *, history);
	vect_history *history = vect_init_history(8);

	VECT_GENERATE_NAME(char *, command);
	vect_command *commands = vect_init_command(8);
	while(1){
		int nhistory = 0;
		while(vect_chk_bounds(history, nhistory)) nhistory++;
		vect_push_history(history, "");

		// riempio tmp con source_input
		char tmp[255];
		int lencmd = 0;
		if (source_input == stdin){
			int startpos = 20;
			while (true) {
				int ch = getch();
				int xpos;
				int ypos;
				getsyx(xpos, ypos);
				if (ch > 0 && ch < 127){
					insch(ch);
					printw("%c", ch);
					for(int i=lencmd; i>ypos-startpos; i--){
						tmp[i+1] = tmp[i];
					}
					tmp[ypos-startpos] = ch;
					lencmd++;
				} else {
					if (ch == KEY_UP){
						if (vect_chk_bounds(history, nhistory-1)){
							nhistory--;
							move(xpos, startpos);
							clrtoeol();
							strcpy(tmp, vect_at_history(history, nhistory));
							addstr(tmp);
							lencmd = strlen(tmp);
						}
					} else if (ch == KEY_DOWN){
						if (vect_chk_bounds(history, nhistory+1)){
							nhistory++;
							move(xpos, startpos);
							clrtoeol();
							move(xpos, startpos);
							strcpy(tmp, vect_at_history(history, nhistory));
							addstr(tmp);
							lencmd = strlen(tmp);
						}
					} else if (ch == KEY_BACKSPACE || ch == 127 || ch == '\b'){
						if (ypos > startpos){
							for(int i=ypos-startpos; i<lencmd; i++){
								tmp[i-1] = tmp[i];
							}
							lencmd--;
							move(xpos, --ypos);
							delch();
						}
					} else if (ch == KEY_LEFT){
						if (ypos > startpos){
							move(xpos, --ypos);
						}
					} else if (ch == KEY_RIGHT){
						if (ypos < lencmd + startpos){
							move(xpos, ++ypos);
						}
					}
				}

				if (ch == '\n'){
					tmp[lencmd-1] = '\0';
					// for (int d=0; d<lencmd; d++){
					// 	printw("[%d] [%c]\n", tmp[d], tmp[d]);
					// 	refresh();
					// }
					break;
				}
			}
		} else {
			while((tmp[lencmd++] = getc(source_input)) != '\n');
			tmp[lencmd-1]='\0';
		}
		
		vect_pop_history(history);
		vect_push_history(history, strdup(tmp));

		// se sto analizzando lo script printa tmp
		if (source_input != stdin){ 
			printw("%s\n", tmp);
			// se sto analizzando lo script e l'ultimo carattere non e' \n, allora cambia source_input
			if(ftell(source_input) == source_input_size)
				source_input = stdin;
		}

		char stmp[255];
		int i = 0;
		int j = 0;
		do {
			if (tmp[j] != ' ' && tmp[j] != '\n'){
				stmp[i++] = tmp[j];
			}
			else {
				stmp[i]='\0';
				if(strlen(stmp) > 0){
					char *no_ref = (char*) malloc(strlen(stmp));
					strcpy(no_ref, stmp);
					vect_push_command(commands, no_ref);
					i = 0;
				}
			}
		} while(tmp[j++] != '\n');

		// check for seek and filter
		uint64_t seek = regs.rip;
		strfilter = NULL;
		uint8_t nseek = -1;
		uint8_t nfilter = -1;
		while(vect_chk_bounds(commands, i)){
			char *tmp = (char*)vect_at_command(commands, i);
			if (tmp[0] == '@'){
				seek = get_temporary_seek(tmp);
				nseek = i;
			}
			if (tmp[0] == '~'){
				strfilter = strdup(++tmp);
				nfilter = i;
			}
			i++;
		}
		if (nseek > nfilter) {
			if (vect_chk_bounds(commands, nseek))
				vect_rem_command(commands, nseek);
			if (vect_chk_bounds(commands, nfilter))
				vect_rem_command(commands, nfilter);
		} else if (nseek < nfilter){
			if (vect_chk_bounds(commands, nfilter))
				vect_rem_command(commands, nfilter);
			if (vect_chk_bounds(commands, nseek))
				vect_rem_command(commands, nseek);
		}

		char *command = "";
		if (vect_chk_bounds(commands, 0))
			command = (char*)vect_at_command(commands, 0);

		// check for help
		int is_helper = 0;
		if (strlen(command) > 0 && command[strlen(command)-1] == '?'){
			is_helper = 1;
			if (strlen(command) > 1){
				command[strlen(command)-1] = '\0';
			} else {
				printf_filter("%-20s %s\n", "?", "help");
				printf_filter("%-20s %s\n", "@", "temporary seek");
				printf_filter("%-20s %s\n", "~", "grep");
				printf_filter("%-20s %s\n", "i", "info");
				printf_filter("%-20s %s\n", "f", "flags");
				printf_filter("%-20s %s\n", "p", "print");
				printf_filter("%-20s %s\n", "d", "debug");
				printf_filter("%-20s %s\n", "q", "quit");
			}
		}

		// check commands
		if (!strcmp(command, "d")){
				printf_filter("%-20s %s\n", "db", "breakpoints");
				printf_filter("%-20s %s\n", "dc", "debug continue");
				printf_filter("%-20s %s\n", "dm", "debug memory");
				printf_filter("%-20s %s\n", "dr", "show registers");
				printf_filter("%-20s %s\n", "ds", "debug step");
		}
		else if (!strcmp(command, "i")){
			printf_filter("%-20s %s\n", "is", "info symbols");
			printf_filter("%-20s %s\n", "iS", "info sections");
			printf_filter("%-20s %s\n", "iz", "info strings");
		}
		else if (!strcmp(command, "p")){
			printf_filter("%-20s %s\n", "pd", "print dissasembly");
			printf_filter("%-20s %s\n", "px", "show hexdump");
		}
		else if (!strcmp(command, "pd")) {
			if (is_helper) {
				printf_filter("%-20s %s\n", "pd", "print dissasembly");
				printf_filter("%-20s %s\n", "pd [len]", "disassemble N instructions");
			}
			else {
				// len: number bytes to disassembly
				uint8_t len = 0;
				if (vect_chk_bounds(commands, 1)) {
					char *len_param = (char *) vect_at_command(commands, 1);
					len = atoi(len_param);
				}
				if (len <= 0) len = 1;

				dump_code(pid, seek, len);
			}
		}
		else if (strcmp(command, "ds") == 0){
			if (is_helper)
				printf_filter("%-20s %s\n", "ds", "debug step");
			else
				single_step(pid);
		}
		else if (!strcmp(command, "dr")){
			if (is_helper){
				printf_filter("%-20s %s\n", "dr", "show registers");
				printf_filter("%-20s %s\n", "dr [reg]", "show value of given register");
				printf_filter("%-20s %s\n", "dr [reg] [value]", "set value of given register");
			}
			else {
				char *reg = NULL;
				char *param2 = NULL;
				if (vect_chk_bounds(commands, 2)) {
					reg = (char *) vect_at_command(commands, 1);
					param2 = (char *) vect_at_command(commands, 2);
					uint64_t value = str2ui64(param2);
					set_reg(pid, reg, value);
				} else if (vect_chk_bounds(commands, 1)) {
					reg = (char *) vect_at_command(commands, 1);
					dump_regs(reg);
				} else {
					dump_regs(NULL);
				}
			}
		}
		else if (!strcmp(command, "dc")){
			if (is_helper) {
				printf_filter("%-20s %s\n", "dc", "debug continue");
				printf_filter("%-20s %s\n", "dcc", "debug continue until call");
				printf_filter("%-20s %s\n", "dcr", "debug continue until ret");
				printf_filter("%-20s %s\n", "dcu [addr]", "debug continue until");
			}
			else
				continue_execution(pid);
		}
		else if (!strcmp(command, "dcc")){
			if (is_helper)
				printf_filter("%-20s %s\n", "dcc", "debug continue call");
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
				printf_filter("%-20s %s\n", "dcr", "debug continue return");
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
				printf_filter("%-20s %s\n", "dcu", "debug continue until");
			else {
				uint64_t addr_until = 0;
				if (vect_chk_bounds(commands, 1)) {
					char *until_param = (char *) vect_at_command(commands, 1);
					addr_until = str2ui64(until_param);
					add_breakpoint(pid, addr_until, 1);
				}
				if (addr_until <= 0) continue;

				continue_execution(pid);
			}
		}
		else if (!strcmp(command, "db")){
			if (is_helper){
				printf_filter("%-20s %s\n", "db", "show breakpoints");
				printf_filter("%-20s %s\n", "db [addr]", "add breakpoints");
			}
			else {
				uint64_t addr = 0;
				if (vect_chk_bounds(commands, 1)){
					char *tmp = (char *) vect_at_command(commands, 1);
					addr = str2ui64(tmp);
					if (addr != 0){
						add_breakpoint(pid, addr, 0);
					}
				}
				else{
					show_breakpoints();
				}
			}
		}
		else if (!strcmp(command, "is")){
			if (is_helper)
				printf_filter("%-20s %s\n", "is", "info symbols");
			else {
				struct symbol_t *syms = (struct symbol_t *) malloc(sizeof(struct symbol_t) * 1);
				get_symbols(&sections, &syms);
				free(symbols);
				symbols = syms;

				printf_filter("[Symbols]\n");
				printf_filter("%-4s\t%-10s\t%-6s\t%-6s\t%-4s\t%s\n", "nth", "paddr", "bind", "type", "size", "name");
				int i = 0;
				while (symbols[i].symbol_num == i){
					printf_filter("%-4d\t0x%08lx\t%-6s\t%-6s\t%-4x\t%s\n", symbols[i].symbol_num, symbols[i].symbol_value, "type", "bind", symbols[i].symbol_size, symbols[i].symbol_name);
					i++;
				}

			}
		}
		else if (!strcmp(command, "iS")){
			if (is_helper)
				printf_filter("%-20s %s\n", "iS", "info Sections");
			else {
				struct section_t *secs = (struct section_t *) malloc(sizeof(struct section_t) * 1);
				get_sections(&secs);
				free(sections);
				sections = secs;

				printf_filter("[Sections]\n");
				printf_filter("%-4s\t%-10s\t%-6s\t%-4s\t%s\n", "nth", "paddr", "size", "perm", "name");
				int i = 0;
				while(sections[i].section_index == i) {
					printf_filter("%-4d\t0x%08lx\t0x%-4x\t%-4s\t%s\n", i, sections[i].section_addr, sections[i].section_size, sections[i].section_flags, sections[i].section_name);
					i++;
				}
			}
		}
		else if (!strcmp(command, "iz")){
			if (is_helper){
				printf_filter("%-20s %s\n", "iz", "info strings");
			}
			else {
				if (vect_chk_bounds(commands, 1)){
					strfilter = (char *) vect_at_command(commands, 1);
				}
				printf_filter("[Strings]\n");
				get_strings();
			}
		}
		else if (!strcmp(command, "px")){
			if (is_helper) {
				printf_filter("%-20s %s\n", "px", "show hexdump");
				printf_filter("%-20s %s\n", "px [len]", "show hexdump");
				printf_filter("%-20s %s\n", "pxq", "show hex quadwords");
			}
			else {
				int len = 0x10;
				if (vect_chk_bounds(commands, 1)){
					char *param1 = (char *) vect_at_command(commands, 1);
					len = str2ui64(param1);
				}
				print_hexdump(pid, seek, len);
			}
		}
		else if (!strcmp(command, "pxw")){
			if (is_helper) {
				printf_filter("%-20s %s\n", "pxw", "show hexdump");
				printf_filter("%-20s %s\n", "pxw [len]", "show hexdump");
			}
			else {
				int len = 0x10;
				if (vect_chk_bounds(commands, 1)){
					char *param1 = (char *) vect_at_command(commands, 1);
					len = str2ui64(param1);
				}
				print_hex_double(pid, seek, len);
			}
		}
		else if (!strcmp(command, "pxq")){
			if (is_helper) {
				printf_filter("%-20s %s\n", "pxq", "show hex quadwords");
				printf_filter("%-20s %s\n", "pxq [len]", "show hex quadwords");
			}
			else {
				int len = 0x10;
				if (vect_chk_bounds(commands, 1)){
					char *param1 = (char *) vect_at_command(commands, 1);
					len = str2ui64(param1);
				}
				print_hex_quad(pid, seek, len);
			}
		}
		else if (!strcmp(command, "f")){
			if (is_helper) {
				printf_filter("%-20s %s\n", "f", "show flags");
				printf_filter("%-20s %s\n", "f [name]", "add flag");
			}
			else {
				if (vect_chk_bounds(commands, 1)) {
					char *name = (char *) vect_at_command(commands, 1);					
					add_flag(name, seek);
				} else {
					show_flags();
				}
			}
		}
		else if (strcmp(command, "dm") == 0){
			if (is_helper)
				printf_filter("%-20s %s\n", "dm", "list memory maps of target process");
			else
				virtual_memory(pid, 1);
		}
		else if (strcmp(command, "q") == 0){
			if (is_helper)
				printf_filter("%-20s %s\n", "q", "quit");
			else {
				kill(pid, SIGKILL);
				wait_for_signal(pid);
				vect_free(commands);
				vect_free(vect_flags);
				vect_free(vect_breakpoints);
				exit(0);
			}
		}
		else {
			if (!is_helper)
				printf_filter("command not found\n");
		}

		// rimuovo tutti gli elementi
		while(vect_chk_bounds(commands, 0)) 
			vect_rem_command(commands, 0);

		printw("\ndbg:0x%12lx> ", regs.rip);
	}
	vect_free(history);
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

void usage(const char *program_name){
	printf("Usage: \n\t%s [-i script] execfile [options]\n", program_name);
	exit(0);
	return 0;
}

int main(int argc, char *argv[]) {
	pid_t pid;
	int result;

	if (argc < 2) {
		usage(argv[0]);
	}

	char *script_filename = NULL;
    int opt;
	while ((opt = getopt(argc, argv, "i:h")) != -1) {
		switch(opt) {
		case 'i':
			script_filename = optarg;
			if (!cfileexists(script_filename)){
				perror(script_filename);
				usage(argv[0]);
			}
			break;
		case 'h':
			usage(argv[0]);
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	if (optind >= argc)
		usage(argv[0]);

	filename = argv[optind];
	parse_elf(filename);

	pid = fork();
	if (pid) {
		result = parent_main(pid, script_filename);
	} else {
		result = child_main(filename, NULL);
	}

	return result;
}