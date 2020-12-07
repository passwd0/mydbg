#include "elfparser.h"

uint8_t *mem;
uint64_t mem_size;

void parse_elf(char *filename){
	int fd, i;
	struct stat st;

	if ((fd = open(filename, O_RDONLY)) < 0 ) {
		perror("open");
		exit(-1);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(-1);
	}
	mem_size = st.st_size;

	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	// if (ehdr->e_type != ET_EXEC) {
	// 	fprintf(stderr, "%s is not an executable\n", filename);
	// 	exit(-1);
	// }

	if (mem[0] != 0x7f && strcmp(&mem[1], "ELF")) {
		fprintf(stderr, "%s is not an ELF file\n", filename);
		exit(-1);
	}
}

void get_strings(char *filter){
	int i = 0;
	char buf[250];
	int c = 0;
	int old_size = 0;
	for (int i=0; i<mem_size; i++){
		if (mem[i] > 32 && mem[i] < 127){
			buf[c] = mem[i];
			c++;
		} else {
			old_size = c;
			buf[c] = '\0';
			c = 0;
		}
		if (old_size > 4){
			if (filter == NULL || strstr(buf, filter)) {
				printf("%s\n", buf);
			}
			old_size = 0;
		}
	}
}

uint64_t get_entrypoint() {
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *) mem;
	return ehdr->e_entry;
}

char *get_segment_type(uint32_t seg_type) {
    switch(seg_type) {
        case PT_NULL:   return "NULL";                  /* Program header table entry unused */ 
        case PT_LOAD: return "LOAD";                    /* Loadable program segment */
        case PT_DYNAMIC: return "DYNAMIC";              /* Dynamic linking information */
        case PT_INTERP: return "INTERP";                /* Program interpreter */
        case PT_NOTE: return "NOTE";                    /* Auxiliary information */
        case PT_SHLIB: return "SHLIB";                  /* Reserved */
        case PT_PHDR: return "PHDR";                    /* Entry for header table itself */
        case PT_TLS: return "TLS";                      /* Thread-local storage segment */
        case PT_NUM: return "NUM";                      /* Number of defined types */
        case PT_LOOS: return "LOOS";                    /* Start of OS-specific */
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";    /* GCC .eh_frame_hdr segment */
        case PT_GNU_STACK: return "GNU_STACK";          /* Indicates stack executability */
        case PT_GNU_RELRO: return "GNU_RELRO";          /* Read-only after relocation */
        //case PT_LOSUNW: return "LOSUNW";
        case PT_SUNWBSS: return "SUNWBSS";              /* Sun Specific segment */
        case PT_SUNWSTACK: return "SUNWSTACK";          /* Stack segment */
        //case PT_HISUNW: return "HISUNW";
        case PT_HIOS: return "HIOS";                    /* End of OS-specific */
        case PT_LOPROC: return "LOPROC";                /* Start of processor-specific */
        case PT_HIPROC: return "HIPROC";                /* End of processor-specific */
        default: return "UNKNOWN";
    }
}

char *get_section_type(int tt) {
    if(tt < 0)
        return "UNKNOWN";

    switch(tt) {
        case 0: return "SHT_NULL";      /* Section header table entry unused */
        case 1: return "SHT_PROGBITS";  /* Program data */
        case 2: return "SHT_SYMTAB";    /* Symbol table */
        case 3: return "SHT_STRTAB";    /* String table */
        case 4: return "SHT_RELA";      /* Relocation entries with addends */
        case 5: return "SHT_HASH";      /* Symbol hash table */
        case 6: return "SHT_DYNAMIC";   /* Dynamic linking information */
        case 7: return "SHT_NOTE";      /* Notes */
        case 8: return "SHT_NOBITS";    /* Program space with no data (bss) */
        case 9: return "SHT_REL";       /* Relocation entries, no addends */
        case 11: return "SHT_DYNSYM";   /* Dynamic linker symbol table */
        default: return "UNKNOWN";
    }
    return "UNKNOWN";
}

char *get_flags(uint32_t f) {
    static char flags[] = "---";

    if(f & PF_R)
        flags[0] = 'r';

    if(f & PF_W)
        flags[1] = 'w';

    if(f & PF_X)
        flags[2] = 'x';

    return flags;
}

void get_sections(struct section_t **sections) {
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *) mem;
	Elf64_Shdr *shdr = (Elf64_Shdr *) &mem[ehdr->e_shoff];
	char *StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];

	*sections = (struct section_t *) realloc(*sections, sizeof(struct section_t) * ehdr->e_shnum);
	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		(*sections)[i].section_index = i;
		(*sections)[i].section_addr = shdr[i].sh_addr;
		(*sections)[i].section_addr_align = shdr[i].sh_addralign;
		(*sections)[i].section_ent_size = shdr[i].sh_entsize;
		(*sections)[i].section_name = &StringTable[shdr[i].sh_name];
		(*sections)[i].section_offset = shdr[i].sh_offset;
		(*sections)[i].section_size = shdr[i].sh_size;
		(*sections)[i].section_type = strdup(get_section_type(shdr[i].sh_type));
		(*sections)[i].section_flags = strdup(get_flags(shdr[i].sh_flags));
		(*sections)[i].section_link = shdr[i].sh_link;
	}
}

void get_programs() {
	char *interp;
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *) mem;
	Elf64_Phdr *phdr = (Elf64_Phdr *) &mem[ehdr->e_phoff];

	printf("\nProgram header list\n\n");
	for (int i = 0; i < ehdr->e_phnum; ++i)
	{
		switch(phdr[i].p_type) {
			case PT_LOAD:
				if (phdr[i].p_offset == 0)
					printf("Text segment: 0x%lx\n", phdr[i].p_vaddr);
				else
					printf("Data segment: 0x%lx\n", phdr[i].p_vaddr);
				break;
			case PT_INTERP:
				interp = strdup((char *) &mem[phdr[i].p_offset]);
				printf("Interpreter: %s\n", interp);
				break;
			case PT_NOTE:
				printf("Note segment: 0x%lx\n", phdr[i].p_vaddr);
				break;
			case PT_DYNAMIC:
				printf("Dynamic segment: 0x%lx\n", phdr[i].p_vaddr);
				break;
			case PT_PHDR:
				printf("Phdr segment: 0x%lx\n", phdr[i].p_vaddr);
				break;
		}
	}
}

char *get_symbol_type(uint8_t sym_type) {
    switch(ELF32_ST_TYPE(sym_type)) {
        case 0: return "NOTYPE";
        case 1: return "OBJECT";
        case 2: return "FUNC";
        case 3: return "SECTION";
        case 4: return "FILE";
        case 6: return "TLS";
        case 7: return "NUM";
        case 10: return "LOOS";
        case 12: return "HIOS";
        default: return "UNKNOWN";
    }
}

char *get_symbol_bind(uint8_t sym_bind) {
    switch(ELF32_ST_BIND(sym_bind)) {
        case 0: return "LOCAL";
        case 1: return "GLOBAL";
        case 2: return "WEAK";
        case 3: return "NUM";
        case 10: return "UNIQUE";
        case 12: return "HIOS";
        case 13: return "LOPROC";
        default: return "UNKNOWN";
    }
}

char *get_symbol_visibility(uint8_t sym_vis) {
    switch(ELF32_ST_VISIBILITY(sym_vis)) {
        case 0: return "DEFAULT";
        case 1: return "INTERNAL";
        case 2: return "HIDDEN";
        case 3: return "PROTECTED";
        default: return "UNKNOWN";
    }
}

void get_symbols(struct section_t **sections, struct symbol_t **symbols) {
	if (*sections == NULL)
    	get_sections(sections);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) mem;
	Elf64_Shdr *shdr = (Elf64_Shdr *) &mem[ehdr->e_shoff];

    // get strtab
    char *sh_strtab_p = NULL;
	int i = 0;
    while ((*sections)[i].section_index == i) {
        if(!strcmp((*sections)[i].section_type, "SHT_STRTAB") && !strcmp((*sections)[i].section_name, ".strtab")){
            sh_strtab_p = (char*)mem + (*sections)[i].section_offset;
            break;
        }
		i++;
    }

    // get dynstr
    char *sh_dynstr_p = NULL;
	i = 0;
    while ((*sections)[i].section_index == i) {
        if(!strcmp((*sections)[i].section_type, "SHT_STRTAB") && !((*sections)[i].section_name, ".dynstr")){
            sh_dynstr_p = (char*)mem + (*sections)[i].section_offset;
            break;
        }
		i++;
    }

	int j = 0;
	int sum_total_syms = 0;
    while ((*sections)[j].section_index == j) {
        if(strcmp((*sections)[j].section_type, "SHT_SYMTAB") && strcmp((*sections)[j].section_type, "SHT_DYNSYM")){
            j++;
			continue;
		}
		char *str_tbl;
		Elf64_Sym* sym_tbl;
		uint32_t i, total_syms;

		sym_tbl = ((Elf64_Sym*) &(mem[(*sections)[j].section_offset]));
	
		uint32_t str_tbl_ndx = (*sections)[j].section_link;
		str_tbl = &(mem[(*sections)[str_tbl_ndx].section_offset]);

		total_syms = ((*sections)[j].section_size/sizeof(Elf64_Sym));
		sum_total_syms += total_syms;
		j++;
	}

	*symbols = (struct symbol_t *) realloc(*symbols, sizeof(struct symbol_t) * (sum_total_syms));

	j = 0;
	int old_total_syms = 0;
	while ((*sections)[j].section_index == j) {
        if(strcmp((*sections)[j].section_type, "SHT_SYMTAB") && strcmp((*sections)[j].section_type, "SHT_DYNSYM")){
            j++;
			continue;
		}
		char *str_tbl;
		Elf64_Sym* sym_tbl;
		uint32_t i, total_syms;

		sym_tbl = ((Elf64_Sym*) &(mem[(*sections)[j].section_offset]));
	
		uint32_t str_tbl_ndx = (*sections)[j].section_link;
		str_tbl = &(mem[(*sections)[str_tbl_ndx].section_offset]);

		total_syms = ((*sections)[j].section_size/sizeof(Elf64_Sym));
	
		// printf("%d symbols\n", total_syms);

		for(i=0; i< total_syms; i++) {
			(*symbols)[i+old_total_syms].symbol_num = i+old_total_syms;
			(*symbols)[i+old_total_syms].symbol_name = strdup(str_tbl + sym_tbl[i].st_name);
			(*symbols)[i+old_total_syms].symbol_bind = strdup(get_symbol_bind(sym_tbl[i].st_info));
			// symbols[i+old_total_syms].symbol_index = get_symbol_index(sym_tbl[i].st_shndx);
			(*symbols)[i+old_total_syms].symbol_size = sym_tbl[i].st_size;
			(*symbols)[i+old_total_syms].symbol_type = strdup(get_symbol_type(sym_tbl[i].st_info));
			(*symbols)[i+old_total_syms].symbol_value = sym_tbl[i].st_value;
			(*symbols)[i+old_total_syms].symbol_visibility = strdup(get_symbol_visibility(sym_tbl[i].st_other));
		}
		j++;
		old_total_syms += total_syms;
	}
}