#include "elfparser.h"

int get_sections(char *filename)
{
	int fd, i;
	uint8_t *mem;
	struct stat st;
	char *StringTable, *interp;

	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;


	if ((fd = open(filename, O_RDONLY)) < 0 ) {
		perror("open");
		exit(-1);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(-1);
	}

	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	ehdr = (Elf64_Ehdr *) mem;

	phdr = (Elf64_Phdr *) &mem[ehdr->e_phoff];
	shdr = (Elf64_Shdr *) &mem[ehdr->e_shoff];

	if (mem[0] != 0x7f && strcmp(&mem[1], "ELF")) {
		fprintf(stderr, "%s is not an ELF file\n", filename);
		exit(-1);
	}

	// if (ehdr->e_type != ET_EXEC) {
	// 	fprintf(stderr, "%s is not an executable\n", filename);
	// 	exit(-1);
	// }

	printf("Program Entry point: 0x%x \n", ehdr->e_entry );

	StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];

	printf("Section header list:\n\n");

	for (i = 1; i < ehdr->e_shnum; i++)
	{
		printf("%s: 0x%x\n", &StringTable[shdr[i].sh_name], shdr[i].sh_addr );

	}

	printf("\nProgram header list\n\n");

	for (i = 0; i < ehdr->e_phnum; ++i)
	{
		switch(phdr[i].p_type) {
			case PT_LOAD:
				if (phdr[i].p_offset == 0)
					printf("Text segment: 0x%x\n", phdr[i].p_vaddr);
				else
					printf("Data segment: 0x%x\n", phdr[i].p_vaddr);
				break;
			case PT_INTERP:
				interp = strdup((char *) &mem[phdr[i].p_offset]);
				printf("Interpreter: %s\n", interp);
				break;
			case PT_NOTE:
				printf("Note segment: 0x%x\n", phdr[i].p_vaddr);
				break;
			case PT_DYNAMIC:
				printf("Dynamic segment: 0x%x\n", phdr[i].p_vaddr);
				break;
			case PT_PHDR:
				printf("Phdr segment: 0x%x\n", phdr[i].p_vaddr);
				break;
		}
	}
}

// int read_elf_header(const char *filename) {
// 	int fd, i;
//     struct stat st;

//     if ((fd = open(filename, O_RDONLY)) < 0) {
//         printf("Err %d: open\n", fd);
//         exit(-1);
//     }
//     if (fstat(fd, &st) < 0) {
//         printf("Err: fstat\n");
//         exit(-1);
//     }
//     uint64_t *map_binary = (uint64_t *) mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
//     if (mmap_binary == MAP_FAILED) {
//         printf("Err: mmap\n");
//         exit(-1);
//     }

//     Elf64_Ehdr *header = (Elf64_Ehdr*)mmap_binary;
//     if (header->e_ident[EI_CLASS] != ELFCLASS64) {
//         printf("Only 64-bit files supported\n");
//     }
// }

// void print_sections(section_t *sections) {
//     printf("  [Nr] %-16s %-16s %-16s %s\n", "Name", "Type", "Address", "Offset");
//     printf("       %-16s %-16s %5s\n",
//                     "Size", "EntSize", "Align");
    
//     printf("len: %d\n", sizeof(sections));
//     for (int i=0; i<sizeof(sections); i++) {
//         printf("  [%2d] %-16s %-16s %016llx %08llx\n", 
//             sections[i].section_index,
//             sections[i].section_name.c_str(),
//             sections[i].section_type,
//             sections[i].section_addr, 
//             sections[i].section_offset);

//         printf("       %016zx %016llx %5llx\n",
//             sections[i].section_size, 
//             sections[i].section_ent_size,
//             sections[i].section_addr_align);
//     }
// }

// section_t *get_sections() {
//     Elf64_Ehdr *ehdr = (Elf64_Ehdr*)mmap_binary;
//     Elf64_Shdr *shdr = (Elf64_Shdr*)(mmap_binary + ehdr->e_shoff);
//     int shnum = ehdr->e_shnum;

//     Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
//     const char *const sh_strtab_p = (char*)mmap_binary + sh_strtab->sh_offset;

//     section_t *sections = (section_t *) malloc(sizeof(section_t) * shnum);
//     for (int i = 0; i < shnum; ++i) {
//         section_t section;
//         section.section_index= i;
//         section.section_name = std::string(sh_strtab_p + shdr[i].sh_name);
//         section.section_type = get_section_type(shdr[i].sh_type);
//         section.section_addr = (uint64_t *) shdr[i].sh_addr;
//         section.section_offset = (uint64_t *) shdr[i].sh_offset;
//         section.section_size = shdr[i].sh_size;
//         section.section_ent_size = shdr[i].sh_entsize;
//         section.section_addr_align = shdr[i].sh_addralign; 
        
//         sections[i] = section;
//     }
//     return sections;
// }

// char *get_section_type(int tt) {
//     if(tt < 0)
//         return "UNKNOWN";

//     switch(tt) {
//         case 0: return "SHT_NULL";      /* Section header table entry unused */
//         case 1: return "SHT_PROGBITS";  /* Program data */
//         case 2: return "SHT_SYMTAB";    /* Symbol table */
//         case 3: return "SHT_STRTAB";    /* String table */
//         case 4: return "SHT_RELA";      /* Relocation entries with addends */
//         case 5: return "SHT_HASH";      /* Symbol hash table */
//         case 6: return "SHT_DYNAMIC";   /* Dynamic linking information */
//         case 7: return "SHT_NOTE";      /* Notes */
//         case 8: return "SHT_NOBITS";    /* Program space with no data (bss) */
//         case 9: return "SHT_REL";       /* Relocation entries, no addends */
//         case 11: return "SHT_DYNSYM";   /* Dynamic linker symbol table */
//         default: return "UNKNOWN";
//     }
//     return "UNKNOWN";
// }