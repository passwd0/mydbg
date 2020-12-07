#ifndef H_ELFPARSER
#define H_ELFPARSER

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>

struct symbol_t {
    char *symbol_index;
    uint64_t symbol_value;
    int symbol_num; //0
    int symbol_size; //0
    char *symbol_type;
    char *symbol_bind;
    char *symbol_visibility;
    char *symbol_name;
};

struct section_t {
    int section_index; //0
    uint64_t section_offset;
    uint64_t section_addr;
    char *section_name;
    char *section_type; 
    char *section_flags;
    int section_size;
    int section_ent_size;
    int section_addr_align;
    uint32_t section_link;
};

void parse_elf(char *filename);
uint8_t *get_memory(uint64_t addr, uint64_t size);
uint64_t get_entrypoint();
void get_programs();
void get_symbols(struct section_t **sections, struct symbol_t **syms);
void get_sections(struct section_t **sections);
void get_strings();

// int read_elf_header(const char *filename);
// section_t *get_sections();
// char *get_section_type(int tt);
// void print_sections(section_t *sections);

#endif