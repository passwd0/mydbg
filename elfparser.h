#ifndef H_ELFPARSER
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


// typedef struct {
//     char *symbol_index;
//     int *symbol_value;
//     int symbol_num; //0
//     int symbol_size; //0
//     char *symbol_type;
//     char *symbol_bind;
//     char *symbol_visibility;
//     char *symbol_name;
//     char *symbol_section;      
// } symbol_t;

// typedef struct {
//     int section_index; //0
//     uint64_t *section_offset;
//     uint64_t *section_addr;
//     std::string section_name;
//     char *section_type; 
//     int section_size;
//     int section_ent_size;
//     int section_addr_align;
// } section_t;

// int read_elf_header(const char *filename);
// section_t *get_sections();
// char *get_section_type(int tt);
// void print_sections(section_t *sections);

#endif