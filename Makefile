CC=g++
LIBNAME = capstone

mydbg: mydbg.o vector.o utils.o elf_parser.o
	$(CC) $^ -o $@ -g -l $(LIBNAME) -fPIE

mydbg.o: mydbg.c
	$(CC) -c $< -o $@ -l $(LIBNAME) -g

# pmparser.o: pmparser.c
# 	$(CC) -c $< -o $@ -g

vector.o: vector.c
	$(CC) -c $< -o $@ -g

utils.o: utils.c
	$(CC) -c $< -o $@ -g

elf_parser.o: elf_parser.cpp
	$(CC) -c $< -o $@ -g

clean:
	rm *.o