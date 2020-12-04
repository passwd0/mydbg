CC=gcc
LIBNAME = capstone

mydbg: mydbg.o pmparser.o vector.o utils.o
	$(CC) $^ -o $@ -g -l $(LIBNAME) -fPIE

mydbg.o: mydbg.c
	$(CC) -c $< -o $@ -l $(LIBNAME) -g

pmparser.o: pmparser.c
	$(CC) -c $< -o $@ -g

vector.o: vector.c
	$(CC) -c $< -o $@ -g

utils.o: utils.c
	$(CC) -c $< -o $@ -g

clean:
	rm *.o