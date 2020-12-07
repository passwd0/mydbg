CC=clang
LIBNAME = capstone

mydbg: mydbg.o vector.o utils.o elfparser.o pmparser.o
	$(CC) $^ -o $@ -g -l $(LIBNAME) -fPIE -Wall

mydbg.o: mydbg.c
	$(CC) -c $< -o $@ -l $(LIBNAME) -g

pmparser.o: pmparser.c
	$(CC) -c $< -o $@ -g

vector.o: vector.c
	$(CC) -c $< -o $@ -g

utils.o: utils.c
	$(CC) -c $< -o $@ -g

elfparser.o: elfparser.c
	$(CC) -c $< -o $@ -g

clean:
	rm *.o