mydbg: mydbg.o pmparser.o vector.o
	gcc mydbg.o pmparser.o vector.o -o mydbg -g

mydbg.o: mydbg.c
	gcc -c mydbg.c -o mydbg.o -g

pmparser.o: pmparser.c
	gcc -c pmparser.c -o pmparser.o -g

vector.o: vector.c
	gcc -c vector.c -o vector.o -g
