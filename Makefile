my_debugger: my_debugger.o pmparser.o
	gcc mydbg.o pmparser.o -o mydbg -g

mydbg.o: mydbg.c
	gcc -c mydbg.c -o mydbg.o -g

pmparser.o: pmparser.c
	gcc -c pmparser.c -o pmparser.o -g
