my_debugger: my_debugger.o pmparser.o
	gcc my_debugger.o pmparser.o -o my_debugger -g

my_debugger.o: my_debugger.c
	gcc -c my_debugger.c -o my_debugger.o -g

pmparser.o: pmparser.c
	gcc -c pmparser.c -o pmparser.o -g
