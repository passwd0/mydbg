project('mydbg', 'c')

CC='clang'
src = ['src/mydbg.c', 'src/elfparser.c', 'src/vector.c', 'src/utils.c', 'src/pmparser.c']
cdep = dependency('capstone')
executable('mydbg', src, dependencies: cdep)
