project('mydbg', 'c')

CC='clang'
src = ['src/mydbg.c', 'src/elfparser.c', 'src/utils.c', 'src/pmparser.c']
cdep = dependency('capstone')
ndep = dependency('ncurses')
executable('mydbg', src, dependencies: [cdep, ndep])
