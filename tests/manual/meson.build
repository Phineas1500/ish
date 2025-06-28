project('ish-tests', 'c')
add_project_arguments(['-m32', '-fno-stack-protector'], language: 'c')
add_project_link_arguments('-m32', language: 'c')

# hello world
executable('hello', ['hello.c'], link_args: ['-static', '-nostdlib'])
executable('hello-libc-static', ['hello-clib.c'], link_args: ['-static'])
executable('hello-libc', ['hello-clib.c'])

# 64-bit test binary (override the default -m32)
executable('hello-64bit', ['hello-clib.c'], 
    c_args: ['-m64', '-fno-stack-protector'], 
    link_args: ['-m64', '-static'],
    override_options: ['c_args='])

# simple benchmark
executable('looper', ['looper.c'])
executable('fibbonaci', ['fibbonaci.c'])

# filesystem
executable('cat', ['cat.c'])
executable('stat', ['stat.c'], c_args: ['-D_FILE_OFFSET_BITS=64'])
executable('getdents', ['getdents.c'])

executable('signal', ['signal.c'], link_args: ['-static'])
executable('forkexec', ['forkexec.c'])

executable('thread', ['thread.c'], dependencies: dependency('threads'))

# various tests for code that modifies itself
executable('modify', ['modify.c'], link_args: ['-zexecstack'])

# qemu test program
# executable('qemu-test', ['qemu-test.c'], link_args: ['-lm'])  # commented out - file missing

run_target('busybox',
    command: ['get-busybox.sh'])
