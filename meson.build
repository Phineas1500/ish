project('ish', 'c',
    default_options: ['default_library=static', 'c_std=gnu11', 'warning_level=2'])
cc = meson.get_compiler('c')

if cc.get_id() == 'clang'
    add_project_arguments('-Wimplicit-fallthrough', '-Wtautological-constant-in-range-compare', language: 'c')
endif

if get_option('b_sanitize').split(',').contains('undefined')
    add_project_arguments('-fno-sanitize=alignment', language: 'c')
endif

log_on = get_option('log').split()
log_off = get_option('nolog').split()
foreach channel : log_on + log_off
    if log_on.contains(channel)
        add_project_arguments('-DDEBUG_' + channel + '=1', language: 'c')
    else
        add_project_arguments('-DDEBUG_' + channel + '=0', language: 'c')
    endif
endforeach
add_project_arguments('-DLOG_HANDLER_' + get_option('log_handler').to_upper() + '=1', language: 'c')
add_project_arguments('-DENGINE_' + get_option('engine').to_upper() + '=1', language: 'c')

if get_option('arch') == 'x86_64'
    add_project_arguments('-DISH_64BIT=1', language: 'c')
    add_project_arguments('-DISH_64BIT=1', language: 'cpp')
endif

if get_option('no_crlf')
    add_project_arguments('-DNO_CRLF', language: 'c')
endif

add_project_arguments('-Wno-switch', language: 'c')

includes = [include_directories('.')]

threads = dependency('threads')
librt = cc.find_library('rt', required: false)
libm = cc.find_library('m', required: false)
libdl = cc.find_library('dl', required: false)
sqlite3 = cc.find_library('sqlite3')
dependencies = [librt, libm, libdl, threads, sqlite3]

subdir('vdso') # ish depends on the vdso

offsets = custom_target('offsets',
    output: 'cpu-offsets.h', input: 'asbestos/offsets.c', depfile: 'cpu-offsets.h.d',
    command: [find_program('tools/staticdefine.sh'), '@OUTDIR@/compile_commands.json', '@INPUT@', '@OUTPUT@', '@DEPFILE@'])

emu_src = [
    'emu/tlb.c',
    'emu/fpu.c',
    'emu/vec.c',
    'emu/mmx.c',
    'emu/float80.c',

]
# For now, use aarch64 gadgets for both 32-bit and 64-bit emulation on ARM64
# TODO: Create proper 64-bit gadgets later
gadgets = 'asbestos/gadgets-' + host_machine.cpu_family()

emu_src += [
    'asbestos/asbestos.c',
    'asbestos/gen.c',
    'asbestos/helpers.c',
    gadgets+'/entry.S',
    gadgets+'/memory.S',
    gadgets+'/control.S',
    gadgets+'/math.S',
    gadgets+'/bits.S',
    gadgets+'/string.S',
    gadgets+'/misc.S',
    offsets,
]

libish_emu = library('ish_emu', emu_src, include_directories: includes)

libfakefs = library('fakefs',
    ['fs/fake-db.c', 'fs/fake-migrate.c', 'fs/fake-rebuild.c'],
    include_directories: includes,
    dependencies: sqlite3)

subdir('deps')

if get_option('kernel') == 'ish'
    if get_option('engine') != 'asbestos'
        error('Only asbestos is supported with ish kernel')
    endif

    src = [
        'kernel/init.c',
        'kernel/errno.c',

        'kernel/calls.c',
        'kernel/memory.c',
        'kernel/user.c',
        'kernel/vdso.c', vdso,
        'kernel/task.c',
        'kernel/group.c',
        'kernel/log.c',

        'kernel/fork.c',
        'kernel/exec.c',
        'kernel/exit.c',
        'kernel/time.c',
        'kernel/mmap.c',
        'kernel/uname.c',
        'kernel/tls.c',
        'kernel/futex.c',
        'kernel/getset.c',
        'kernel/signal.c',
        'kernel/resource.c',
        'kernel/random.c',
        'kernel/misc.c',
        'kernel/eventfd.c',
        'kernel/ipc.c',
        'kernel/ptrace.c',

        'kernel/fs.c',
        'kernel/fs_info.c',
        'fs/mount.c',
        'fs/fd.c',
        'fs/inode.c',
        'fs/stat.c',
        'fs/dir.c',
        'fs/generic.c',
        'fs/path.c',
        'fs/real.c',
        'fs/fake.c',

        'fs/proc.c',
        'fs/proc/entry.c',
        'fs/proc/ish.c',
        'fs/proc/root.c',
        'fs/proc/pid.c',

        'fs/dyndev.c',

        'fs/adhoc.c',
        'fs/sock.c',
        'fs/pipe.c',
        'fs/sockrestart.c',
        'fs/lock.c',

        'fs/dev.c',
        'fs/mem.c',
        'fs/tty.c',
        'fs/tty-real.c',
        'fs/pty.c',
        'fs/tmp.c',

        'fs/poll.c',
        'kernel/poll.c',
        'kernel/epoll.c',

        'util/timer.c',
        'util/sync.c',
        'util/fifo.c',
        'util/fchdir.c',

        'platform/' + host_machine.system() + '.c',
    ]

    libish = library('ish', src,
        include_directories: includes)
    ish = declare_dependency(
        link_with: [libish, libish_emu, libfakefs],
        dependencies: dependencies,
        include_directories: includes)

    if not meson.is_cross_build()
        executable('ish', ['main.c'], dependencies: ish)
    endif

elif get_option('kernel') == 'linux'
    kernel_src = [
        'linux/main.c',
        'linux/fakefs.c',
    ]
    user_src = []
    emu_deps = []

    if get_option('engine') == 'asbestos'
        user_src += 'linux/emu_asbestos.c'
        emu_deps += declare_dependency(link_with: libish_emu)
    elif get_option('engine') == 'unicorn'
        user_src += 'linux/emu_unicorn.c'
        kernel_src += 'linux/emu_unicorn_kernel.c'
        emu_deps += declare_dependency(
            dependencies: [cc.find_library('unicorn', dirs: [meson.current_source_dir()+'/deps/unicorn/build'])],
            include_directories: include_directories('deps/unicorn/include'),
        )
    endif

    modules = static_library('linux_modules', kernel_src, dependencies: [linux_headers, sqlite3])
    user_modules = static_library('linux_user', user_src, dependencies: [user_linux_headers] + emu_deps)
    executable('ish',
        build_linux,
        link_with: [libfakefs],
        dependencies: [
            liblinux,
            libm,
            libdl,
            threads,
            declare_dependency(link_whole: [modules, user_modules]),
        ] + emu_deps)
endif

subdir('tools')

gdb_scripts = ['ish-gdb.gdb']
foreach script : gdb_scripts
    custom_target(script,
        output: script, input: script,
        command: ['ln', '-sf', '@INPUT@', '@OUTPUT@'],
        build_by_default: true)
endforeach

if not meson.is_cross_build()
    # test for floating point library
    float80_test = executable('float80_test', ['emu/float80.c', 'emu/float80-test.c'], dependencies: [libm])
    test('float80', float80_test)
endif

e2e_test = find_program('tests/e2e/e2e.bash')
test('e2e', e2e_test, args: ['-y'], timeout: 180)
