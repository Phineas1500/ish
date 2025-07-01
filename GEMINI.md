# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

### iOS App (Xcode)
- Open `iSH.xcodeproj` in Xcode to build the iOS app
- Set `ROOT_BUNDLE_IDENTIFIER` in `iSH.xcconfig` to something unique
- Update development team ID in project build settings
- Scripts handle the rest automatically

### Command Line Tool (Linux/macOS)
```bash
# Activate development environment
source ish-env/bin/activate

# Initial setup (32-bit default)
meson setup build
ninja -C build

# 64-bit experimental build
meson setup build-64bit -Darch=x86_64
ninja -C build-64bit

# Run tests
meson test -C build
# or run specific tests:
build/float80_test
tests/e2e/e2e.bash -y
```

### Cross-compilation
- Use appropriate `.xcconfig` files for target platform
- `Linux.xcconfig` for Linux builds
- `iOS.xcconfig` for iOS builds

## Logging and Debugging

Enable logging channels in build configuration:
- **Xcode**: Set `ISH_LOG` in `iSH.xcconfig` to space-separated channel list
- **Meson**: `meson configure -Dlog="<channels>"`

Key channels:
- `strace`: System call tracing (most useful for debugging)
- `instr`: Instruction-level execution tracing (very verbose)
- `verbose`: General debug information

Debug tools:
- Use `tools/ptraceomatic` instead of `ish` for single-step register comparison
- GDB scripts: `ish-gdb.gdb`
- LLDB scripts: `ish-lldb.lldb`

## Architecture Overview

iSH is a Linux x86 emulator for iOS with three main layers:

### 1. Emulation Layer (`asbestos/` + `emu/`)
- **Asbestos JIT**: Dynamic binary translation from x86 to ARM64 "gadgets"
- **CPU State**: Complete x86 processor emulation including FPU, MMX, SSE
- **Entry Point**: `cpu_run_to_interrupt()` - main execution loop
- **Performance**: Uses threaded code technique with function pointer arrays

### 2. Kernel Layer (`kernel/`)
- **Process Management**: Linux-compatible task abstraction (`task.h`)
- **System Calls**: Complete Linux syscall compatibility layer (`calls.h`)
- **Memory Management**: Virtual memory with copy-on-write (`memory.h`)
- **Initialization**: `become_first_process()` sets up initial process context

### 3. Filesystem Layer (`fs/`)
- **VFS Core**: Virtual filesystem switch with pluggable backends
- **Real FS**: Direct host filesystem access (`real.c`)
- **Fake FS**: SQLite-backed metadata overlay for Linux compatibility (`fake.c`)
- **Special FS**: /proc (`proc/`), /dev, tmpfs implementations

### Key Integration Points
- **Execution Flow**: `main.c` → `xX_main_Xx.h` → mount filesystem → `do_execve()`
- **Memory Translation**: Two-level page tables in `struct mem` with MMU interface
- **Syscall Dispatch**: x86 interrupt → kernel syscall handler → VFS operations
- **Cache Management**: Asbestos invalidates compiled blocks on memory changes

## Development Workflows

### Setting up Alpine Root Filesystem
```bash
# Download Alpine minirootfs i386 tarball from alpinelinux.org/downloads/
./tools/fakefsify <tarball> <output_directory>
./ish -f <output_directory> /bin/sh
```

### Adding New System Calls
1. Add declaration to `kernel/calls.h`
2. Implement in appropriate `kernel/*.c` file
3. Add to syscall table in `kernel/calls.c`
4. Test with `strace` logging enabled

### Filesystem Backend Development
1. Implement `struct fs_ops` interface
2. Add mount type handling in `fs/mount.c`
3. Update initialization in `kernel/fs.c`

### Assembly Gadgets (Advanced)
- Located in `asbestos/gadgets-<arch>/`
- Each gadget ends with tailcall to next function
- Modify with extreme caution - compiler/assembler issues are common
- Use `cpu-offsets.h` for accessing CPU state from assembly

## Important Files and Interfaces

### Core Headers
- `debug.h`: Logging and debug macros
- `misc.h`: Common utilities and definitions
- `kernel/task.h`: Process/thread abstraction
- `fs/fd.h`: File descriptor operations
- `emu/cpu.h`: Complete x86 CPU state definition

### Entry Points
- `main.c`: Command-line tool entry point
- `app/main.m`: iOS app entry point
- `kernel/init.c`: Process initialization
- `asbestos/asbestos.c`: JIT compiler core

### Build Configuration
- `meson.build`: Main build system configuration
- `app/*.xcconfig`: Xcode build configurations
- `meson_options.txt`: Available build options

## Code Conventions

- Assembly gadgets use minimal naming (`ss`, `s`, `a`) due to assembler limitations
- Kernel code follows Linux kernel style
- iOS app code follows Objective-C conventions
- C code uses GNU11 standard with warning level 2