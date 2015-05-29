**strace+** is an improved version of strace that collects stack traces associated with each system call. Since system calls require an expensive user-kernel context switch, they are often sources of performance bottlenecks. strace+ allows programmers to do more detailed system call profiling and determine, say, which call sites led to costly syscalls and thus have potential for optimization.

Created by [Philip Guo](http://www.pgbovine.net/)

**Disclaimer: As of Jan 2012, this project is unsupported. Features from strace-plus have been merged into the official strace as the -k option, starting from version 4.9.**


## Quick-start guide ##

Prerequisites: A reasonably-modern 32-bit or 64-bit x86-Linux machine with the standard GNU compiler toolchain (i.e., gcc, gdb, make, and friends).

0. Check out the source code from Git (requires git >= 1.6.6)

```
git clone https://code.google.com/p/strace-plus/
```

1. Compile strace+

```
cd strace-plus/
autoreconf -f -i # might be needed on some platforms, but unsure
./configure && make
```

2. Compile a "hello world" test program

```
gcc examples/hello.c -o hello
```

`hello.c` is a simple program that makes four `write` system calls via `printf` statements:

```
include <stdio.h>

void bar() {
  printf("bar\n");
  printf("bar again\n");
}

void foo() {
  printf("foo\n");
  bar();
}

int main() {
  printf("Hello world\n");
  foo();
  return 0;
}
```

3. Run strace+ on the `hello` executable to generate a trace file named `hello.out`.

```
./strace+ -o hello.out ./hello
```

4. Post-process `hello.out` to print out a list of system calls each augmented with stack traces (requires `python` >= 2.6, `gdb`, and `file` programs to be installed).

```
  python scripts/pretty_print_strace_out.py hello.out --trace
```

If all goes well, you should see a print-out where each line contains a system call followed by a stack trace of functions on the stack at the time the respective system call was made.  Here is an excerpt showing the four `write` system calls and their contexts:

```
write(1, "Hello world\n", 12)           = 12
  > write() ../sysdeps/unix/syscall-template.S:82
  > _IO_new_file_write() fileops.c:1277
  > _IO_new_do_write() fileops.c:531
  > _IO_new_file_overflow() fileops.c:889
  > _IO_puts() ioputs.c:40
  > main() [/home/pgbovine/strace-plus/hello]
  > __libc_start_main() libc-start.c:258
  > _start() [/home/pgbovine/strace-plus/hello]
write(1, "foo\n", 4)                    = 4
  > write() ../sysdeps/unix/syscall-template.S:82
  > _IO_new_file_write() fileops.c:1277
  > _IO_new_do_write() fileops.c:531
  > _IO_new_file_overflow() fileops.c:889
  > _IO_puts() ioputs.c:40
  > foo() [/home/pgbovine/strace-plus/hello]
  > main() [/home/pgbovine/strace-plus/hello]
  > __libc_start_main() libc-start.c:258
  > _start() [/home/pgbovine/strace-plus/hello]
write(1, "bar\n", 4)                    = 4
  > write() ../sysdeps/unix/syscall-template.S:82
  > _IO_new_file_write() fileops.c:1277
  > _IO_new_do_write() fileops.c:531
  > _IO_new_file_overflow() fileops.c:889
  > _IO_puts() ioputs.c:40
  > bar() [/home/pgbovine/strace-plus/hello]
  > foo() [/home/pgbovine/strace-plus/hello]
  > main() [/home/pgbovine/strace-plus/hello]
  > __libc_start_main() libc-start.c:258
  > _start() [/home/pgbovine/strace-plus/hello]
write(1, "bar again\n", 10)             = 10
  > write() ../sysdeps/unix/syscall-template.S:82
  > _IO_new_file_write() fileops.c:1277
  > _IO_new_do_write() fileops.c:531
  > _IO_new_file_overflow() fileops.c:889
  > _IO_puts() ioputs.c:40
  > bar() [/home/pgbovine/strace-plus/hello]
  > foo() [/home/pgbovine/strace-plus/hello]
  > main() [/home/pgbovine/strace-plus/hello]
  > __libc_start_main() libc-start.c:258
  > _start() [/home/pgbovine/strace-plus/hello]
```

Notice how the top function in each stack trace is always the libc `write()` function, followed by other libc functions and then the functions from `hello.c` that called `printf`.


5. If you want to print a summary of stack traces, use the `--tree` option:

```
python scripts/pretty_print_strace_out.py hello.out --tree
```

You should see an aggregated stack trace output like the following, which shows that `write` was called four times with slightly different call stacks:

```
=== write ===
     4    write()+0 (../sysdeps/unix/syscall-template.S:82)
     4      _IO_new_file_write()+67 (fileops.c:1277)
     4        _IO_new_do_write()+149 (fileops.c:531)
     4          _IO_new_file_overflow()+324 (fileops.c:889)
     4            _IO_puts()+419 (ioputs.c:40)
     1              bar()+24 (/home/pgbovine/strace-plus/hello)
     1                foo()+24 (/home/pgbovine/strace-plus/hello)
     1                  main()+24 (/home/pgbovine/strace-plus/hello)
     1                    __libc_start_main()+253 (libc-start.c:258)
    [1]                     _start()+41 (/home/pgbovine/strace-plus/hello)
     1              bar()+14 (/home/pgbovine/strace-plus/hello)
     1                foo()+24 (/home/pgbovine/strace-plus/hello)
     1                  main()+24 (/home/pgbovine/strace-plus/hello)
     1                    __libc_start_main()+253 (libc-start.c:258)
    [1]                     _start()+41 (/home/pgbovine/strace-plus/hello)
     1              foo()+14 (/home/pgbovine/strace-plus/hello)
     1                main()+24 (/home/pgbovine/strace-plus/hello)
     1                  __libc_start_main()+253 (libc-start.c:258)
    [1]                   _start()+41 (/home/pgbovine/strace-plus/hello)
     1              main()+14 (/home/pgbovine/strace-plus/hello)
     1                __libc_start_main()+253 (libc-start.c:258)
    [1]                 _start()+41 (/home/pgbovine/strace-plus/hello)
```

Notice that this "tree view" is an aggregated version of the "trace view" offered by the `--trace` option.  Terminal nodes in the tree are surrounded by brackets (e.g., `[1]`).


---


## More detailed documentation ##

### High-level concepts ###

strace+ is a modified version of strace (v4.6) that prints out the call stack alongside each traced system call.  For example, regular strace might print the following line when the traced program makes a `write` system call:

```
write(1, "Hello world\n", 12) = 12
```

Instead, strace+ prints the following line, which prepends the stack trace onto the original strace print-out:

```
[ /lib32/libc-2.11.1.so:0x6b09a:0xf768609a /lib32/libc-2.11.1.so:0x5eacb:0xf7679acb /home/pgbovine/hello:0x432:0x8048432  ] write(1, "Hello world\n", 12) = 12
```


### Raw strace+ traces ###

Each entry within the leading brackets represents information about one stack frame.  In this one-line toy example, there are three stack frames:

```
/lib32/libc-2.11.1.so:0x6b09a:0xf768609a
/lib32/libc-2.11.1.so:0x5eacb:0xf7679acb
/home/pgbovine/hello:0x432:0x8048432
```

Each stack frame entry contains these three elements, separated by colon delimiters:

  1. The binary file containing the code that this frame is executing
  1. The instruction that this frame is currently executing, given as a hex offset from the start of the binary
  1. The absolute address of the instruction as it appears in the process's address space

strace+ uses [libunwind](http://www.nongnu.org/libunwind/) to obtain backtraces because it is fairly robust and does not require the presence of a frame pointer.  The main disadvantage of using libunwind is that it's **much slower** than a simple "frame pointer walking" technique.  However, frame pointers aren't usually available in optimized 64-bit ELF binaries, so libunwind is the only practical way to obtain a backtrace on 64-bit Linux systems.  (They're more likely to exist in 32-bit binaries, though.)

As a faster alternative, if you invoke strace+ with the `-w` option, it uses a "frame pointer walking" technique: strace+ first queries the current instruction pointer (`%eip`) and then uses the frame pointer (`%ebp`) to walk up the stack and collect the return address of each successive frame.  For this technique to work, the target program and **all libraries** (e.g., libc) must be compiled with a frame pointer.  (Note that when a 64-bit strace+ is monitoring a 32-bit target binary, it always uses this frame pointer walking technique, since a 64-bit libunwind is unable to parse 32-bit binaries.)

For both 32-bit and 64-bit binaries, filenames are obtained by querying (`/proc/[target PID]/maps`) and calculating which binary files are mapped into the virtual address region where each instruction pointer is located.


### Post-processing the raw traces ###

Since raw strace+ output isn't useful to developers, I've created a post-processing script (`scripts/pretty_print_strace_out.py`), which transforms the raw output into a "profile tree" of system call and stack frame occurrences.

My Python script calls `gdb` to open the binaries and query for the debugging information associated with each instruction pointer address.  When debug symbols are available, then my script can print source filenames and line numbers; when debug symbols aren't available, then my script simply prints out function names and offsets.  Piggy-backing off of `gdb` is useful since `gdb` supports "split debug" binaries that keep debugging symbols in a separate `.debug` file.

Running the post-processing script on the one-line trace in our toy example produces the following output:

```
=== write ===
     1    new_do_write()+51 (fileops.c:530)
     1      _IO_puts()+363 (ioputs.c:40)
    [1]       main()+26 (hello.c:18)
```

This snippet shows that the `write` syscall was called once from the following call chain: `main -> _IO_puts -> new_do_write`.  Notice that the `main` function is from my `hello.c` source file, and the other two functions are from `libc` source files.  The numbers formatted like `+26` represent instruction offsets from the beginning of the function's source code, which can be used to disambiguate between two different call sites in the same function (e.g., when line numbers aren't available).


Run this command to get a list of post-processing options:
```
python scripts/pretty_print_strace_out.py --help
```

### Useful strace options ###

Since strace+ is built upon strace, you can use all of the usual strace options.  Here are a few that I've found to be useful:

  * The `-f` option tells strace to follow forks, in order to trace child processes.  If you don't use this option, then strace will only trace the process you launched but NOT its children.
  * The `-o [filename]` option tells strace to print its output to a given filename.  This is a more elegant method than stdout/stderr redirection.
  * The `-e trace=[list of syscalls]` option tells strace to only trace the listed syscalls.  For example, if you only want to trace `open` and `close` syscalls, you could use `-e trace=open,close`.
    * Also, if you explicitly don't want to trace a syscall, put a `\!` in front of its name.  e.g., to ignore the `gettid` syscall, use `-e trace=\!gettid`.

Selective tracing is especially useful when honing in on a particular problem.  Also, tracing all syscalls can lead to an unbearable performance slowdown and produce way too large of a raw trace file.

**(TODO: add an strace+ option to only walk up the stack to a limited depth, which could improve performance if the full stack isn't needed in the raw traces.)**