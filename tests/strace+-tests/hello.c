// The first-ever test for strace++!  Compile a 32-bit binary with:
//   gcc -m32 -g -O0 -fno-omit-frame-pointer hello.c -o hello32
#include <stdio.h>

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

/* Example run:

# Compile
gcc -m32 -g -O0 -fno-omit-frame-pointer hello.c -o hello32

# Run hello32
strace++/strace -o strace.out ./hello32

# Post-process strace.out
python strace++/scripts/pretty_print_strace_out.py strace.out

Example (simplified) output:

write(1, "Hello world\n", 12)           = 12
  > new_do_write() fileops.c:530 (/lib32/libc-2.11.1.so:0x67aef:0xf75ccaef)
  > _IO_new_do_write() fileops.c:503 (/lib32/libc-2.11.1.so:0x67e06:0xf75cce06)
  > _IO_new_file_overflow() fileops.c:889 (/lib32/libc-2.11.1.so:0x68928:0xf75cd928)
  > __overflow() genops.c:249 (/lib32/libc-2.11.1.so:0x6b09a:0xf75d009a)
  > _IO_puts() ioputs.c:40 (/lib32/libc-2.11.1.so:0x5eacb:0xf75c3acb)
  > main() hello.c:17 (/home/pgbovine/hello32:0x432:0x8048432)
  > __libc_start_main() libc-start.c:258 (/lib32/libc-2.11.1.so:0x16bd6:0xf757bbd6)
  > _start (/home/pgbovine/hello32:0x351:0x8048351)
write(1, "foo\n", 4)                    = 4
  > new_do_write() fileops.c:530 (/lib32/libc-2.11.1.so:0x67aef:0xf75ccaef)
  > _IO_new_do_write() fileops.c:503 (/lib32/libc-2.11.1.so:0x67e06:0xf75cce06)
  > _IO_new_file_overflow() fileops.c:889 (/lib32/libc-2.11.1.so:0x68928:0xf75cd928)
  > __overflow() genops.c:249 (/lib32/libc-2.11.1.so:0x6b09a:0xf75d009a)
  > _IO_puts() ioputs.c:40 (/lib32/libc-2.11.1.so:0x5eacb:0xf75c3acb)
  > foo() hello.c:12 (/home/pgbovine/hello32:0x416:0x8048416)
  > main() hello.c:18 (/home/pgbovine/hello32:0x437:0x8048437)
  > __libc_start_main() libc-start.c:258 (/lib32/libc-2.11.1.so:0x16bd6:0xf757bbd6)
  > _start (/home/pgbovine/hello32:0x351:0x8048351)
write(1, "bar\n", 4)                    = 4
  > new_do_write() fileops.c:530 (/lib32/libc-2.11.1.so:0x67aef:0xf75ccaef)
  > _IO_new_do_write() fileops.c:503 (/lib32/libc-2.11.1.so:0x67e06:0xf75cce06)
  > _IO_new_file_overflow() fileops.c:889 (/lib32/libc-2.11.1.so:0x68928:0xf75cd928)
  > __overflow() genops.c:249 (/lib32/libc-2.11.1.so:0x6b09a:0xf75d009a)
  > _IO_puts() ioputs.c:40 (/lib32/libc-2.11.1.so:0x5eacb:0xf75c3acb)
  > bar() hello.c:7 (/home/pgbovine/hello32:0x3f6:0x80483f6)
  > foo() hello.c:13 (/home/pgbovine/hello32:0x41b:0x804841b)
  > main() hello.c:18 (/home/pgbovine/hello32:0x437:0x8048437)
  > __libc_start_main() libc-start.c:258 (/lib32/libc-2.11.1.so:0x16bd6:0xf757bbd6)
  > _start (/home/pgbovine/hello32:0x351:0x8048351)
write(1, "bar again\n", 10)             = 10
  > new_do_write() fileops.c:530 (/lib32/libc-2.11.1.so:0x67aef:0xf75ccaef)
  > _IO_new_do_write() fileops.c:503 (/lib32/libc-2.11.1.so:0x67e06:0xf75cce06)
  > _IO_new_file_overflow() fileops.c:889 (/lib32/libc-2.11.1.so:0x68928:0xf75cd928)
  > __overflow() genops.c:249 (/lib32/libc-2.11.1.so:0x6b09a:0xf75d009a)
  > _IO_puts() ioputs.c:40 (/lib32/libc-2.11.1.so:0x5eacb:0xf75c3acb)
  > bar() hello.c:8 (/home/pgbovine/hello32:0x402:0x8048402)
  > foo() hello.c:13 (/home/pgbovine/hello32:0x41b:0x804841b)
  > main() hello.c:18 (/home/pgbovine/hello32:0x437:0x8048437)
  > __libc_start_main() libc-start.c:258 (/lib32/libc-2.11.1.so:0x16bd6:0xf757bbd6)
  > _start (/home/pgbovine/hello32:0x351:0x8048351)

*/
