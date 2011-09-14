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

