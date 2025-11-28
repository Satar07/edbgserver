// test_target.c
#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) void trigger_breakpoint() {
  printf("[Target] Trigger function called!\n");
}

int main() {
  printf("[Target] PID: %d\n", getpid());

  while (1) {
    trigger_breakpoint();
    sleep(1);
  }
  return 0;
}
