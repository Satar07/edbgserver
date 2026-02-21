#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

void logic_A() { printf("Thread A running\n"); sleep(1); }
void logic_B() { printf("Thread B running\n"); sleep(1); }
void logic_C() { printf("Thread C running\n"); sleep(1); }

void* worker_A(void* arg) { while(1) logic_A(); }
void* worker_B(void* arg) { while(1) logic_B(); }
void* worker_C(void* arg) { while(1) logic_C(); }

int main() {
    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, worker_A, NULL);
    pthread_create(&t2, NULL, worker_B, NULL);
    pthread_create(&t3, NULL, worker_C, NULL);
    pthread_exit(NULL);
}
