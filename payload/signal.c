#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

void sig_handler(int signo)
{
    if (signo == SIGINT) {
        printf("received SIGINT!\n");
        exit(0);
    }
}

int main()
{
    printf("Hello, signal!\n");

    pid_t pid = fork();
    if (pid == 0) {
        printf("Child is running ...\n");
        while (1) {
        }
    } else {
        kill(pid, SIGINT);
        printf("Parent sends sig!\n");

        int ret = 0;
        waitpid(pid, &ret, 0);
        printf("Parent gets code [%d]\n", ret);
    }
    return 0;
}
