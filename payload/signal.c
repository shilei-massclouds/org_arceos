#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

static int child_exit = 0;

void sig_handler(int signo)
{
    if (signo == SIGINT) {
        printf("received SIGINT!\n");
        child_exit = 1;
    }
}

int main()
{
    printf("Hello, signal!\n");

    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        printf("Cant catch SIGINT\n");
        exit(-1);
    }

    pid_t pid = fork();
    if (pid == 0) {
        printf("Child is running ...\n");
        while (!child_exit) {
            sleep(1);
        }
        printf("Child is exiting ...\n");
    } else {
        kill(pid, SIGINT);
        printf("Parent sends sig!\n");

        int ret = 0;
        waitpid(pid, &ret, 0);
        printf("Parent gets code [%d]\n", ret);
    }
    return 0;
}
