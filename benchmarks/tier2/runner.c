/* Trusted crash-authenticity wrapper.
 *
 * The sandbox cannot trust the target's stdout/exit code to tell a REAL sanitizer
 * abort from a forgery: docker collapses a SIGABRT death and a plain exit(134)
 * into the same status 134, and any text on stdout is target-controlled. This
 * tiny wrapper — built and baked into the image by US, not the code under test —
 * runs the harness as a CHILD and inspects the OS-reported wait status, which the
 * child cannot fabricate:
 *
 *   - child died by a deadly SIGNAL (WIFSIGNALED) -> exit 99, the trusted
 *     "a real crash happened" code the sandbox gates on.
 *   - child exited normally -> pass its code through, but REMAP 99 to 98 so a
 *     child that calls exit(99) can never masquerade as a signal death.
 *
 * So exit 99 from this wrapper means "the OS observed the child die by a signal",
 * a fact no amount of target-printed ASan text or self-chosen exit code can forge.
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

#define SANITIZER_CRASH_EXIT 99

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "runner: usage: runner CMD [ARGS...]\n");
        return 64;
    }
    pid_t pid = fork();
    if (pid < 0) {
        perror("runner: fork");
        return 70;
    }
    if (pid == 0) {
        execv(argv[1], &argv[1]);   /* inherits stdio, so the ASan report still flows out */
        perror("runner: execv");
        _exit(71);
    }
    int status = 0;
    int rc;
    /* Retry on EINTR so a stray signal to the wrapper cannot be misreported as a
     * waitpid failure while the child is still fine. */
    while ((rc = waitpid(pid, &status, 0)) < 0 && errno == EINTR) {
        /* interrupted — wait again */
    }
    if (rc < 0) {
        perror("runner: waitpid");
        return 72;
    }
    if (WIFSIGNALED(status)) {
        return SANITIZER_CRASH_EXIT;                 /* OS-observed signal death */
    }
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 98;
    return code == SANITIZER_CRASH_EXIT ? 98 : code; /* a child exit(99) is NOT a crash */
}
