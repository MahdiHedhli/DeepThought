/* Trusted crash-authenticity wrapper.
 *
 * The sandbox cannot trust the target's stdout/exit code to tell a REAL sanitizer
 * abort from a forgery: docker collapses a SIGABRT death and a plain exit(134) into
 * the same status 134, and any text on stdout is target-controlled. This tiny
 * wrapper — built and baked into the image by US, not the code under test — runs the
 * harness as a CHILD and inspects the OS-reported wait status, which the child cannot
 * fabricate:
 *
 *   - child died by a deadly SIGNAL (WIFSIGNALED) -> exit CRASH_EXIT (99), the
 *     trusted "a real crash happened" code the sandbox gates on.
 *   - child exited normally -> pass its code through, EXCEPT any code in the reserved
 *     wrapper range [CRASH_EXIT..ERR_WAIT] is remapped to 98, so a harness can never
 *     forge the crash code OR a wrapper-infra code.
 *
 * The wrapper's OWN failures use RESERVED codes distinct from a normal harness exit,
 * and execv failure is detected out-of-band via a close-on-exec pipe (NOT the child's
 * exit code), so a missing/unstartable harness is reported as infrastructure — never
 * silently as a non-reproducing run, and never confused with a harness that happened
 * to exit a sysexits value like 70/71/72.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define CRASH_EXIT 99   /* OS-observed signal death — a real sanitizer abort */
#define ERR_USAGE 100
#define ERR_PIPE 101
#define ERR_FORK 102
#define ERR_EXECV 103   /* the harness could not be exec'd (it never ran) */
#define ERR_WAIT 104
#define RESERVED_LO CRASH_EXIT
#define RESERVED_HI ERR_WAIT

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "runner: usage: runner CMD [ARGS...]\n");
        return ERR_USAGE;
    }
    /* A close-on-exec pipe: if execv succeeds it closes silently (parent reads EOF);
     * if execv fails the child writes errno, so the parent detects the failure out of
     * band rather than guessing from an exit code that a harness could also produce. */
    int pfd[2];
    if (pipe(pfd) != 0) {
        perror("runner: pipe");
        return ERR_PIPE;
    }
    if (fcntl(pfd[1], F_SETFD, FD_CLOEXEC) != 0) {
        perror("runner: fcntl");
        return ERR_PIPE;
    }
    pid_t pid = fork();
    if (pid < 0) {
        perror("runner: fork");
        return ERR_FORK;
    }
    if (pid == 0) {
        close(pfd[0]);
        execv(argv[1], &argv[1]);   /* inherits stdio, so the ASan report still flows out */
        int e = errno;
        (void)!write(pfd[1], &e, sizeof(e));
        _exit(ERR_EXECV);
    }
    close(pfd[1]);
    int child_errno = 0;
    ssize_t n;
    /* Retry on EINTR: an interrupted read must not be mistaken for "execv succeeded"
     * (EOF), which would silently drop a real execv failure to a negative run. */
    while ((n = read(pfd[0], &child_errno, sizeof(child_errno))) < 0 && errno == EINTR) {
        /* interrupted — read again */
    }
    close(pfd[0]);
    if (n < 0) {
        /* A non-EINTR read failure: we cannot tell whether execv ran, so fail closed
         * as infrastructure rather than risk dropping an execv failure to a negative. */
        perror("runner: read");
        return ERR_PIPE;
    }

    int status = 0, rc;
    while ((rc = waitpid(pid, &status, 0)) < 0 && errno == EINTR) {
        /* interrupted — wait again */
    }
    if (rc < 0) {
        perror("runner: waitpid");
        return ERR_WAIT;
    }
    if (n > 0) {   /* the child wrote an errno -> execv failed; the harness never ran */
        fprintf(stderr, "runner: execv failed: %s\n", strerror(child_errno));
        return ERR_EXECV;
    }
    if (WIFSIGNALED(status)) {
        return CRASH_EXIT;   /* OS-observed signal death */
    }
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 98;
    /* A harness must never forge the crash code or a wrapper-infra code. */
    return (code >= RESERVED_LO && code <= RESERVED_HI) ? 98 : code;
}
