# OS command injection (CWE-78) fixture (Python), modeled on ansys CVE-2024-29189.
import subprocess


def vulnerable(args):
    # spawned via a shell -> metacharacters in args execute
    return subprocess.Popen(args, shell=True)


def safe(args):
    # no shell; argv list passed directly
    return subprocess.Popen(args)
