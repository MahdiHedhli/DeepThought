// OS command injection (CWE-78) fixture: vulnerable + safe, one file. Detector only parses.
const { execSync, execFileSync } = require('child_process');

function vulnerable(userArg) {
  // dynamic input string-built into a shell command
  return execSync('npm ' + userArg);
}

function safe(userArg) {
  // argv array, no shell — the value is never re-parsed by a shell
  return execFileSync('npm', [userArg]);
}
