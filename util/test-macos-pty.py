#!/usr/bin/python3
"""Exercise native PTY allocation and SIGWINCH forwarding through staged sudo."""

import fcntl
import json
import os
import select
import signal
import struct
import subprocess
import sys
import termios
import time


def child():
    def report(_signal=None, _frame=None):
        size = os.get_terminal_size(0)
        print(json.dumps([size.lines, size.columns]), flush=True)

    assert os.isatty(0), "command did not receive a PTY"
    signal.signal(signal.SIGWINCH, report)
    signal.alarm(20)
    report()
    while True:
        signal.pause()


def read_report(process, deadline):
    # The helper writes one short, flushed JSON record per window-size event.
    remaining = deadline - time.monotonic()
    assert remaining > 0, "PTY size report timed out"
    ready, _, _ = select.select([process.stdout], [], [], remaining)
    assert ready, "PTY size report timed out"
    line = process.stdout.readline()
    assert line, "PTY helper exited without reporting its terminal size"
    return json.loads(line)


def parent(sudo):
    terminal = os.open("/dev/tty", os.O_RDWR)
    original = fcntl.ioctl(terminal, termios.TIOCGWINSZ, bytes(8))
    rows, columns, _, _ = struct.unpack("HHHH", original)
    changed = [rows + 1 if rows < 65535 else rows - 1,
               columns + 2 if columns < 65534 else columns - 2]
    process = None
    try:
        process = subprocess.Popen(
            [sudo, "-n", "/usr/bin/python3", __file__, "--child"],
            stdout=subprocess.PIPE,
            bufsize=0,
        )
        initial = read_report(process, time.monotonic() + 10)
        assert initial == [rows, columns], ("initial PTY dimensions", initial, [rows, columns])
        fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", *changed, 0, 0))
        deadline = time.monotonic() + 10
        while read_report(process, deadline) != changed:
            pass
        print("PASS native PTY dimensions and window-change forwarding", flush=True)
    finally:
        fcntl.ioctl(terminal, termios.TIOCSWINSZ, original)
        os.close(terminal)
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process.stdout.close()


def job_control(sudo):
    terminal = os.open("/dev/tty", os.O_RDWR)
    foreground = os.tcgetpgrp(terminal)
    original_sigttou = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    process = None

    def prepare_child():
        # Give only this test command the foreground. The controller stays in
        # its own process group and can observe/resume the stopped sudo job.
        os.setpgrp()
        os.tcsetpgrp(terminal, os.getpgrp())
        os.set_inheritable(terminal, False)
        signal.signal(signal.SIGTTOU, signal.SIG_DFL)

    try:
        process = subprocess.Popen(
            [sudo, "-n", "/usr/bin/python3", __file__, "--job-child"],
            stdout=subprocess.PIPE, bufsize=0, pass_fds=(terminal,),
            preexec_fn=prepare_child,
        )
        assert read_report(process, time.monotonic() + 10) == "job-started"
        deadline = time.monotonic() + 10
        while True:
            pid, status = os.waitpid(process.pid, os.WNOHANG | os.WUNTRACED)
            if pid:
                assert os.WIFSTOPPED(status), ("sudo did not suspend with its command", status)
                break
            assert time.monotonic() < deadline, "sudo did not report command suspension"
            time.sleep(0.02)
        os.killpg(process.pid, signal.SIGCONT)
        assert read_report(process, time.monotonic() + 10) == "job-resumed"
        assert process.wait(timeout=5) == 0
    finally:
        os.tcsetpgrp(terminal, foreground)
        signal.signal(signal.SIGTTOU, original_sigttou)
        os.close(terminal)
        if process is not None:
            if process.poll() is None:
                os.kill(process.pid, signal.SIGCONT)
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process.stdout.close()
    print("PASS foreground job suspension and resumption", flush=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--child"]:
        child()
    elif sys.argv[1:] == ["--job-child"]:
        signal.alarm(20)
        print(json.dumps("job-started"), flush=True)
        os.kill(os.getpid(), signal.SIGSTOP)
        print(json.dumps("job-resumed"), flush=True)
    elif len(sys.argv) == 2:
        parent(sys.argv[1])
        job_control(sys.argv[1])
    else:
        raise SystemExit("usage: test-macos-pty.py STAGED_SUDO")
