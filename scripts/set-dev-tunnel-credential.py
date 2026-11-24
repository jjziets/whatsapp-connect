#!/usr/bin/env python3
"""C-008/C-009 owner-directed development plaintext exception; no secret export."""
import ctypes
import errno
import os
from pathlib import Path
import secrets
import resource
import stat
import sys
import termios


class UnsafeDestination(Exception):
    pass


def no_acl(fd):
    # macOS extended ACL inspection uses the opened object, never a second path.
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.acl_get_fd_np.restype = ctypes.c_void_p
    libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    libc.acl_get_entry.restype = ctypes.c_int
    libc.acl_free.argtypes = [ctypes.c_void_p]
    libc.acl_valid.argtypes = [ctypes.c_void_p]
    libc.acl_valid.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = libc.acl_get_fd_np(fd, 0x100)  # ACL_TYPE_EXTENDED
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:  # Darwin: no extended ACL
            return
        raise UnsafeDestination()
    try:
        if libc.acl_valid(acl) != 0:
            raise UnsafeDestination()
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = libc.acl_get_entry(acl, 0, ctypes.byref(entry))  # ACL_FIRST_ENTRY
        if result != -1 or ctypes.get_errno() != errno.EINVAL:
            raise UnsafeDestination()
    finally:
        libc.acl_free(acl)


def private_object(fd, directory=False):
    info = os.fstat(fd)
    expected = 0o700 if directory else 0o600
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not kind or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != expected:
        raise UnsafeDestination()
    if not directory and info.st_nlink != 1:
        raise UnsafeDestination()
    no_acl(fd)


def read_masked():
    # Always read the controlling terminal, with no echoed-input fallback.
    fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    try:
        if not os.isatty(fd) or os.tcgetpgrp(fd) != os.getpgrp():
            raise OSError()
        original = termios.tcgetattr(fd)
        hidden = termios.tcgetattr(fd)
        hidden[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON)
        hidden[6][termios.VMIN] = 1
        hidden[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
        try:
            os.write(fd, b'Runtime key (hidden): ')
            value = bytearray()
            while True:
                item = os.read(fd, 1)
                if not item or item == b'\x04':
                    raise EOFError()
                if item in (b'\r', b'\n'):
                    break
                if item in (b'\x7f', b'\x08'):
                    if value:
                        value.pop()
                    continue
                value.extend(item)
                if len(value) > 4096:
                    raise ValueError()
            if not value or any(byte < 0x21 or byte > 0x7e for byte in value):
                raise ValueError()
            return value
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, original)
            os.write(fd, b'\n')
    finally:
        os.close(fd)


def main():
    if len(sys.argv) != 1 or sys.platform != 'darwin':
        print('invalid-configuration', file=sys.stderr)
        return 64
    os.umask(0o077)
    root = Path(__file__).resolve().parent.parent
    repo_fd = directory_fd = temporary_fd = None
    temporary = None
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        repo_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.mkdir('.local-credentials', 0o700, dir_fd=repo_fd)
        except FileExistsError:
            pass
        directory_fd = os.open('.local-credentials', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=repo_fd)
        private_object(directory_fd, directory=True)
        destination = 'openai-tunnel-runtime.key'
        try:
            old = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        else:
            try:
                private_object(old)
            finally:
                os.close(old)
        value = read_masked()
        temporary = '.runtime-' + secrets.token_hex(16)
        temporary_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
        private_object(temporary_fd)
        view = memoryview(value)
        while view:
            written = os.write(temporary_fd, view)
            if written <= 0:
                raise OSError()
            view = view[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        os.replace(temporary, destination, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temporary = None
        os.fsync(directory_fd)
        print('development-credential-written')
        return 0
    except (EOFError, KeyboardInterrupt):
        print('credential-entry-canceled', file=sys.stderr)
        return 130
    except ValueError:
        print('invalid-credential', file=sys.stderr)
        return 78
    except Exception:  # Fixed category only; never export underlying input/OS errors.
        print('credential-file-unavailable', file=sys.stderr)
        return 77
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary is not None and directory_fd is not None:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except OSError:
                pass
        if directory_fd is not None:
            os.close(directory_fd)
        if repo_fd is not None:
            os.close(repo_fd)


if __name__ == '__main__':
    sys.exit(main())
