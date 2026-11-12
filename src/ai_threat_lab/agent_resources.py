"""Native limits for the trusted offline agent worker."""

import sys
from contextlib import contextmanager

MEMORY_BYTES = 512 * 1024 * 1024
OPEN_FILES = 128


def apply_worker_limits():
    if sys.platform == "linux":
        import resource

        for name, maximum in ((resource.RLIMIT_AS, MEMORY_BYTES),
                              (resource.RLIMIT_NOFILE, OPEN_FILES)):
            soft, hard = resource.getrlimit(name)
            limit = min(value for value in (maximum, soft, hard)
                        if value != resource.RLIM_INFINITY)
            resource.setrlimit(name, (limit, limit))


@contextmanager
def supervise_windows(process):
    """Assign before sending input. Close the job to terminate remaining members."""
    if sys.platform != "win32":
        yield
        return

    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
            ("flags", wintypes.DWORD), ("min_working_set", ctypes.c_size_t),
            ("max_working_set", ctypes.c_size_t), ("processes", wintypes.DWORD),
            ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
            ("scheduling", wintypes.DWORD),
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("basic", BasicLimits), ("io", ctypes.c_ulonglong * 6),
            ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
            ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = (
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    )
    kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        limits = ExtendedLimits()
        # Active process limit, aggregate committed memory, kill on last handle close.
        limits.basic.flags = 0x0008 | 0x0200 | 0x2000
        limits.basic.processes = 1
        limits.job_memory = MEMORY_BYTES
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.AssignProcessToJobObject(job, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        yield
    finally:
        kernel.CloseHandle(job)
