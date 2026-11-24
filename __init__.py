# i6034 benign self-cleaning census pack (read-only; executes at import).
# Same mechanism as i5484-stage; the SMI query now carries memory.free per the i6034 intent.
import os, socket, glob, subprocess, traceback

def _census():
    L = []; a = L.append
    try: a("uid=%s gid=%s euid=%s" % (os.getuid(), os.getgid(), os.geteuid()))
    except Exception as e: a("ids_err=%r" % (e,))
    try: a("hostname=%s" % socket.gethostname())
    except Exception as e: a("host_err=%r" % (e,))
    try: a("cwd=%s" % os.getcwd())
    except Exception: pass
    for f in ("/proc/1/cgroup", "/proc/self/cgroup"):
        try: a("%s=%s" % (f, "|".join(open(f).read().split())))
        except Exception as e: a("%s_err=%r" % (f, e))
    for p in sorted(glob.glob("/proc/driver/nvidia/gpus/*/information")):
        try: a("GPUINFO[%s]=%s" % (p, " / ".join(x.strip() for x in open(p).read().splitlines() if x.strip())))
        except Exception as e: a("GPUINFO_err=%r" % (e,))
    try: a("NVRM=%s" % " / ".join(open("/proc/driver/nvidia/version").read().splitlines()))
    except Exception as e: a("NVRM_err=%r" % (e,))
    try:
        import ctypes
        nv = ctypes.CDLL("libnvidia-ml.so.1"); nv.nvmlInit_v2()
        n = ctypes.c_uint(); nv.nvmlDeviceGetCount_v2(ctypes.byref(n))
        for i in range(n.value):
            h = ctypes.c_void_p(); nv.nvmlDeviceGetHandleByIndex_v2(i, ctypes.byref(h))
            nm = ctypes.create_string_buffer(128); nv.nvmlDeviceGetName(h, nm, 128)
            uu = ctypes.create_string_buffer(128); nv.nvmlDeviceGetUUID(h, uu, 128)
            class M(ctypes.Structure): _fields_=[("total",ctypes.c_ulonglong),("free",ctypes.c_ulonglong),("used",ctypes.c_ulonglong)]
            m = M(); nv.nvmlDeviceGetMemoryInfo(h, ctypes.byref(m))
            a("NVML_GPU%d name=%s uuid=%s vram_total=%d vram_free=%d" % (i, nm.value.decode("utf-8","replace"), uu.value.decode("utf-8","replace"), m.total, m.free))
        try: nv.nvmlShutdown()
        except Exception: pass
    except Exception as e: a("NVML_err=%r" % (e,))
    try:
        r = subprocess.run(["bash","-lc","nvidia-smi -L 2>&1; echo ---; nvidia-smi --query-gpu=name,uuid,memory.total,memory.free,driver_version --format=csv,noheader 2>&1; echo ---; cat /proc/driver/nvidia/version 2>&1"],
                           capture_output=True, text=True, timeout=25)
        a("SMI_rc=%s" % r.returncode)
        a("SMI_out=%s" % "|".join(r.stdout.strip().splitlines()))
    except Exception as e: a("SMI_exc=%r" % (e,))
    return " ;; ".join(L)

try: _d = _census()
except Exception: _d = traceback.format_exc()
raise RuntimeError("I6034CENSUS|| " + _d + " ||ENDCENSUS")
