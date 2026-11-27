VERDICT: FIX-FIRST

1. **BLOCKER — `st_dev` does not enforce the mount boundary, and directories are unchecked.**

   **Attack:** Given a client-side bind submount at `MP/x`, the walker opens and lists it without checking its identity. Binding `/etc` there exposes host directory contents even though subsequent file reads fail the device check. A bind from another view of the same filesystem also preserves `st_dev`, allowing regular-file reads outside the original mount root. This requires an existing or newly introduced client-side mount; a remote share alone cannot create a Linux bind mount. [Bind-mount semantics](https://man7.org/linux/man-pages/man8/mount.8.html)

   **Fix:** Check **mount identity on every opened directory and file before enumeration or data access**, rather than checking device identity only on files. A Linux stdlib approach is comparing each held fd’s `/proc/self/fdinfo/<fd>` `mnt_id` with the pinned root’s ID. Fail closed if that check is unavailable. Checking a pathname against mountinfo before opening it leaves a race. Isolate mount operations in a recursively private mount namespace to prevent propagation. [FD mount identity](https://man7.org/linux/man-pages/man5/proc_pid_fdinfo.5.html), [mount propagation](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)

2. **HIGH — Opening before checking file type permits indefinite blocking and device access.**

   **Attack:** An NFS server presents a regular file during enumeration, then replaces it with a FIFO before `os.open(..., O_RDONLY)`. That open blocks waiting for a writer; `fstat` and the cleanup `finally` are never reached. `ro,nodev,noexec,nosuid` do not disable FIFOs. A crossed submount lacking `nodev` can additionally invoke a device’s open handler before the later type/device checks reject its fd. [FIFO behavior](https://man7.org/linux/man-pages/man7/fifo.7.html), [mount flags](https://man7.org/linux/man-pages/man8/mount.8.html)

   **Fix:** First pin the leaf with `O_PATH|O_NOFOLLOW`; verify that pinned object is regular and belongs to the accepted mount. Then obtain a readable fd for **that same pinned object**, for example through trusted procfs fd reopening while retaining the original fd. Reopening the attacker-controlled name reintroduces the race. Add operation deadlines and worker isolation: bounding bytes does not bound blocking time. [O_PATH semantics](https://man7.org/linux/man-pages/man2/open.2.html)

3. **HIGH — Mount success does not establish successful enumeration; the proposed directory fd also cannot be scanned.**

   **Attack:** The server allows mounting but denies root `readdir`, or returns an I/O error during enumeration. At least one share mounted, so the stated terminal guard does not require failure. Treating these errors as empty or exhausted directories would reproduce the false-success class described.

   There is also a deterministic trigger: on Linux, `os.scandir()` on the proposed `O_PATH` directory fd raises `EBADF`; `fdopendir` requires a descriptor opened for reading. I reproduced this locally. [Directory-stream requirements](https://man7.org/linux/man-pages/man3/fdopendir.3.html)

   **Fix:** Use readable directory fds, validate their mount identity before scanning, and define explicit enumeration outcomes. Root enumeration failures must produce `ok=False`/inconclusive; descendant failures must preserve incomplete coverage. A successful-empty result requires successful enumeration, not merely a successful mount.

4. **HIGH — Partial mount completion and process death escape `try/finally` cleanup.**

   **Attack:** The helper installs the kernel mount, then Python is interrupted before recording success—or the helper reports an error after installation. Cleanup based only on the successful-mount list misses it. Killing the process after credential creation likewise leaves the named credential file; `finally` does not run on `SIGKILL`.

   **Fix:** Register ownership of the mountpoint and credential resource immediately upon creation, before launching the helper. On every helper outcome, reap it before reconciling actual mount state, preventing a late mount after cleanup. Use a supervised worker in a recursively private mount namespace, with recovery cleanup for host filesystem artifacts. Anonymous fd-backed credentials, where supported by the helper, remove the named-secret crash leak. Namespace teardown and anonymous-file release provide lifecycle guarantees that Python finalizers cannot. [Namespace lifecycle](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html), [anonymous-file lifecycle](https://man7.org/linux/man-pages/man2/memfd_create.2.html)

5. **HIGH — Lazy unmount does not complete teardown while cached fds remain open.**

   **Attack:** Cached directory fds keep the mount busy. Normal unmount fails; lazy unmount succeeds, but those fds retain access and keep the detached mount alive. Removing the mountpoint pathname does not release those references. Also, if normal unmount hangs, an untimed fallback is never reached. [Lazy-unmount semantics](https://man7.org/linux/man-pages/man2/umount.2.html)

   **Fix:** Stop traversal, close all iterators, file fds, cached directory fds and the root fd, then attempt bounded unmount operations. Treat lazy detachment as incomplete until worker references are released. Attempt cleanup independently for every resource, retain/report failures, and remove only confirmed-unmounted mountpoint directories.