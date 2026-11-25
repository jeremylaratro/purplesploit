"""Background capture-process manager -- the chassis extension for listener-based
validation executors (ADR-001 Decision 1, ADR-002 D4).

The eight synchronous executors (T1-1..8) run one tool at a time
(``ctx.runner.run(argv) -> RunResult``) and decide each step from a predicate over
that tool's output. The last three techniques (COERCION, NTLM-RELAY,
UNCONSTRAINED-DELEG) need a **capture process running concurrently with a
trigger**: a listener (ntlmrelayx / krbrelayx) is started, a coercion trigger is
fired synchronously, and the listener's accumulated output / loot is polled until
a success predicate holds or a bounded timeout elapses.

:class:`ProcessManager` is that abstraction -- deliberately small and injected,
exactly like :class:`~purplesploit.validation.executors.base.CommandRunner`, so a
listener executor is unit-testable with a scripted fake and never has to spawn a
real listener or touch a lab. :class:`SubprocessProcessManager` is the real
adapter (``Popen`` + a background reader thread for non-blocking incremental
reads). :func:`poll_for_capture` is the shared bounded poll loop every listener
executor uses.

Secrets rule (unchanged): a captured hash / relayed SAM / TGT / ccache is
presence-detected only, never read into the receipt. The poll predicates assert
on an **artifact** (a loot file, a ``.ccache``) or a non-secret listener marker,
never on secret content.

Python stdlib only; no LLM.
"""
from __future__ import annotations

import itertools
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Optional

from ..predicates import strip_ansi


@dataclass
class ProcHandle:
    """Opaque handle to a started background process.

    Runtime only -- it is never serialized into a receipt (it names no AD entity
    and carries no proof). The ``id`` is an internal token the manager uses to
    look the process up again on ``read``/``poll``/``stop``.
    """
    id: str


class ProcessManager(ABC):
    """Starts a background process and reads its output incrementally.

    Injected (``ExecutorContext.proc_manager``) so listener executors are
    testable with a scripted fake. All four methods take/return only strings and
    a handle, so a fake needs no real subprocess.
    """

    @abstractmethod
    def start(self, argv: list[str], *, env: Optional[dict[str, str]] = None,
              cwd: Optional[str] = None) -> ProcHandle:
        """Spawn ``argv`` **non-blocking** and return a handle. Never waits."""

    @abstractmethod
    def read(self, handle: ProcHandle) -> str:
        """Output accumulated so far (ANSI-stripped). Non-blocking; may be empty."""

    @abstractmethod
    def poll(self, handle: ProcHandle) -> Optional[int]:
        """The process returncode, or ``None`` if it is still running."""

    @abstractmethod
    def stop(self, handle: ProcHandle) -> str:
        """Terminate + reap the process and return its final accumulated output."""


# ------------------------------------------------------------------ real adapter
class _BgProc:
    """One backgrounded ``Popen`` plus a reader thread accumulating its output.

    stdout and stderr are merged (``stderr=STDOUT``) so a single stream carries
    everything a marker/predicate might match. A daemon thread drains the pipe
    into a buffer under a lock, so :meth:`read` never blocks on the child.
    """

    def __init__(self, proc: "subprocess.Popen[str]"):
        self.proc = proc
        self._buf: list[str] = []
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        stream = self.proc.stdout
        if stream is None:
            return
        try:
            for line in iter(stream.readline, ""):
                with self._lock:
                    self._buf.append(line)
        except (OSError, ValueError):
            pass  # pipe closed under us on terminate/reap -- stop draining

    def read(self) -> str:
        with self._lock:
            return strip_ansi("".join(self._buf))

    def poll(self) -> Optional[int]:
        return self.proc.poll()

    def stop(self) -> str:
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
            except OSError:
                pass
        self._thread.join(timeout=5)
        try:
            if self.proc.stdout is not None:
                self.proc.stdout.close()
        except OSError:
            pass
        return self.read()


class SubprocessProcessManager(ProcessManager):
    """Real adapter: ``Popen`` with a background reader thread.

    Runs where the listener tooling (ntlmrelayx, krbrelayx) is on PATH (the Kali
    exec env -- claude-mem #66146). A failed spawn (``OSError`` / tool absent)
    propagates from :meth:`start`; each listener executor wraps the ``start`` call
    and records an honest failed ``start_listener`` step rather than crashing, and
    never fabricates capture.
    """

    def __init__(self, base_env: Optional[dict] = None):
        self.base_env = base_env
        self._procs: dict[str, _BgProc] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def start(self, argv, *, env=None, cwd=None) -> ProcHandle:
        import os
        merged = dict(os.environ if self.base_env is None else self.base_env)
        if env:
            merged.update({k: v for k, v in env.items() if v is not None})
            for k, v in env.items():
                if v is None:
                    merged.pop(k, None)  # honor an explicit unset (e.g. KRB5CCNAME)
        proc = subprocess.Popen(
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=cwd, env=merged,
        )
        with self._lock:
            handle = ProcHandle(id=f"pm{next(self._ids)}")
            self._procs[handle.id] = _BgProc(proc)
        return handle

    def read(self, handle) -> str:
        bg = self._procs.get(handle.id)
        return bg.read() if bg is not None else ""

    def poll(self, handle) -> Optional[int]:
        bg = self._procs.get(handle.id)
        return bg.poll() if bg is not None else None

    def stop(self, handle) -> str:
        bg = self._procs.get(handle.id)
        if bg is None:
            return ""
        out = bg.stop()
        self._procs.pop(handle.id, None)
        return out


# ------------------------------------------------------------------ shared poll loop
def poll_for_capture(
    pm: ProcessManager, handle: ProcHandle, *,
    success: Callable[[str], bool],
    interval_s: float,
    timeout_s: float,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[str, bool]:
    """Bounded poll loop shared by every listener executor.

    After the listener is started and the trigger fired, poll the listener's
    accumulated output (``pm.read``) and test ``success`` until it holds, the
    listener process exits without a capture (``pm.poll`` returns a code), or
    ``timeout_s`` elapses -- whichever comes first. ``success`` is a POSITIVE
    predicate (an artifact exists / a non-secret marker is present), never
    "no error seen", so a timeout or a dead listener is an honest *no capture*
    (``captured=False``), never a proof.

    Returns ``(latest_output, captured)``. Does NOT call ``stop`` -- the caller
    stops the listener so it can also record the final output. ``clock``/``sleep``
    are injectable so a test runs with no wall-clock sleep (``interval_s`` is read
    from ``config.poll_interval_s`` and is tiny); the timeout branch fires
    immediately when ``timeout_s`` is 0.
    """
    start = clock()
    while True:
        output = pm.read(handle)
        if success(output):
            return output, True
        rc = pm.poll(handle)
        if rc is not None:
            return output, False          # listener exited without a capture
        if clock() - start >= timeout_s:
            return output, False          # bounded timeout -> honest no-capture
        sleep(interval_s)
