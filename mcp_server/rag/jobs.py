"""Minimal in-memory ingestion job tracker (spec section 6: "background jobs
may use FastAPI background tasks or an internal job service. Keep the
abstraction replaceable by a queue later.").

This is deliberately the simplest thing that satisfies the contract
(POST returns a job_id immediately, GET /jobs/{job_id} reports status) — a
dict-backed store, no persistence, no distributed workers. Swapping this for
Celery/RQ/an external queue later only requires replacing JobService's
internals; the public create()/get()/mark_* methods are the seam.

NON-DURABLE BY DESIGN (documented pilot limitation, not an oversight): all
job state lives in process memory and is lost on restart. Bounded retention
(max_jobs, below) prevents unbounded memory growth over a long-running
process -- once the cap is reached, the oldest terminal (SUCCEEDED/FAILED)
jobs are evicted first; PENDING/RUNNING jobs are never evicted while active.
"""

import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

JobStatus = Literal["PENDING", "RUNNING", "SUCCEEDED", "FAILED"]
_TERMINAL_STATUSES = frozenset({"SUCCEEDED", "FAILED"})

# Bounded retention default: enough for any realistic pilot ingestion volume
# without letting the in-memory dict grow forever in a long-running process.
DEFAULT_MAX_JOBS = 1000


@dataclass
class Job:
    job_id: str
    kind: str
    status: JobStatus = "PENDING"
    result: dict | None = None
    error: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class JobNotFoundError(KeyError):
    pass


class JobService:
    def __init__(self, *, max_jobs: int = DEFAULT_MAX_JOBS):
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self.max_jobs = max_jobs

    def create(self, kind: str) -> Job:
        self._evict_if_over_capacity()
        job = Job(job_id=f"JOB-{uuid.uuid4().hex[:12].upper()}", kind=kind)
        self._jobs[job.job_id] = job
        return job

    def _evict_if_over_capacity(self) -> None:
        """Evicts the oldest terminal (SUCCEEDED/FAILED) jobs first, oldest
        insertion order first, until under max_jobs -- never evicts a
        PENDING/RUNNING job just to make room (a still-active job is never
        silently forgotten; if every tracked job happens to be active, the
        dict is allowed to exceed max_jobs rather than lose in-flight state).
        """
        if len(self._jobs) < self.max_jobs:
            return
        for job_id, job in list(self._jobs.items()):
            if len(self._jobs) < self.max_jobs:
                break
            if job.status in _TERMINAL_STATUSES:
                del self._jobs[job_id]

    def get(self, job_id: str) -> Job:
        try:
            return self._jobs[job_id]
        except KeyError:
            raise JobNotFoundError(job_id) from None

    def mark_running(self, job_id: str) -> None:
        job = self.get(job_id)
        job.status = "RUNNING"
        job.updated_at = datetime.now(timezone.utc).isoformat()

    def mark_succeeded(self, job_id: str, result: dict) -> None:
        job = self.get(job_id)
        job.status = "SUCCEEDED"
        job.result = result
        job.updated_at = datetime.now(timezone.utc).isoformat()

    def mark_failed(self, job_id: str, error: str) -> None:
        job = self.get(job_id)
        job.status = "FAILED"
        job.error = error
        job.updated_at = datetime.now(timezone.utc).isoformat()


def _max_jobs_from_env() -> int:
    import os
    try:
        return int(os.environ.get("GENERATOR_MAX_JOBS", DEFAULT_MAX_JOBS))
    except ValueError:
        return DEFAULT_MAX_JOBS


# Process-wide singleton: ingestion jobs are tracked per running API process,
# matching the pilot scope (no persistence across restarts, replaceable later).
JOB_SERVICE = JobService(max_jobs=_max_jobs_from_env())
