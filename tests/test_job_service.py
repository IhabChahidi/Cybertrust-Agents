"""Bounded retention for the in-memory ingestion job tracker (spec section 7:
"prevent unbounded memory growth", "use bounded retention or cleanup").
Covers mcp_server/rag/jobs.py's JobService eviction behavior.
"""

import pytest

from mcp_server.rag.jobs import JobNotFoundError, JobService

pytestmark = pytest.mark.unit


def test_service_stays_within_max_jobs_once_jobs_complete():
    jobs = JobService(max_jobs=5)
    for _ in range(10):
        job = jobs.create(kind="ingestion:evidence")
        jobs.mark_succeeded(job.job_id, {"ingested": 1})
    assert len(jobs._jobs) <= 5


def test_oldest_terminal_jobs_are_evicted_first():
    jobs = JobService(max_jobs=3)
    first = jobs.create(kind="ingestion:evidence")
    jobs.mark_succeeded(first.job_id, {})
    second = jobs.create(kind="ingestion:evidence")
    jobs.mark_succeeded(second.job_id, {})
    third = jobs.create(kind="ingestion:evidence")
    jobs.mark_succeeded(third.job_id, {})

    # This 4th job pushes the count to 4, over the cap of 3 -- the oldest
    # terminal job (`first`) must be evicted, not `second`/`third`.
    fourth = jobs.create(kind="ingestion:evidence")

    with pytest.raises(JobNotFoundError):
        jobs.get(first.job_id)
    assert jobs.get(second.job_id) is not None
    assert jobs.get(third.job_id) is not None
    assert jobs.get(fourth.job_id) is not None


def test_active_pending_or_running_jobs_are_never_evicted():
    jobs = JobService(max_jobs=2)
    still_running = jobs.create(kind="ingestion:evidence")
    jobs.mark_running(still_running.job_id)

    # Both new jobs complete instantly; capacity is exceeded, but the
    # still-RUNNING job must survive regardless -- eviction only ever
    # targets SUCCEEDED/FAILED jobs.
    for _ in range(5):
        job = jobs.create(kind="ingestion:evidence")
        jobs.mark_succeeded(job.job_id, {})

    assert jobs.get(still_running.job_id).status == "RUNNING"


def test_get_unknown_job_raises_job_not_found_error():
    jobs = JobService()
    with pytest.raises(JobNotFoundError):
        jobs.get("JOB-DOES-NOT-EXIST")
