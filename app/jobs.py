"""Background jobs: checks run as asyncio tasks, the page polls their progress."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections.abc import Awaitable, Callable

from .db import Database

log = logging.getLogger("vpsc.jobs")

Progress = Callable[[str], Awaitable[None]]
Work = Callable[[Progress], Awaitable[dict]]


class JobManager:
    def __init__(self, db: Database, limit: int = 3):
        self.db = db
        self.sem = asyncio.Semaphore(limit)
        self.tasks: set[asyncio.Task] = set()

    async def recover(self) -> None:
        await self.db.execute(
            "UPDATE jobs SET status = 'interrupted', finished_at = ? WHERE status IN ('running', 'queued')",
            (time.time(),),
        )

    async def start(self, kind: str, mode: str, target: str, public_inputs: dict, work: Work) -> str:
        job_id = secrets.token_urlsafe(9)
        await self.db.create_job(job_id, kind, mode, target, public_inputs)
        task = asyncio.create_task(self._run(job_id, work))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return job_id

    async def _run(self, job_id: str, work: Work) -> None:
        async with self.sem:
            async def progress(step: str) -> None:
                await self.db.update_job(job_id, progress=step)

            try:
                result = await work(progress)
                status = "done"
            except Exception:  # never let a job crash the app; details go to the journal only
                log.exception("job %s failed", job_id)
                result = {"error": "internal_error"}
                status = "failed"
            await self.db.update_job(job_id, status=status, result=result, finished_at=time.time(), progress="")
