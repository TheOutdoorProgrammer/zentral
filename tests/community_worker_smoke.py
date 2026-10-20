"""Exercise real control and task queues against a current RabbitMQ broker."""
import os
from pathlib import Path
import subprocess
import sys
import time


root = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root / "server"), str(root)]
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "server.settings")

import django  # noqa: E402
django.setup()

from django.core.management import call_command  # noqa: E402
from server.celery import app  # noqa: E402


def main():
    call_command("migrate", interactive=False, verbosity=0)
    hostname = "community-smoke@localhost"
    worker = subprocess.Popen(
        [sys.executable, "-m", "celery", "-A", "server", "worker",
         "--hostname", hostname, "--queues", "community-smoke", "--concurrency", "1"],
        cwd=root / "server", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if worker.poll() is not None:
                raise RuntimeError("Worker exited before accepting control requests")
            replies = app.control.ping(destination=[hostname], timeout=1)
            if any(reply.get(hostname, {}).get("ok") == "pong" for reply in replies):
                break
            time.sleep(1)
        else:
            raise RuntimeError("Worker did not answer control requests")
        result = app.send_task("celery.accumulate", args=[["community-smoke"]], queue="community-smoke")
        if result.get(timeout=30) != ["community-smoke"]:
            raise RuntimeError("Worker returned an unexpected task result")
        result.forget()
        print("RabbitMQ control reply and persisted Celery task result verified")
    finally:
        worker.terminate()
        try:
            worker.wait(timeout=15)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait(timeout=5)


if __name__ == "__main__":
    main()
