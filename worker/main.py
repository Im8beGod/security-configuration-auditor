import logging
import signal

from app.jobs.runner import create_worker_runtime


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    runtime = create_worker_runtime()

    def request_shutdown(_signum, _frame) -> None:
        runtime.request_shutdown()

    signal.signal(signal.SIGTERM, request_shutdown)
    try:
        runtime.run_forever()
    except KeyboardInterrupt:
        runtime.request_shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
