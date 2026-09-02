import logging
from pathlib import Path

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "pentaia.log"


def setup_logging() -> None:
    LOG_DIR.mkdir(exist_ok=True)

    root_logger = logging.getLogger()

    for handler in root_logger.handlers:
        if isinstance(handler, logging.FileHandler):
            try:
                if Path(handler.baseFilename).resolve() == LOG_FILE.resolve():
                    return
            except AttributeError:
                continue

    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )
    )

    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
