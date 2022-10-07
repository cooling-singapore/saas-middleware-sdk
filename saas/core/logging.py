import logging
import time

from logging.handlers import RotatingFileHandler
from threading import Lock


class Logging:
    _lock: Lock = Lock()
    _default_format: str = '%(asctime)s.%(msecs)03d [%(levelname)s] [%(name)s] %(message)s'
    _default_datefmt: str = '%Y-%m-%d %H:%M:%S'

    @classmethod
    def initialise(cls, level: int = logging.INFO, log_path: str = None, console_log_enabled: bool = True,
                   custom_format: str = None, custom_datefmt: str = None,
                   max_bytes: int = 1*1024*1024, backup_count: int = 10) -> None:
        with Logging._lock:
            # set formatting and use GMT/UTC timezone
            formatter = logging.Formatter(
                fmt=custom_format if custom_format else Logging._default_format,
                datefmt=custom_datefmt if custom_datefmt else Logging._default_datefmt
            )
            formatter.converter = time.gmtime

            # set default log level
            root_logger = logging.getLogger()
            root_logger.setLevel(level)

            # remove all handlers -> we will create our own
            cls.remove_all_handlers()

            # do we have a default log path?
            if log_path:
                file_handler = RotatingFileHandler(log_path, maxBytes=max_bytes, backupCount=backup_count)
                file_handler.setFormatter(formatter)
                root_logger.addHandler(file_handler)

            # do we have console logging enabled?
            if console_log_enabled:
                console_handler = logging.StreamHandler()
                console_handler.setFormatter(formatter)
                root_logger.addHandler(console_handler)

    @classmethod
    def get(cls, name: str, level: int = None, custom_log_path: str = None) -> logging.Logger:
        logger = logging.getLogger(name)

        # do we have a custom level?
        if level:
            logger.setLevel(level)

        # do we have a custom log path?
        if custom_log_path:
            file_handler = logging.FileHandler(custom_log_path)
            file_handler.setFormatter(logging.Formatter(Logging._default_format))
            logger.addHandler(file_handler)

        return logger

    @staticmethod
    def remove_all_handlers():
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            # Flush and close any open streams
            handler.flush()
            handler.close()
            root_logger.removeHandler(handler)
