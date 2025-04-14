import logging
import os
import time

logger_levels: dict = {
    "DEBUG": 0,
    "INFO": 10,
    "ERROR": 20,
    "CRITICAL": 30
}


class Logger():

    _level: int

    def __init__(self, level: int) -> None:
        self._level = level

    def log(self, level: int, message: str) -> None:
        return


class FileLogger(Logger):

    def __init__(self, level: int, log_path: str) -> None:
        self._level = level

        if not os.path.exists(log_path):
            os.makedirs(log_path, 0o777)

        logging.basicConfig(
            filename=log_path + "/log.txt", format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
        )

        logging.getLogger(__name__)

    def log(self, level: int, message: str) -> None:

        if (level < self._level):
            return

        match (level):
            case 0:
                logging.debug(message)
            case 10:
                logging.info(message)
            case 20:
                logging.error(message)
            case 30:
                logging.critical(message)


class ConsoleLogger(Logger):

    __start_time: float

    def __init__(self, level: int) -> None:
        self._level = level
        self.__start_time = time.time()

    def log(self, level: int, message: str) -> None:

        if (level < self._level):
            return

        current_time = time.time() - self.__start_time

        match (level):
            case 0:
                print(f"[{current_time:9.4f}][DEBUG   ] " + message)
            case 10:
                print(f"[{current_time:9.4f}][INFO    ] " + message)
            case 20:
                print(f"[{current_time:9.4f}][ERROR   ] " + message)
            case 30:
                print(f"[{current_time:9.4f}][CRITICAL] " + message)


loggers: list[Logger] = []


def initLogging(level: int, log_path: str):

    loggers.append(ConsoleLogger(level))
    loggers.append(FileLogger(level, log_path))

    log(10, "Initiated logger!")


def log(level: int, message: str):
    for logger in loggers:
        logger.log(level, message)
