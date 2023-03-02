import logging
import logging.handlers
import os
import sys

class SingleFilter(logging.Filter):
    def __init__(self, level, flag = False):
        self.__level = level
        self.__flag = flag
    def filter(self, record):
        if self.__flag:
            return record.levelno <= self.__level
        else:
            return False

class PyLog(object):
    loggers = set()
    def __init__(self, name, format="%(asctime)s | %(levelname)s | %(message)s ", level=logging.INFO, store=True, consolePrint=True):
        self.name = name
        self.format = format
        self.level = level
        self.store = store
        self.consolePrint = consolePrint


        self.console_formatter = logging.Formatter(self.format)

        
        self.console_handler = logging.StreamHandler(sys.stdout)
        self.console_handler.addFilter(SingleFilter(self.level, consolePrint))
        self.console_handler.setFormatter(self.console_formatter)

        self.file_handler =  logging.FileHandler(f"./logs/{name}.log", mode="w", encoding="utf-8")
        self.file_handler.addFilter(SingleFilter(logging.INFO, store))
        self.file_handler.setFormatter(self.console_formatter)

        self.file_handler2 = logging.FileHandler(f"./logs/error.log", mode="w", encoding="utf-8")
        self.file_handler2.addFilter(SingleFilter(logging.ERROR, store))
        self.file_handler2.setFormatter(self.console_formatter)

        self.file_handler3 = logging.FileHandler(f"./logs/debug.log", mode="w", encoding="utf-8")
        self.file_handler3.addFilter(SingleFilter(logging.DEBUG, store))
        self.file_handler3.setFormatter(self.console_formatter)


        self.logger = logging.getLogger(name)

        if name not in self.loggers:
            self.loggers.add(name)
            self.logger.setLevel(self.level)
            self.logger.addHandler(self.console_handler)
            self.logger.addHandler(self.file_handler)
            self.logger.addHandler(self.file_handler2)
            self.logger.addHandler(self.file_handler3)

    def info(self, msg, extra=None):
        self.logger.info(msg, extra=extra)

    def error(self, msg, extra=None):
        self.logger.error(msg, extra=extra)

    def debug(self, msg, extra=None):
        self.logger.debug(msg, extra=extra)

    def warn(self, msg, extra=None):
        self.logger.warn(msg, extra=extra)


