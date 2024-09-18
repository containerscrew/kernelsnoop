from enum import Enum


class LoggingLevel(str, Enum):
    NOTSET = "NOTSET"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Endpoints(Enum):
    IP_API = "https://ifconfig.co/ip"
    COUNTRY_API = "https://ifconfig.co/country"
