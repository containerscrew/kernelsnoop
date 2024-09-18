import tomllib as toml
from dataclasses import dataclass
from dacite import from_dict


@dataclass
class DaemonSettings:
    enabled: bool
    stdout_path: str
    stdeer_path: str
    log_level: str
    notifications_enabled: bool


@dataclass
class Config:
    daemon: DaemonSettings


def load_toml():
    """
    Load the config file.
    """
    with open("config.toml", "rb") as f:
        data = toml.load(f)
    return data


def load_config():
    """
    Map the config file to a dataclass.
    """
    config = from_dict(data_class=Config, data=load_toml())

    return config
