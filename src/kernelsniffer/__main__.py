import notify2
import schedule
import daemon
import tomllib as toml
from dataclasses import dataclass
from importlib.metadata import version
from dacite import from_dict
from kernelsniffer.external_ip import get_public_ip_and_country

app_version = version("kernelsniffer")

# Endpoints
ip_api = "https://ifconfig.co/ip"
country_api = "https://ifconfig.co/country"

# Load config.toml
with open("config.toml", "rb") as f:
    data = toml.load(f)

# Definir dataclass para el mapeo
@dataclass
class DaemonSettings:
    enabled: bool

@dataclass
class Config:
    daemon: DaemonSettings

# Convet dict to dataclass structure
# Now, you can access all the values
config = from_dict(data_class=Config, data=data)


def notify():
    notify2.init("IP geolocation")
    n = notify2.Notification("Geolocation ip checker", get_public_ip_and_country(), "./world-map")
    n.show()


def main():
    with daemon.DaemonContext(stdout=open("/tmp/stdout.log", "w+"), stderr=open("/tmp/stderr.log", "w+")):
        print("Starting the daemon")
        # The first time the program is executed, execute the first notification
        notify()
        schedule.every(5).minutes.do(notify)  # Run the main function every 5 minutes
        while True:
            schedule.run_pending()


if __name__ == "__main__":
    main()