import notify2
import requests
import schedule
import daemon
import tomllib as toml
import json
from dataclasses import dataclass
from dacite import from_dict

ip_api = "https://ifconfig.co/ip"
country_api = "https://ifconfig.co/country"

with open("config.toml", "rb") as f:
    data = toml.load(f)


# json_data = json.dumps(data, indent=2)

@dataclass
class DaemonSettings:
    enabled = bool

@dataclass
class Daemon:
    settings: DaemonSettings


user = from_dict(data_class=Daemon, data=data)


print(data.settings.enabled)
# json_obj = json.loads(json_data)
# test = Daemon(**json_obj)
# print(test.daemon.enabled)


# def get_public_ip_and_country():
#     try:
#         ip = requests.get(ip_api).text.strip()
#         country = requests.get(country_api).text.strip()
#         print(f"Connected to {ip} ({country})")
#         return f"Connected to {ip} ({country})"
#     except Exception:
#         return "Error"


# def main():
#     notify2.init("IP geolocation")
#     n = notify2.Notification("Geolocation ip checker", get_public_ip_and_country(), "./world-map")
#     n.show()


# if __name__ == "__main__":
#     with daemon.DaemonContext(stdout=open("/tmp/stdout.log", "w+"), stderr=open("/tmp/stderr.log", "w+")):
#         print("Starting the daemon")
#         # The first time the program is executed, execute the first notification
#         main()
#         schedule.every(5).minutes.do(main)  # Run the main function every 5 minutes
#         while True:
#             schedule.run_pending()