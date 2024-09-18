import requests
from kernelsnoop.constants import Endpoints


def get_public_ip_and_country(log):
    try:
        ip = requests.get(Endpoints.IP_API.value).text.strip()
        country = requests.get(Endpoints.COUNTRY_API.value).text.strip()
        print(f"Connected to {ip} ({country})")
        return f"Connected to {ip} ({country})"
    except Exception as err:
        log.error(f"Error getting public IP: {err}")
