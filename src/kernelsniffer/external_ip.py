import requests
from kernelsniffer.constants import Endpoints


def get_public_ip_and_country():
    try:
        ip = requests.get(Endpoints.IP_API).text.strip()
        country = requests.get(Endpoints.COUNTRY_API).text.strip()
        print(f"Connected to {ip} ({country})")
        return f"Connected to {ip} ({country})"
    except Exception:
        return "Error"
