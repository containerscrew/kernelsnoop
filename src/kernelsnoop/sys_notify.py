import logging
import notify2

from kernelsnoop.external_ip import get_public_ip_and_country


class Notifier:
    def __init__(self) -> None:
        self.log = logging.getLogger("kernelsnoop")

    def send_notification(self):
        self.log.info("Sending notification")
        notify2.init("IP geolocation")
        n = notify2.Notification(
            "Geolocation ip checker", get_public_ip_and_country(self.log), "./world-map"
        )
        n.show()
