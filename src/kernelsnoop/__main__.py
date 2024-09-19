import daemon
from kernelsnoop.config import load_config
from kernelsnoop.eBPF.hello_world import hello_world_ebpf
from kernelsnoop.logger import init_logger
from kernelsnoop.sys_notify import Notifier
from kernelsnoop.args import parse_args


def main() -> None:
    """ """

    # Parse command line arguments
    parse_args()

    # Read and load config.toml configuration file
    config = load_config()

    # Initialize logger
    log = init_logger(config.daemon.log_level)

    # Initialize Notifier
    notifier = Notifier()

    # Start the daemon if enabled
    if config.daemon.enabled:
        try:
            with daemon.DaemonContext(
                stdout=open(config.daemon.stdout_path, "a+"),
                stderr=open(config.daemon.stdeer_path, "a+"),
            ):
                log.info("Daemon started")
                # schedule.every(1).minutes.do(notifier.send_notification)
                while True:
                    hello_world_ebpf()
                    # schedule.run_pending()
        except Exception as exc:
            log.error(f"An error occurred: {exc}")
    else:
        notifier.send_notification()

    print("Starting kernelsoop")


if __name__ == "__main__":
    main()
