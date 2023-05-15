#!/usr/bin/env python3
from fabric import Connection
from utils import setup_config
from pprint import pformat
from time import sleep
import coloredlogs, logging
import socket
import transfers
import pyshark 

logger = logging.getLogger(__name__)
level = 'INFO'# if verbose else 'INFO'  

coloredlogs.install(fmt = "%(levelname)s.%(name)s - %(message)s:", level=level, logger=logger)

class Sniffer:
    def __init__(self, config_file, auto_start = True):
        
        conn_cfg, self.tcpdump_cfg, verbose = setup_config(config_file)

        logger.debug("Loaded config:\n" + pformat(self.tcpdump_cfg))
        
        level = 'DEBUG' if verbose else 'INFO'  

        coloredlogs.install(fmt = "%(levelname)s.%(name)s - %(message)s:", level=level, logger=logger)

        self.connection = Connection(
            host = conn_cfg['vulnbox_ip'], #"172.30.240.1",
            user = conn_cfg['user'], #"root",
            port = conn_cfg['vulnbox_port'], # 3030,
            connect_kwargs={
                "key_filename": conn_cfg["ssh_key"] #"./vulnbox_key",
            },
            connect_timeout=5
        )

        logger.info("Connection setup completed")

        if auto_start:
            self.start_tcpdump()

    def command_wrapper(self, cmd, show_output=False):

        logger.debug(f"Trying to execute command: \n{cmd}")
        try:
            result = self.connection.run(cmd, hide=True, timeout=5)
        except TimeoutError:
            logger.error("Command executin timeout")
            exit(1)
        except socket.timeout:
            logger.error("Socket connection timout")
            exit(1)

        if show_output:
            msg = "Ran {0.command!r} on {0.connection.host}, got stdout:\n{0.stdout}".format(result)
            logger.debug(msg)

    def start_tcpdump(self):
        cfg = self.tcpdump_cfg

        
        # Create remote folder and upload rename_script
        try:
            self.command_wrapper(f"mkdir {cfg['remote_pcap_folder']}")
        except:
            logger.debug("Remote folder already exists!")
            pass

        transfers.rsync(
            self.connection, 
            source = cfg["script_name"], 
            target = f"{cfg['remote_pcap_folder']}{cfg['script_name']}"
        )

        # This command is your choice.
        tpcdump_cmd = "nohup tcpdump -C {C} -W {W} -s0 -i {i} -Z root -z {z} -U -w {w} not port 22  > /dev/null 2>&1 & echo started".format(
            C = cfg['max_size'], 
            W = cfg['max_packets'], 
            i = cfg['interface'],
            z = f"{cfg['remote_pcap_folder']}{cfg['script_name']}",
            w = f"{cfg['remote_pcap_folder']}{cfg['packet_name']}")
        
        # First check if tcpdump is already running. If not, run tcpdump
        cmd = f'if [ $(pgrep -c "tcpdump") -eq 0 ]; then {tpcdump_cmd}; fi'

        self.command_wrapper(cmd)

    def start_rsync(self, repeat=0):
        cfg = self.tcpdump_cfg
        while True:
            try:
                res = transfers.rsync(
                    self.connection, 
                    source = f"{cfg['remote_pcap_folder']}*.pcap",
                    target = cfg['local_pcap_folder'],
                    remote_to_local=True)
            except:
                logger.error("Something went wrong with RSYNC. Retrying...")
                continue
            
            if not repeat:
                break
            
            sleep(repeat)

    def test(self):
        self.command_wrapper("whoami")

if __name__ == "__main__":
    sniffer = Sniffer("./config.json", False)

    counts = analyze("./new_packets/packet_capture198.pcap", sniffer.filters)

    logger.info("Loaded config:\n" + pformat(counts))
    #sniffer.start_tcpdump()
    #subprocess.run(["ls"], capture_output=False) 

    #sniffer.start_rsync()

