#!/usr/bin/env python3
from utils import setup_config, check_file
from constants import *
import os
import coloredlogs, logging
from time import sleep

# Create a logger object.
logger = logging.getLogger(__name__)

# coloredlogs.install(fmt = "%(levelname)s.%(name)s - %(message)s:", level='DEBUG', logger=logger)


class Sniffer:
    def __init__(self, conn, tcpdump, auto_start=False):
        self.ip = conn[VULN_IP]
        self.port = conn[VULN_PORT]
        self.user = conn[USER]
        self.key = conn[SSH_KEY]
        self.interface = tcpdump[INT]

        if auto_start:
            self.start_tcpdump(tcpdump)

    # WARNING - Before executing this, make sure rename_caps script has been created on remote host!
    def start_tcpdump(self, tcpdump):
        remote_path = tcpdump[REMOTE_FOLDER] + tcpdump[PACKET_NAME] # i.e /tmp/pbub
        remote_script = tcpdump[REMOTE_FOLDER] + tcpdump[SCRIPT_NAME]
        sniff_command = TCPDUMP_COMMAND.format(
            C = tcpdump[MAX_SIZE], 
            W = tcpdump[MAX_PACKETS], 
            i = tcpdump[INT], 
            z = remote_script, 
            w = remote_path
        )

        remote_command = REMOTE_COMMAND.format(
            k = self.key, 
            p = self.port, 
            i = self.ip, 
            u = self.user,
            c = sniff_command
        )

        if not check_file(self.key):
            logger.error(KEY_NOTFOUND.format(
                k = self.key, 
                u = self.user, 
                i = self.ip
            ))
            exit(1)
            
        logger.debug("Starting remote command...\n{}\n".format(remote_command))
        os.system(remote_command)

    def upload_file(self, filename):
        # remote_path contains *.pcap because we want rsync to only take packets that tcpdump has finished (tcpdump adds .pcap on postrotate, so when the packet is ready to be analyzed)

        rsync_cmd = RSYNC_COMMAND_UPLOAD.format(
            k = self.key,
            p = self.port,
            u = self.user,
            i = self.ip,
            r = tcpdump[REMOTE_FOLDER] + "",
            l = filename
        )

        if not check_file(self.key):
            logger.error(KEY_NOTFOUND.format(
                k = self.key, 
                u = self.user, 
                i = self.ip
            ))
            exit(1)

        logger.debug("Starting local command...\n{}\n".format(rsync_cmd))

        os.system(rsync_cmd)

        # if tcpdump[AUTO_UPLOAD_CARONTE]:
        #     start_upload()


    def get_packets(self, tcpdump):
        
        # remote_path contains *.pcap because we want rsync to only take packets that tcpdump has finished (tcpdump adds .pcap on postrotate, so when the packet is ready to be analyzed)

        remote_path = tcpdump[REMOTE_FOLDER] + "*.pcap" 
        rsync_cmd = RSYNC_COMMAND.format(
            k = self.key,
            p = self.port,
            u = self.user,
            i = self.ip,
            r = remote_path,
            l = tcpdump[LOCAL_FOLDER]
        )

        if not check_file(self.key):
            logger.error(KEY_NOTFOUND.format(
                k = self.key, 
                u = self.user, 
                i = self.ip
            ))
            exit(1)

        logger.debug("Starting local command...\n{}\n".format(rsync_cmd))

        os.system(rsync_cmd)

        # if tcpdump[AUTO_UPLOAD_CARONTE]:
        #     start_upload()



if __name__ == "__main__":
    # Get config.json info
    conn, tcpdump, verbose = setup_config()

    level = 'DEBUG' if verbose else 'INFO'  

    coloredlogs.install(fmt = "%(levelname)s.%(name)s - %(message)s:", level=level, logger=logger)

    sniffer = Sniffer(conn, tcpdump, False)

    sniffer.get_packets(tcpdump)

    sniffer.upload_file(tcpdump['script_name'])

    os.system(f"./feedCaronte.sh {tcpdump[LOCAL_FOLDER]} > /dev/null")

    while True:
        sniffer.get_packets(tcpdump)

        logger.info(f"Waiting {tcpdump['sleep_time']} seconds")
        sleep(tcpdump[SLEEP_TIME])