# --- Config json keys ---
VULN_IP = "vulnbox_ip"
VULN_PORT = "vulnbox_port"
USER = "user"
SSH_KEY = "ssh_key"
INT = "interface"
REMOTE_FOLDER = "remote_pcap_folder"
LOCAL_FOLDER = "local_pcap_folder"
MAX_SIZE = "max_size"
MAX_PACKETS = "max_packets"
PACKET_NAME = "packet_name"
SLEEP_TIME = "sleep_time"
SCRIPT_NAME = "script_name"

# --- Premade commands ---
# https://explainshell.com/explain?cmd=tcpdump+-C++-W+-s0++-Z+-z++-U+-w+
TCPDUMP_COMMAND = "nohup tcpdump -C {C} -W {W} -s0 -i {i} -Z root -z {z} -U -w {w} not port 22 > /dev/null 2>&1 &"


REMOTE_COMMAND = "ssh -oStrictHostKeyChecking=no -i {k} -p {p} {u}@{i} '{c}'"
RSYNC_COMMAND = 'rsync -avz -e "ssh -oStrictHostKeyChecking=no -i {k} -p {p}" {u}@{i}:{r} {l} 2>/dev/null'

# --- ERRORS ---
KEY_NOTFOUND  = """
You must first generate a SSH key!
To do, follow:
    ssh-keygen -f {k} -t ecdsa -b 521
    ssh-copy-id -i {k} {u}@{i} 
"""