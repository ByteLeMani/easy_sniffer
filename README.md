# Easy Sniffer
### Network tool for A/D CTF

This tool allow you to automatically start tcpdump session on remote host and save capture files (.pcap) on local machine

Thanks to **rsync** it is possibile to transfer quickly files from remote host to local machine

Dependencies:
- python3
- coloredlogs (from pip)
- tcpdump
- rsync (both on local machine and remote host)

### Basic config
All configuration must be done in **_config.json_**
Example:
```js
{
    "connection_info":{
        "vulnbox_ip": "172.17.112.1",
        "vulnbox_port" : 3022,
        "user" : "root",
        "ssh_key" : "chiave"
    },
    "tcpdump_info": {
        "interface" : "any",
        "remote_pcap_folder" : "/tmp/",
        "local_pcap_folder" : "./dumps",
        "max_packets" : 500,
        "max_size" : 1,
        "packet_name" : "pbub",
        "sleep_time" : 30
    }
}
```

### Attention
**Make sure**:
- **rename_caps** is present in same the same folder of **_remote_pcap_folder_**
- tcpdump is up to date on remote host
- to execute `aa-complain /bin/tcpdump` on remote host (apt-get install apparmor-utils). This is needed to make -z postcommand of tcpdump run properly (error such as permission denied could be issued and packets are not renamed in packetnameXXX.pcap, but remains packetname.pcapXXX - not good for Caronte)
- **rsync** is installed both on local and remote machine

For more information on point (3), look at:
https://ubuntuforums.org/showthread.php?t=1501339
https://answers.launchpad.net/ubuntu/+source/tcpdump/+question/168402

### Caronte integration
Thanks to [@eciavatta](https://github.com/eciavatt) it is pretty easy to integrate Caronte. Just use `./feedCaronte .` inside the **local pcap folder** and keep it running.
In order to use it, you need to install `inotify-tools`

### TODO
- [ ] Check if tcpdump is already running on remote host
- [ ] Add better timing for rsync to be called
- [x] Add integration with Caronte and ~~Flower~~ (automatic pcap uploader)
- [ ] Add basic web interface for easy settings management and for basic pcap analyzing (similiar to Flower)
- [ ] Dockerize when finished





