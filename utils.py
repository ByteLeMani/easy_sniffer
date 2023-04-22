import json

def check_file(filename):
    try:
        f = open(filename, "r")
        f.close()
    except:
        return False
    return True

def setup_config(filename=None):
    if not filename:
        filename = "config.json"

    if not check_file(filename):
        print("Error on opening file " + filename)
        exit(1)
        
    f = open(filename, "r")
    config = json.loads(f.read())
    f.close()

    try:
        global tcpdump, connection
        connection = config['connection_info']
        tcpdump = config['tcpdump_info']
        verbose = config['verbose']
    except:
        print("Something is wrong in " + filename)
        exit(1)

    return connection, tcpdump, verbose
