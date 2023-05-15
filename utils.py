import json
KEY_NOTFOUND  = """
You must first generate a SSH key!
To do, follow:
    ssh-keygen -f {k}
    ssh-copy-id -i {k} {u}@{i} 
"""
def check_file(filename):
    try:
        f = open(filename, "r")
        f.close()
    except FileNotFoundError:
        print("Error: no such file {}".format(filename))
        return False
    except PermissionError:
        print("Error: can't read file {}".format(filename))
    return True

def setup_config(filename=None):
    if not filename:
        filename = "config.json"

    if not check_file(filename):
        exit(1)
        
    f = open(filename, "r")
    config = json.loads(f.read())
    f.close()

    try:
        global tcpdump, connection, verbose, filters
        connection = config['connection_info']
        tcpdump = config['tcpdump_info']
        verbose = config['verbose']
        #filters = config['filters']
    except:
        print("Something is wrong in " + filename)
        exit(1)

    if not check_file(connection['ssh_key']):
        print("SSH Key not found for name: " + connection['ssh_key'])
        print(KEY_NOTFOUND)
        exit(1)


    return connection, tcpdump, verbose#, filters
