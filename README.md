# MassUPD
 
## About
MassUPD is a powerful command-line tool primarily designed for mass updating Linux systems. In addition to its core functionality of updating software across multiple systems, it also offers the ability to run custom commands on all connected systems simultaneously. This makes it ideal not only for bulk software installations but also for various other administrative tasks. The tool leverages multi-threading to ensure high performance by connecting to all clients concurrently.

The tool is very easy to configure using the various config files

### Features
The tool has a wide range of features such as:

 - Filtering connections
 - Importing connections using a formatted json file
 - Logging
 - Executing custom commands
 - Ability to add more package managers
 - And much more

## Install
To install MassUPD, execute the following command:
```shell
git clone https://github.com/LoserPurp/massupd.git && sudo bash massupd/install.sh
```
**Note: The install script is only for Linux systems. Windows support is coming.**

**For Windows systems, clone the repository and run the script using Python.**

## General information
All the connections are stored encrypted in a file called connections.json. The user sets up their own encryption key, which is wrapped (encrypted with itself) and stored inside a file called "key.txt". The wrapped key is only used to validate that the key you enter when using the tool, ensuring data safety.

All activities performed by the tool are logged in a log file for easy debugging. Access the log by running: 
```shell
massupd -l
```

*Note: if you change the salt in the config file, you would need to re-encrypt the connections.*

## How to use
IMPORTANT: before you use the tool remember to change the salt inside the "conf.yaml" file. It will be located in ```/usr/bin/massupd``` if you used the install script, or in the project folder if you did not.

### Flags
Running the tool without any flags starts the updating process.

**Here are a list of all the different flags and what they do**
```shell
  -a, --add                                        Add one or more new connections
  -c, --connections                                List all connections
  -e, --edit                                       Edit one or more connection
  -f FILTER, --filter FILTER                       Filter out connections
  -h, --help                                       Shows this message
  -i [IMPORT_LIST], --import-list [IMPORT_LIST]    import connections from list
  -k KEY, --key KEY                                Run script with key inn command
  -l [LOG], --log [LOG]                            Reads last 'n' lines in log file (default / blank is 25)
  -r, --remove                                     Remove connection by ip
  -t, --test                                       Test all connections
  -u, --user-command                               Run a user defined command
  -w, --wipe                                       Wipes all the connections
  -x, --export                                     Saves all connections as a unencrypted json file
  ```

## Detailed explanations

### Using -f or --filter
```shell
massupd -f b
```
*Blacklist option*
```shell
massupd -f w
```
*Whitelist option*

Use the filter flag with another valid flag to filter out connections based on specific criteria. For instance, you can filter out all connections using the package manager apt and update only the remaining systems.

<img src="https://github.com/LoserPurp/massupd/assets/99472938/e5d251c3-bff0-41bd-ad59-c713a38e2b68" width="350">

Here we can see i filtered out every connection with the package manger apt. and it therefore updated the only system without that manager.

The filter option can be used with --key (-k), --user-command (-u), --test (-t), and without another flag.<br>
*the default without a flag is to update all systems*

### Using -i or --import-list
```shell
massupd -i [filename]
```
*If the filename is left blank, it will look for /usr/lib/massupd/list.json, which is a dummy file.*

The import flag allows you to preconfigure all your connections in a JSON file. 

The JSON file has four main parts:

- loop: Indicates if the loop function should run.
- creds: Shared credentials for multiple connections.
- ips: List of IP addresses with shared credentials.
- connections: Standalone connections with defined IP and credentials.

*Example JSON file:*
```json
{
    "loop" : true,
    "creds" : {
        "user" : "bob",
        "password" : "pWord",
        "port" : 22,
        "passwordSudo" : "no",
        "manager" : "apt"
    },
    "ips" : [
        "192.168.10.150",
        "192.168.10.151",
        "192.168.10.152",
        "192.168.10.153",
        "192.168.10.154",
        "192.168.10.155"
    ],
    "connections" : [
        {
        "user": "jan",
        "ip": "192.168.10.420",
        "port": 22,
        "password": "password",
        "passwordSudo": "yes",
        "manager": "yum"
        },
        {
        "user": "banan",
        "ip": "192.168.10.69",
        "port": 33,
        "password": "password",
        "passwordSudo": "no",
        "manager": "dnf"
        }
    ]
}
```
*Note: it is recommended that you delete this file after use*

### Using -x or --export
```shell
massupd -x
```
Exporting connections will decrypt all the connections and save them as a json file in the folder you are running the command. The exported file, called "export.json" is compatible with the import function which makes it usefull and the only to change the encryption key (for now).

### Using -w or --wipe
```shell
massupd -w
```
Restores everything to default settings, except configurations made in the config files.

## Configuration
There are two yaml files used for configuring the tool.
- managers.yaml
- conf.yaml

These will be located in ```/usr/bin/massupd``` (If the linux install script was used)

**Mangers.yaml**
```yaml
apt: 'sudo apt update && sudo apt upgrade -y'
dnf: 'sudo dnf upgrade -y'
yum: 'sudo yum update -y'
pacman: 'sudo pacman -Syu --noconfirm'
```
Add or modify package managers and their update commands here.

**Conf.yaml**
```yaml
salt: salt1234
testCommand: whoami
logFile: log
listFile: /usr/lib/massups/list.json
conFile: connections.json
managerFile: mangers.yaml
keyFile: key.txt
```
This file contains settings such as the salt for encryption, the command for testing connections, and file paths. It is crucial to change the salt to something random and complex.


## Extra
MassUPD is still under development. If you encounter any bugs, issues, or have feature requests, please let me know.
