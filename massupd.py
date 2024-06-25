import json
import argparse
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import paramiko
import time
import getpass
import threading
from datetime import datetime
from collections import deque
import os
import yaml

current_directory = os.getcwd()

script_directory = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_directory)

try:
    with open("conf.yaml", "r") as file:
        global conf
        conf = yaml.safe_load(file)
except Exception as e:
    print(f'Error reading manager file, {e}')
    exit()


filters = {}
encrypted_data_file = conf["conFile"]


def derive_key(passphrase, salt=conf["salt"].encode(), iterations=100000):
    passphrase_bytes = passphrase.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    derived_key = kdf.derive(passphrase_bytes)

    return base64.urlsafe_b64encode(derived_key).decode('utf-8')


def encrypt_credentials(credentials, key):
    cipher_suite = Fernet(key)
    encrypted_credentials = cipher_suite.encrypt(json.dumps(credentials).encode())

    return base64.b64encode(encrypted_credentials).decode('utf-8')


def decrypt_credentials(encrypted_credentials, key):
    try:
        cipher_suite = Fernet(key)
        encrypted_credentials_bytes = base64.b64decode(encrypted_credentials)
        decrypted_credentials = cipher_suite.decrypt(encrypted_credentials_bytes)
        decrypted_credentials_str = decrypted_credentials.decode('utf-8')
        return json.loads(decrypted_credentials_str.replace("'", "\""))
    except:
        log("Error decryption failed, wrong password or connection is not formatted correctly!", True)
        exit()


def get_managers():
    try:
        with open(conf["managerFile"], "r") as file:
            managers = yaml.safe_load(file)
            return(managers)
    except Exception as e:
        log(f'Error reading manager file, {e}', True)
        exit()


def log(msg, to_console):
        if to_console:
            print(msg)
        try:
            with open(conf["logFile"], 'a') as file:
                file.write(f'{datetime.now().strftime("[%d.%m.%Y %H:%M:%S]")} - {msg} \n')
        except Exception as e:
            print(f"An error with the log occurred: {e}")


def update_system(user, ip, port, password, package_manager, sudo_password):
    try:
        managers = get_managers()
        check = ['user', 'ip', 'port', 'password', 'passwordSudo', 'manager']
        check2 = [user, ip, port, password, sudo_password, package_manager]

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if not filters:
            ssh.connect(ip, username=user, password=password, port=port)

        elif filters["filter"] in ['w', 'wl', 'whitelist'] and filters["filtering"] in check and filters["value"] in check2:
            ssh.connect(ip, username=user, password=password, port=port)

        elif filters["filter"] in ['b', 'bl', 'blacklist'] and filters["filtering"] in check and filters["value"] not in check2:
            ssh.connect(ip, username=user, password=password, port=port)

        else:
            return

        if package_manager in managers:
            stdin, stdout, stderr = ssh.exec_command(f'{managers[package_manager]}\n', get_pty=True)
        else:
            log(f"Error updating {ip}, did not find {package_manager} in manager list", True)
            return

        if not sudo_password == 'y' or 'yes':
            stdin.write(password + '\n')
            stdin.flush()

        log(f"Update started on {ip}, this may take a while.", True)        
        stdout.channel.recv_exit_status()
        exit_code = str(stdout.channel.recv_exit_status())

        if exit_code != '0':
            if exit_code == '1':
                log(f'Error updating connection {ip}: (Exit code {exit_code}) Is the manager correct?', True)
            else:
                log(f'Error updating connection {ip}: (Exit code {exit_code})', True)
        else:
            log(f"Update on {ip} using {package_manager} completed.", True)

    except Exception as e:
        log(f"Error updating {ip}, {e}", True)
    finally:
        ssh.close()


def test_connection(user, ip, port, password, sudo_password, manager):
    command = conf["testCommand"]
    try:
        check = ['user', 'ip', 'port', 'password', 'passwordSudo', 'manager']
        check2 = [user, ip, port, password, sudo_password, manager]

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if not filters:
            ssh.connect(ip, username=user, password=password, port=port)

        elif filters["filter"] in ['w', 'wl', 'whitelist'] and filters["filtering"] in check and filters["value"] in check2:
            ssh.connect(ip, username=user, password=password, port=port)

        elif filters["filter"] in ['b', 'bl', 'blacklist'] and filters["filtering"] in check and filters["value"] not in check2:
            ssh.connect(ip, username=user, password=password, port=port)

        else:
            return

        if user != "root":
            command = "sudo "+ command

        stdin, stdout, stderr = ssh.exec_command(f'{command}\n', get_pty=True)

        if not sudo_password == 'y' or 'yes':
            stdin.write(password + '\n')
            stdin.flush()

        stdout.channel.recv_exit_status()
        exit_code = str(stdout.channel.recv_exit_status())

        if exit_code != '0':
            log(f'Error testing connection {ip}: (Exit code {exit_code})', True)
        else:
            log(f"Test on {ip} was successful", True)

    except Exception as e:
        log(f'Error testing connection {ip}: {e}', True)
    finally:
        ssh.close()


def add_new_connection(key):
    all_connection_ips = []

    try:
        with open(encrypted_data_file, "r") as file:
            encrypted_data = json.load(file)
    except FileNotFoundError:
        encrypted_data = []

    for encrypted_connection in encrypted_data:
        decrypted_credentials = decrypt_credentials(encrypted_connection, key)
        all_connection_ips.append(decrypted_credentials["ip"])


    while True:
        user = input("Enter username: ")
        if user:
            break
        else:
            print("Username cannot be blank.")

    while True:
        ip = input("Enter IP address: ")
        if ip in all_connection_ips:
            print("A connection with the same ip already exists")
        elif ip:
            break
        else:
            print("IP address cannot be blank.")

    while True:
        port_input = input("Enter port: (Blank for port 22) ")
        if port_input == "":
            port = 22
            print("Port set to 22")
            break
        try:
            port = int(port_input)
            if port:
                break
        except ValueError:
            print("Port must be a number")

    while True:
        password = getpass.getpass("Enter password: ")
        if password:
            break
        else:
            print("Password can not be blank")

    while True:
        sudo_password = input("Passwordless sudo? [Y/n]: ").lower()
        if sudo_password in ['y', 'n', '', 'yes', 'no']:
            break
        else:
            print("Please enter 'Y', 'N', or leave blank for no.")

    managers = get_managers()
    manger_list = ""
    for manger in managers:
        manger_list += f"{manger}/"
    while True:
        manager = input(f"Enter package manager ({manger_list[:-1]}): ").lower()
        if manager in managers:
            break
        else:
            print(f"Invalid package manager. Please choose from ({manger_list[:-1]})")


    new_connection = {
        "user": user,
        "ip": ip,
        "port": port,
        "password": password,
        "passwordSudo": sudo_password,
        "manager": manager,
    }
    log(f'Added connection: {user}@{ip}:{port} using {manager}', True)
    return new_connection


def list_connections(encrypted_data, key):
    for encrypted_connection in encrypted_data:
        decrypted_credentials = decrypt_credentials(encrypted_connection, key)

        sudoP = decrypted_credentials['passwordSudo']
        if sudoP in ['', 'n','no']:
            sudoP = 'No'
        else:
            sudoP = 'Yes'

        if not filters:
            print(f"{decrypted_credentials['user']}@{decrypted_credentials['ip']}:{decrypted_credentials['port']}, "
              f"Manager: {decrypted_credentials['manager']}, Passwordless sudo: {sudoP}")

        elif filters["filter"] in ['w', 'wl', 'whitelist']:
            if decrypted_credentials[filters["filtering"]] == filters["value"]:
                print(f"{decrypted_credentials['user']}@{decrypted_credentials['ip']}:{decrypted_credentials['port']}, "
                    f"Manager: {decrypted_credentials['manager']}, Passwordless sudo: {sudoP}")

        elif filters["filter"] in ['b', 'bl', 'blacklist']:
            if decrypted_credentials[filters["filtering"]] != filters["value"]:
                print(f"{decrypted_credentials['user']}@{decrypted_credentials['ip']}:{decrypted_credentials['port']}, "
                    f"Manager: {decrypted_credentials['manager']}, Passwordless sudo: {sudoP}")


def edit_credentials(key, ip, attribute, change):
    decrypted_data = []
    found = False
    if attribute == "port":
        change = int(change)

    try:
        with open(encrypted_data_file, "r") as file:
            encrypted_data = json.load(file)
        for data in encrypted_data:
            decrypted_data.append(decrypt_credentials(data, key))

    except FileNotFoundError:
        print("No connections found. Use -a or -i to add new connections.")

    for index, connection in enumerate(decrypted_data):
        if connection["ip"] == ip:
            found = True
            break

    if found == False:
        log(f'Error editing {ip}, not found in connections.', True)

    connection[attribute] = change
    encrypted_credentials = encrypt_credentials(connection, key)
    try:
        with open(encrypted_data_file, "w") as file:
            encrypted_data[index] = encrypted_credentials
            json.dump(encrypted_data, file)

    except FileNotFoundError:
        print("No connections found. Use -a or -i to add new connections.")


def remove_connection(key, ip):
    
    decrypted_data = []
    found = False

    try:
        with open(encrypted_data_file, "r") as file:
            encrypted_data = json.load(file)
        for data in encrypted_data:
            decrypted_data.append(decrypt_credentials(data, key))
    except FileNotFoundError:
        log(f'Error removing connection {ip}: connection file not found', False)
        print("No connections found. Use -a or -i to add new connections.")
        return
    except json.JSONDecodeError:
        print("Error decoding connection file.")
        log(f'Error removing connection {ip}: Could not decode connection file', False)
        return

    for index, connection in enumerate(decrypted_data):
        if connection["ip"] == ip:
            found = True
            break

    if not found:
        log(f"Error removing {ip}, not found in connections.", True)
        return

    del decrypted_data[index]

    encrypted_data = []
    for data in decrypted_data:
        encrypted_data.append(encrypt_credentials(data, key))

    try:
        with open(encrypted_data_file, "w") as file:
            json.dump(encrypted_data, file)
    except Exception as e:
        print(f"An error occurred while saving connections: {e}")


def check_key(key):
    check_key = ""

    def new_key():
        with open(conf["keyFile"], "w") as file:
            check_key = encrypt_credentials(key, key)
            file.write(check_key)
            return check_key

    try:
        with open(conf["keyFile"], "r") as file:
            check_key = file.read()
            if not check_key:
                check_key = new_key()
    except FileNotFoundError:
        check_key = new_key()

    try:
        cipher_suite = Fernet(key)
        encrypted_credentials_bytes = base64.b64decode(check_key)
        decrypted_credentials = cipher_suite.decrypt(encrypted_credentials_bytes)
        decrypted_credentials_str = decrypted_credentials.decode('utf-8')
    except:
        return False

    return json.loads(decrypted_credentials_str.replace("'", "\""))


def read_log(number_of_lines):
    with open(conf["logFile"], 'r') as file:
        last_n_lines = deque(file, maxlen=int(number_of_lines))
    return list(last_n_lines)


def run_custom_command(user, ip, port, password, sudo_password, command, manager, filters=None):
    try:
        check = ['user', 'ip', 'port', 'password', 'passwordSudo', 'manager']
        check2 = [user, ip, port, password, sudo_password, manager]

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if not filters:
            ssh.connect(ip, username=user, password=password, port=port)
        elif filters["filter"] in ['w', 'wl', 'whitelist'] and filters["filtering"] in check and filters["value"] in check2:
            ssh.connect(ip, username=user, password=password, port=port)
        elif filters["filter"] in ['b', 'bl', 'blacklist'] and filters["filtering"] in check and filters["value"] not in check2:
            ssh.connect(ip, username=user, password=password, port=port)
        else:
            log("Filter conditions not met, command not executed", True)
            return

        stdin, stdout, stderr = ssh.exec_command(command, get_pty=True)

        if command.lower().startswith('sudo') and sudo_password not in ['y', 'yes']:
            stdin.write(sudo_password + '\n')
            stdin.flush()

        stdout.channel.recv_exit_status()
        exit_code = str(stdout.channel.recv_exit_status())

        if exit_code != '0':
            log(f'Error running custom command on {ip}: (Exit code {exit_code})', True)
        else:
            log(f"Custom command [{command}] on {ip} ran successfully", True)

    except Exception as e:
        log(f'Error running custom command on {ip}: {e}', True)
    finally:
        try:
            ssh.close()
        except Exception as e:
            log(f'Error closing SSH connection: {e}', True)


def loop_add(key, list_file):
    new_connection = {}
    all_connection_ips = []

    try:
        with open(encrypted_data_file, "r") as file:
            encrypted_data = json.load(file)
    except FileNotFoundError:
        encrypted_data = []

    for encrypted_connection in encrypted_data:
        decrypted_credentials = decrypt_credentials(encrypted_connection, key)
        all_connection_ips.append(decrypted_credentials["ip"])

    def add():
        encrypted_connection = encrypt_credentials(new_connection, key)
        encrypted_data.append(encrypted_connection)

        with open(encrypted_data_file, "w") as file:
            json.dump(encrypted_data, file)

    try:
        if list_file == conf["listFile"]:
            direc = list_file
        elif list_file.startswith("/"):
            direc = list_file
        else:
            direc = f"{current_directory}/{list_file}"

        with open(direc, "r") as file:
            cons = json.load(file)
    except Exception as e:
        log(f'Error importing connections from file, {e}', True)
    try:
        if cons["loop"]:
            for ip in cons["ips"]:
                new_connection = {
                    "user": cons["creds"]["user"],
                    "ip": ip,
                    "port": cons["creds"]["port"],
                    "password": cons["creds"]["password"],
                    "passwordSudo": cons["creds"]["passwordSudo"],
                    "manager": cons["creds"]["manager"],
                }
                if ip not in all_connection_ips:
                    add()
                    log(f'Importing {len(cons["ips"])} connections with shared credentials', False)
                    log(f'Added connection: {cons["creds"]["user"]}@{ip}:{cons["creds"]["port"]} using {cons["creds"]["manager"]}', True)
                else:
                    print(f'{ip} was skipped because a connection with that same ip already exists')
    except:
        pass

    try:
        if cons["connections"]:
            log(f'Importing {len(cons["connections"])} connections with seperate credentials', False)
            for connection in cons["connections"]:
                new_connection = {
                    "user": connection["user"],
                    "ip": connection["ip"],
                    "port": connection["port"],
                    "password": connection["password"],
                    "passwordSudo": connection["passwordSudo"],
                    "manager": connection["manager"],
                }
                if connection["ip"] not in all_connection_ips:
                    add()
                    log(f'Added connection: {connection["user"]}@{connection["ip"]}:{connection["port"]} using {connection["manager"]}', True)
                else:
                    print(f'{connection["ip"]} was skipped because a connection with that same ip already exists')
    except:
        pass


class CustomHelpFormatter(argparse.HelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        pass

def main():
    try:
        parser = argparse.ArgumentParser(description="Update Linux systems and manage connections.", formatter_class=CustomHelpFormatter, add_help=False,)
        parser.add_argument("-a", "--add", action="store_true", help="Add one or more new connections")
        parser.add_argument("-b", "--backup", action="store", help="Makes or restore a backup")
        parser.add_argument("-c", "--connections", action="store_true", help="List all connections")
        parser.add_argument("-e", "--edit", action="store_true", help="Edit one or more connection")
        parser.add_argument("-f", "--filter", action="store", help="Filter out connections")
        parser.add_argument("-h", "--help", action="help", help="Shows this message")
        parser.add_argument("-i", "--import-list", nargs='?', const=conf["listFile"], default=None, help="import connections from list")
        parser.add_argument("-k", "--key", action="store", help="Run script with key inn command")
        parser.add_argument("-l", "--log", nargs='?', const=25, default=None, help="Reads last 'n' lines in log file (default / blank is 25)")
        parser.add_argument("-r", "--remove", action="store_true", help="Remove connection by ip")
        parser.add_argument("-t", "--test", action="store_true", help="Test all connections")
        parser.add_argument("-u", "--user-command", action="store_true", help="Run a user defined command")
        parser.add_argument("-w", "--wipe", action="store_true", help="Wipes all the connections")
        parser.add_argument("-x", "--export", action="store_true", help="Saves all connections as a unencrypted json file")

        args = parser.parse_args()

        if args.log is not None:
            read_log(args.log)
            lines = read_log(args.log)
            for line in lines:
                print(line, end='')
            exit()


        if args.key:
            key = args.key
            key = derive_key(key)
            check = check_key(key)

            if key != check:
                print("Error, key does not match!")
                exit()
        else:
            tries = 0
            while tries < 3:
                key = getpass.getpass("Enter decryption key: ")

                key = derive_key(key)
                check = check_key(key)

                if key != check:
                    print("Error, key does not match!")
                    tries += 1
                    if tries >= 3:
                        log("Tried password to many times!", True)
                        exit()
                else:
                    break

        if args.filter:
            if args.connections or args.edit or args.log:
                print("Filter can not be run along this argument, use filter with (update, test or when running a custom command)")
                exit()
            while True:
                if args.filter not in ['w', 'b', 'white', 'black', 'whitelist', 'blacklist', 'wl', 'bl']:
                    print('Filter must be white or blacklist (w/b)')
                else:
                    break

            global filters
            filters = {
                "filter" : args.filter,
                "filtering" : "",
                "value" : ""
            }

            attribute_mapping = {
                1: "ip",
                2: "user",
                3: "port",
                4: "password",
                5: "passwordSudo",
                6: "manager",
                7: "exit"
            }

            print("Filters:\n"
                "\n"
                "1) IP\n"
                "2) User\n"
                "3) Port\n"
                "4) Password\n"
                "5) Passwordless Sudo [Y/n]\n"
                "6) Package Manager\n"
                "7) Exit\n")

            try:
                while True:
                    temp = int(input("Enter an option from 1-7: "))
                    if temp:
                        break
                if 1 <= temp <= 7:
                    if temp == 7:
                        exit()
                    filters["filtering"] = attribute_mapping[temp]
                    if filters["filtering"] == "password":
                        filters["value"] = getpass.getpass("Choose a value to filter: ")
                    else:
                        filters["value"] = input("Choose a value to filter: ")
                else:
                    print("Invalid input. Please enter a number between 1 and 7.")
            except ValueError:
                pass


        if args.add:
            log("Starting script with add function", False)
            try:
                with open(encrypted_data_file, "r") as file:
                    encrypted_data = json.load(file)
            except FileNotFoundError:
                encrypted_data = []

            while True:
                new_connection = add_new_connection(key)
                encrypted_connection = encrypt_credentials(new_connection, key)
                encrypted_data.append(encrypted_connection)

                add_another = input("Do you want to add another system? [Y/n]: ")
                if add_another.lower() in ["no", "n", ""]:
                    break

            with open(encrypted_data_file, "w") as file:
                json.dump(encrypted_data, file)


        elif args.backup:
            if not os.path.exists('./backup'):
                try:
                    os.mkdir('./backup')
                    print("Backup folder was missing, created folder successfully.")
                except Exception as e:
                    print("Backup folder was missing, folder could not be created")

            if args.backup not in ['m', 'r']:
                print("You must choose to make or restore a backup [M/r]")

            elif args.backup == 'm':
                try:
                    with open(encrypted_data_file, "r") as file:
                        encrypted_data = json.load(file)
                        if encrypted_data != []:
                            with open(f'backup/{datetime.now().strftime("[%d.%m.%Y.%H:%M]")}.backup', 'w') as backup_file:
                                json.dump(encrypted_data, backup_file)
                                print(f"Made a backup of all connections")
                        else:
                            log("Did not make a backup, connections file is empty!", True)
                except FileNotFoundError:
                    log("Error, connections file not found", True)

            elif args.backup == 'r':
                print("")

                files = [f for f in os.listdir('./backup') if os.path.isfile(os.path.join('./backup', f)) and f.endswith('.backup')]
                for index, file in enumerate(files, start=1):
                    print(f'Backup {index}: {file.split('.backup')[0]}')
                print("")
                try:
                    select = int(input("Select a backup to restore: "))
                except ValueError:
                    print("You must select a number!")
                    exit(1)
                if 1 <= select <= len(files):
                    selected_file = os.path.join('./backup', files[select - 1])
                    try:
                        with open(selected_file, "r") as file:
                            backup = json.load(file)
                            if backup != [] or not '':
                                with open(encrypted_data_file, "w") as file:
                                    json.dump(backup, file)
                                    log(f"Restored from backup {selected_file.split('.backup')[0]}")
                            else:
                                log("Did restore backup, backup file is empty!", True)
                    except FileNotFoundError:
                        log("Error, backup file not found", True)
                    except Exception as e:
                        log(f"Error, {e}", False)

                else:
                    print("Invalid selection")


        elif args.import_list:
            log("Starting script with import function", False)
            loop_add(key, args.import_list)


        elif args.remove:
            try:
                with open(encrypted_data_file, "r") as file:
                    encrypted_data = json.load(file)
            except FileNotFoundError:
                encrypted_data = []

            if not encrypted_data:
                    print("No connections found. Use -a or -i to add new connections.")
                    return

            log("Starting script with remove function", False)
            while True:
                ip = input("type the IP of the connection you would like to remove: ")
                if ip:
                    remove_connection(key, ip)
                    break


        elif args.edit:
            try:
                with open(encrypted_data_file, "r") as file:
                    encrypted_data = json.load(file)
                    if not encrypted_data:
                        print("No connections found. Use -a or -i to add new connections.")
                        return
            except:
                print("No connections found. Use -a or -i to add new connections.")
                return

            attribute_mapping = {
                1: "ip",
                2: "user",
                3: "port",
                4: "password",
                5: "passwordSudo",
                6: "manager",
                7: "exit"
            }

            log("Starting script with edit function", False)
            managers = get_managers()
            while True:
                ip = input("type the IP of the connection you would like to change: ")
                print("\n"
                      "1) IP\n"
                      "2) User\n"
                      "3) Port\n"
                      "4) Password\n"
                      "5) Passwordless Sudo [Y/n]\n"
                      "6) Package Manager\n"
                      "7) Exit\n"
                      )

                while True:
                    try:
                        attribute = int(input("Enter an option from 1-7: "))
                        if 1 <= attribute <= 7:
                            if attribute == 7:
                                exit()
                            attribute = attribute_mapping[attribute]
                            break
                        else:
                            print("Invalid input. Please enter a number between 1 and 7.")
                        
                    except ValueError:
                        pass

                while True:
                    if attribute == "password":
                        change = getpass.getpass("What would you like to change it to?: ")
                    else:
                        change = input("What would you like to change it to?: ")

                    if attribute == "port" and not change.isnumeric():
                        print("Port must be a number")
                    elif attribute == "passwordSudo" and change.lower() not in ['y', 'n', 'yes', 'no']:
                        print("Value must be Yes or No [Y/n]")
                    elif attribute == "manager" and change not in managers:
                        print(f"{attribute} is not in manager list")
                    else:
                        edit_credentials(key, ip, attribute, change)
                        break

                add_another = input("Do you want to change another connection? [Y/n]: ")
                if add_another.lower() in ["no", "n", ""]:
                    break


        elif args.connections:
            log("Starting script with list connections function", False)
            try:
                with open(encrypted_data_file, "r") as file:
                    encrypted_data = json.load(file)
                    if not encrypted_data:
                        print("No connections found. Use -a or -i to add new connections.")
                        return
                list_connections(encrypted_data, key)
            except FileNotFoundError:
                print("No connections found. Use -a or -i to add new connections.")


        elif args.test:
            try:
                with open(encrypted_data_file, "r") as file:
                    encrypted_data = json.load(file)
                    if not encrypted_data:
                        print("No connections found. Use -a or -i to add new connections.")
                        return
                log("Staring test on all connections", True)

                def run():
                        decrypted_credentials = decrypt_credentials(encrypted_connection, key)
                        test_connection(decrypted_credentials["user"], decrypted_credentials["ip"],
                                    decrypted_credentials["port"], decrypted_credentials["password"],
                                    decrypted_credentials["passwordSudo"], decrypted_credentials["manager"])

                threads = []
                for encrypted_connection in encrypted_data:
                    thread = threading.Thread(target=run)
                    thread.start()
                    threads.append(thread)

                for thread in threads:
                    thread.join()

            except FileNotFoundError:
                print("No connections found. Use -a or -i to add new connections.")
            except KeyboardInterrupt:
                exit()


        elif args.user_command:
            try:
                with open(encrypted_data_file, "r") as file:
                    encrypted_data = json.load(file)
                    if not encrypted_data:
                        print("No connections found. Use -a or -i to add new connections.")
                        return

                custom_command = input("What command would you like to run?: ")
                log("Running custom command on all systems", True)
                def run():
                        decrypted_credentials = decrypt_credentials(encrypted_connection, key)
                        run_custom_command(decrypted_credentials["user"], decrypted_credentials["ip"],
                                    decrypted_credentials["port"], decrypted_credentials["password"],
                                    decrypted_credentials["passwordSudo"], custom_command, decrypted_credentials["manager"])

                threads = []
                for encrypted_connection in encrypted_data:
                    thread = threading.Thread(target=run)
                    thread.start()
                    threads.append(thread)

                for thread in threads:
                    thread.join()

            except FileNotFoundError:
                print("No connections found. Use -a or -i to add new connections.")
            except KeyboardInterrupt:
                exit()


        elif args.wipe:
            files = [conf["conFile"], conf["keyFile"]]

            for file in files:
                try:
                    with open(file, 'w') as f:
                        f.write('')
                except Exception as e:
                    print(f"Error: Unable to remove {file}. {e}")


        elif args.export:
            data = []

            try:
                with open(encrypted_data_file, "r") as file:
                    encrypted_data = json.load(file)
            except:
                log("Error: Could not open connection file", True)
                exit()

            for con in encrypted_data:
                data.append(decrypt_credentials(con, key))

            output_dict = {"connections": data}
            export_string = json.dumps(output_dict, indent=4)

            try:
                with open(f'{current_directory}/{conf["exportFile"]}', "w") as file:
                    file.write(export_string)
            except Exception as e:
                log(f"Error: Could not save to file, {e}", True)


        else:
            log("Starting updated on all systems", True)
            try:
                with open(encrypted_data_file, "r") as file:
                    encrypted_data = json.load(file)

                    def run():
                        decrypted_credentials = decrypt_credentials(encrypted_connection, key)
                        update_system(decrypted_credentials["user"], decrypted_credentials["ip"],
                                    decrypted_credentials["port"], decrypted_credentials["password"],
                                    decrypted_credentials["manager"], decrypted_credentials["passwordSudo"])

                threads = []
                for encrypted_connection in encrypted_data:
                    thread = threading.Thread(target=run)
                    thread.start()
                    threads.append(thread)

                for thread in threads:
                    thread.join()

            except FileNotFoundError:
                print("No connections found. Use -a or -i to add new connections.")
                log("Update failed, connections file not found", False)
            
            print("\n"
                  "Update finished")


    except KeyboardInterrupt:
        exit()

if __name__ == "__main__":
    main()