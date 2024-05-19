import json
import argparse
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import paramiko
import time
import getpass

encrypted_data_file = "connections.json"

def derive_key(passphrase, salt=b'salt1234', iterations=100000):
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
        print("Wrong password or connection is not formatted correctly!")
        exit()


def update_system(user, ip, port, password, package_manager, sudo_password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=password, port=port)

        if package_manager == "apt":
            stdin, stdout, stderr = ssh.exec_command('sudo apt update && sudo apt upgrade -y\n', get_pty=True)

        elif package_manager == "dnf":
            stdin, stdout = ssh.exec_command('sudo dnf upgrade -y\n', get_pty=True)

        elif package_manager == "yum":
            stdin, stdout, stderr = ssh.exec_command('sudo yum update -y\n', get_pty=True)

        elif package_manager == "pacman":
            stdin, stdout, stderr = ssh.exec_command('sudo pacman -Syu --noconfirm\n', get_pty=True)

        if not sudo_password == 'y' or 'yes':
            stdin.write(password + '\n')
            stdin.flush()

        print("Update in progress, this may take a while.")
        while not stdout.channel.exit_status_ready():
            time.sleep(1)

        print(f"Update on {ip} using {package_manager} completed.")
    except Exception as e:
        print(e)
    finally:
        ssh.close()

def test_connection(user, ip, port, password, sudo_password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=password, port=port)

        stdin, stdout, stderr = ssh.exec_command('sudo whoami\n', get_pty=True)

        if not sudo_password == 'y' or 'yes':
            stdin.write(password + '\n')
            stdin.flush()

        while not stdout.channel.exit_status_ready():
            time.sleep(1)

        print(f"Test on {ip} was successful")
    except Exception as e:
        print(f'Error connecting to {ip}: {e}')
    finally:
        ssh.close()


def add_new_connection():
    while True:
        user = input("Enter username: ")
        if user:
            break
        else:
            print("Username cannot be blank.")

    while True:
        ip = input("Enter IP address: ")
        if ip:
            break
        else:
            print("IP address cannot be blank.")

    while True:
        port = input("Enter port: (Blank for port 22) ")
        if not isinstance(port):
            print("Port must be a number")
        elif port:
            break
        elif port == "":
            port = 22
            print("Port set to 22")
            break

    while True:
        password = getpass.getpass("Enter password: ")
        if password:
            break
        else:
            print("Password can not be blank")

    while True:
        sudo_password = input("Passwordless sudo? (Y/n): ").lower()
        if sudo_password in ['y', 'n', '', 'yes', 'no']:
            break
        else:
            print("Please enter 'Y', 'N', or leave blank for default.")

    while True:
        manager = input("Enter package manager (apt/dnf/yum/pacman): ").lower()
        if manager in ['apt', 'dnf', 'yum', 'pacman']:
            break
        else:
            print("Invalid package manager. Please choose from 'apt', 'dnf', 'yum', or 'pacman'.")


    new_connection = {
        "user": user,
        "ip": ip,
        "port": port,
        "password": password,
        "passwordSudo": sudo_password,
        "manager": manager,
    }
    return new_connection


def load_encryption_key():
    parser = argparse.ArgumentParser(description="Update Linux systems and manage connections.")
    parser.add_argument("--key", required=True, help="Encryption key")
    args = parser.parse_args()

    key = derive_key(args.key)

    return key.encode('utf-8')


def list_connections(encrypted_data, key):
    for encrypted_connection in encrypted_data:
        decrypted_credentials = decrypt_credentials(encrypted_connection, key)

        sudoP = decrypted_credentials['passwordSudo']
        if sudoP in ['', 'n','no']:
            sudoP = 'No'
        else:
            sudoP = 'Yes'
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
        print("No connections found. Use --add to add new connections.")

    for index, connection in enumerate(decrypted_data):
        if connection["ip"] == ip:
            found = True
            break

    if found == False:
        print("IP address", ip, "not found in connections.")

    connection[attribute] = change
    encrypted_credentials = encrypt_credentials(connection, key)
    try:
        with open(encrypted_data_file, "w") as file:
            encrypted_data[index] = encrypted_credentials
            json.dump(encrypted_data, file)

    except FileNotFoundError:
        print("No connections found. Use --add to add new connections.")


def remove_connection(key, ip):
    
    decrypted_data = []
    found = False

    try:
        with open(encrypted_data_file, "r") as file:
            encrypted_data = json.load(file)
        for data in encrypted_data:
            decrypted_data.append(decrypt_credentials(data, key))
    except FileNotFoundError:
        print("No connections found. Use --add to add new connections.")
        return
    except json.JSONDecodeError:
        print("Error decoding connection file.")
        return

    for index, connection in enumerate(decrypted_data):
        if connection["ip"] == ip:
            found = True
            break

    if not found:
        print(f"IP address {ip} not found in connections.")
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





def loop_add(key):
    new_connection = {}

    def add():
        try:
            with open(encrypted_data_file, "r") as file:
                encrypted_data = json.load(file)
        except FileNotFoundError:
            encrypted_data = []

        encrypted_connection = encrypt_credentials(new_connection, key)
        encrypted_data.append(encrypted_connection)


        with open(encrypted_data_file, "w") as file:
            json.dump(encrypted_data, file)


    try:
        with open("list.json", "r") as file:
            cons = json.load(file)
    except Exception as e:
        print(e)
    if cons["loop"] == True:
        for ip in cons["ips"]:
            new_connection = {
                "user": cons["creds"]["user"],
                "ip": ip,
                "port": cons["creds"]["port"],
                "password": cons["creds"]["password"],
                "passwordSudo": cons["creds"]["passwordSudo"],
                "manager": cons["creds"]["manager"],
            }
            add()

    if cons["connections"]:
        for connection in cons["connections"]:
            new_connection = {
                "user": connection["user"],
                "ip": connection["ip"],
                "port": connection["port"],
                "password": connection["password"],
                "passwordSudo": connection["passwordSudo"],
                "manager": connection["manager"],
            }
            add()

def main():
    parser = argparse.ArgumentParser(description="Update Linux systems and manage connections.")
    parser.add_argument("-a", "--add", action="store_true", help="Add one or more new connections")
    parser.add_argument("-c", "--connections", action="store_true", help="List connections")
    parser.add_argument("-e", "--edit", action="store_true", help="Edit one or more connection")
    parser.add_argument("-i", "--import-list", action="store_true", help="import connections from list")
    parser.add_argument("-r", "--remove", action="store_true", help="Remove connection by ip")
    parser.add_argument("-t", "--test", action="store_true", help="Test connections")

    args = parser.parse_args()

    key = getpass.getpass("Enter decryption key: ")

    key = derive_key(key)


    if args.add:
        try:
            with open(encrypted_data_file, "r") as file:
                encrypted_data = json.load(file)
        except FileNotFoundError:
            encrypted_data = []

        while True:
            new_connection = add_new_connection()
            encrypted_connection = encrypt_credentials(new_connection, key)
            encrypted_data.append(encrypted_connection)

            add_another = input("Do you want to add another system? [Y/n]: ")
            if add_another.lower() in ["no", "n", ""]:
                break

        with open(encrypted_data_file, "w") as file:
            json.dump(encrypted_data, file)

    elif args.import_list:
        loop_add(key)
    
    elif args.remove:
        while True:
            ip = input("type the IP of the connection you would like to remove: ")
            if ip:
                remove_connection(key, ip)
                break

    elif args.edit:
        while True:
            ip = input("type the IP of the connection you would like to change: ")
            attribute = input("What would you like to change? (IP, user, port, password, passwordless sudo or package manager) ")
            change = input("What would you like to change it to?: ")

            edit_credentials(key, ip, attribute, change)

            add_another = input("Do you want to change another connection? [Y/n]: ")
            if add_another.lower() in ["no", "n", ""]:
                break

    elif args.connections:
        try:
            with open(encrypted_data_file, "r") as file:
                encrypted_data = json.load(file)
            list_connections(encrypted_data, key)
        except FileNotFoundError:
            print("No connections found. Use --a or -i to add new connections.")

    elif args.test:
        try:
            with open(encrypted_data_file, "r") as file:
                encrypted_data = json.load(file)

            for encrypted_connection in encrypted_data:
                decrypted_credentials = decrypt_credentials(encrypted_connection, key)
                test_connection(decrypted_credentials["user"], decrypted_credentials["ip"],
                                decrypted_credentials["port"], decrypted_credentials["password"],
                                decrypted_credentials["passwordSudo"])

        except FileNotFoundError:
            print("No connections found. Use --add to add new connections.")

    else:
        try:
            with open(encrypted_data_file, "r") as file:
                encrypted_data = json.load(file)

            for encrypted_connection in encrypted_data:
                decrypted_credentials = decrypt_credentials(encrypted_connection, key)
                update_system(decrypted_credentials["user"], decrypted_credentials["ip"],
                              decrypted_credentials["port"], decrypted_credentials["password"],
                              decrypted_credentials["manager"], decrypted_credentials["passwordSudo"])

        except FileNotFoundError:
            print("No connections found. Use --add to add new connections.")


if __name__ == "__main__":
    main()
