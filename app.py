import json
import argparse
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import paramiko
import time
import getpass


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
        print("Wrong password or file is not formatted correctly!")
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

        print(f"test on {ip} was successful")
    except Exception as e:
        print(e)
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
        port = input("Enter port (Blank for port 22): ")
        if port:
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
        "sudoPassword": sudo_password,
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

        sudoP = decrypted_credentials['sudoPassword']
        if sudoP in ['', 'n','no']:
            sudoP = 'No'
        else:
            sudoP = 'Yes'
        print(f"{decrypted_credentials['user']}@{decrypted_credentials['ip']}:{decrypted_credentials['port']}, "
              f"Manager: {decrypted_credentials['manager']}, Passwordless sudo: {sudoP}")


def main():
    parser = argparse.ArgumentParser(description="Update Linux systems and manage connections.")
    parser.add_argument("-a", "--add", action="store_true", help="Add one or more new connections")
    parser.add_argument("-c", "--connections", action="store_true", help="List connections")
    parser.add_argument("-t", "--test", action="store_true", help="Test connections")

    args = parser.parse_args()

    key = getpass.getpass("Enter decryption key: ")

    key = derive_key(key)

    encrypted_data_file = "connections.json"

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

            add_another = input("Do you want to add another system? (yes/no): ").lower()
            if add_another != "yes" or "y" or "":
                break

        with open(encrypted_data_file, "w") as file:
            json.dump(encrypted_data, file)

    elif args.connections:
        try:
            with open(encrypted_data_file, "r") as file:
                encrypted_data = json.load(file)
            list_connections(encrypted_data, key)
        except FileNotFoundError:
            print("No connections found. Use --add to add new connections.")

    elif args.test:
        try:
            with open(encrypted_data_file, "r") as file:
                encrypted_data = json.load(file)

            for encrypted_connection in encrypted_data:
                decrypted_credentials = decrypt_credentials(encrypted_connection, key)
                test_connection(decrypted_credentials["user"], decrypted_credentials["ip"],
                                decrypted_credentials["port"], decrypted_credentials["password"],
                                decrypted_credentials["sudoPassword"])

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
                              decrypted_credentials["manager"], decrypted_credentials["sudoPassword"])

        except FileNotFoundError:
            print("No connections found. Use --add to add new connections.")


if __name__ == "__main__":
    main()
