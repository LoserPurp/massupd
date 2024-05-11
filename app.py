import json
import argparse
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import paramiko
import time

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
        print("Connections file is not formatted correctly!")

def update_system(user, ip, password, package_manager):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=password)

        if package_manager == "apt":
            stdin, stdout, stderr = ssh.exec_command('sudo apt update && sudo apt upgrade -y\n', get_pty=True)

        elif package_manager == "dnf":
            stdin, stdout = ssh.exec_command("sudo dnf upgrade -y")

        elif package_manager == "yum":
            stdin, stdout, stderr = ssh.exec_command("sudo yum update -y")

        elif package_manager == "pacman":
            stdin, stdout, stderr = ssh.exec_command("sudo pacman -Syu --noconfirm")

        stdin.write(password + '\n')
        stdin.flush()

        print("Update in progress, this may take a while.")
        while not stdout.channel.exit_status_ready():
            time.sleep(1)

        print(f"Update on {ip} using {package_manager} completed.")
    except Exception as e:
        print(f"Error updating {ip} using {package_manager}: {e}")
    finally:
        ssh.close()

def add_new_connection():
    new_connection = {
        "user": input("Enter username: "),
        "ip": input("Enter IP address: "),
        "password": input("Enter password: "),
        "manager": input("Enter package manager (apt/dnf/yum/pacman): "),
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
        print(f"IP: {decrypted_credentials['ip']}, User: {decrypted_credentials['user']}, "
              f"Package Manager: {decrypted_credentials['manager']}")

def main():
    parser = argparse.ArgumentParser(description="Update Linux systems and manage connections.")
    parser.add_argument("-k", "--key", required=True, help="Passphrase to derive the key")
    parser.add_argument("-a", "--add", action="store_true", help="Add a new connection")
    parser.add_argument("-c", "--connection", action="store_true", help="List connections")

    args = parser.parse_args()

    key = derive_key(args.key)

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
            if add_another != "yes":
                break

        with open(encrypted_data_file, "w") as file:
            json.dump(encrypted_data, file)

    elif args.connection:
        try:
            with open(encrypted_data_file, "r") as file:
                encrypted_data = json.load(file)
            list_connections(encrypted_data, key)
        except FileNotFoundError:
            print("No connections found. Use --add to add new connections.")

    else:
        try:
            with open(encrypted_data_file, "r") as file:
                encrypted_data = json.load(file)

            for encrypted_connection in encrypted_data:
                decrypted_credentials = decrypt_credentials(encrypted_connection, key)
                update_system(decrypted_credentials["user"], decrypted_credentials["ip"],
                               decrypted_credentials["password"], decrypted_credentials["manager"])

        except FileNotFoundError:
            print("No connections found. Use --add to add new connections.")

if __name__ == "__main__":
    main()