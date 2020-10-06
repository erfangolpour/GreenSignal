# Connection libraries
import socket

# Threading
import Core.Utilities.TracableThreading as TracableThreading

# Encryption libraries
import rsa
import base64
from Core.Encryptions.AESCipher import AESCipher

# To print errors
from sys import exc_info

# Saving files labeled with current time
from datetime import datetime

# To save files
import os

class Server:
    def __init__(self, server_ip, server_port, user_limit, secret_key, admin_panel):
        # Seprated terminal
        self.admin_panel = admin_panel

        # Server details
        self.server_ip = server_ip
        self.server_port = server_port
        self.user_limit = user_limit

        # Setting secret key
        self.secret_key = secret_key

        # AES Object
        self.AES_Cipher = AESCipher(self.secret_key)

        # Username invalid characters
        self.invalid_characters = """'"?!@#$%^&*()[]<>\{\}/\\"""

        # Configuring variables
        self.default_users = ["ADMIN", "INFO"]
        self.users = {}
        self.users_public_keys = {}
        self.muted_users = []
        self.users_threads = []

        # Connection Code Dictionary
        self.control_responses = {
            'wrong_key' : b'#WrongKey#',
            'greeting' : b'#WELCOME#',
            'invalid_username' : b'#InvalidUsername',
            'valid_username' : b'#ValidUsername',
            'leave_message' : b'#Leaving#',
            'kicked' : b'#KICKED#',
            'encryption_failed' : b'#ABORT#',
            'server_down' : b'#ServerTurnDown#',
            'username_limit' : b'#UsernameLimit#',
            'full_server' : b'#FullServer#'
        }

        # Binding Server
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((server_ip, server_port))
        self.server.listen(self.user_limit)

        # Start Accepting Clients
        self.server_thread = TracableThreading.TracableThread(target = self.accept_users, args = (self.server,))
        self.server_thread.start()

    def __repr__(self):
        return 'Server(%r, %r, %r, %r)' % (self.server_ip, self.server_port, self.user_limit, self.secret_key)

    def accept_users(self, server):
        # Avoid stucking in server.accept()
        server.settimeout(2)

        # Accepting new clients
        while True:
            try:
                client, addr = server.accept()
                if len(self.users) >= self.user_limit:
                    client.send(base64.b64encode(self.control_responses['full_server']))
                    client.close()
                    continue
                client.send(base64.b64encode(self.control_responses['greeting']))
                self.admin_panel.print('\n[*] Accepted a connection from: %s:%s' % (addr[0], addr[1]))
                client_thread = TracableThreading.TracableThread(target = self.user_handler, args = (client, addr,))
                client_thread.start()
                self.users_threads.append(client_thread)
            except:
                pass

    def user_handler(self, client_socket, client_addr):
        # Set timeout to none
        client_socket.settimeout(None)

        # Encrypting the connection
        self.admin_panel.print("[*] Encrypting the connection for %s:%s" % (client_addr[0], client_addr[1]))

        # Generating keys
        (pubkey, privkey) = rsa.newkeys(1024)

        # Receiving clients public key
        client_pubkey_primes_base64 = client_socket.recv(1024)
        client_pubkey_primes = base64.b64decode(client_pubkey_primes_base64).decode('utf-8').split('#')
        client_pubkey = rsa.PublicKey(int(client_pubkey_primes[0]), int(client_pubkey_primes[1])) # Clients Public key
        self.admin_panel.print("[*] Client's Public Key received")

        # Send public key to client
        pubkey_primes = '%s#%s' % (str(pubkey.n), str(pubkey.e))
        pubkey_primes_base64 = base64.b64encode(pubkey_primes.encode('utf-8'))
        client_socket.send(pubkey_primes_base64)
        self.admin_panel.print("[*] Public Key sent")

        # Receving hashed signature to make sure encryption is working properly
        self.admin_panel.print("[*] Validating Encryption for %s:%s" % (client_addr[0], client_addr[1]))
        client_signature_base64 = client_socket.recv(4096)
        client_signature = base64.b64decode(client_signature_base64)
        self.admin_panel.print('[*] Recieved Signature: %s' % client_signature)

        try: # rsa.verify raises an exception if the signature isn't valid
            rsa.verify(self.secret_key.encode('utf-8'), client_signature, client_pubkey)
            client_socket.send(base64.b64encode(self.control_responses['greeting']))
        except:
            self.admin_panel.print("\n[*] %s:%s Encryption could not be verified! Ending this thread...\n" % (client_addr[0], client_addr[1]))
            client_socket.send(base64.b64encode(self.control_responses['encryption_failed']))
            client_socket.close()
            return 0

        # Encryption Verified
        self.admin_panel.print("[*] %s:%s - Encryption Verified!" % (client_addr[0], client_addr[1]))

        # Waiting for the secret key
        self.admin_panel.print('[*] Receiving The Secret Key From %s:%s' % (client_addr[0], client_addr[1]))
        request = client_socket.recv(2048)
        client_secret_key = rsa.decrypt(request, privkey).decode('utf-8')
        self.admin_panel.print('[*] Received: %s as the secret key from %s:%s' % (client_secret_key, client_addr[0], client_addr[1]))

        # Validating secret key
        if client_secret_key != self.secret_key:
            self.admin_panel.print('Closing %s:%s - Potensial Threat: Incorrect secret key received!' % (client_addr[0], client_addr[1]))
            client_socket.send(rsa.encrypt(self.control_responses['wrong_key'], client_pubkey))
            client_socket.close()
            return 0

        # Secret key was correct
        client_socket.send(rsa.encrypt(self.control_responses['greeting'], client_pubkey))

        for i in range(3): # Username validation loop

            # Getting client username
            username_buffer = client_socket.recv(1024)

            # Decrypting username
            username = rsa.decrypt(username_buffer, privkey).decode('utf-8').strip()

            # Checks if there's any forbidden character or similar username
            if not username or (set(username) & set(self.invalid_characters)) or username in self.users.keys() or username in self.default_users:
                client_socket.send(rsa.encrypt(self.control_responses['invalid_username'], client_pubkey))
            else:
                break

        else: # Maximum tries = 3
            self.admin_panel.print('[*] %s:%s reached maximum username tries, Closing this thread...' % (client_addr[0], client_addr[1]))
            client_socket.send(rsa.encrypt(self.control_responses['username_limit'], client_pubkey))
            client_socket.close()
            return 0

        # Username was valid
        client_socket.send(rsa.encrypt(self.control_responses['valid_username'], client_pubkey))
        self.admin_panel.print('[*] %s:%s is associated with the username "%s" from now on.' % (client_addr[0], client_addr[1], username))

        # Adding user to the users dictionary
        self.users[username] = client_socket
        self.users_public_keys[username] = client_pubkey

        # Announcing this user login
        self.admin_panel.print('\n[*] %s entered the chat' % username)
        self.broadcast(username, '%s entered the chat' % username)

        # Starting to recieve this user's messages
        while True:
            try:
                # Receiving new messages from client
                encrypted_message = client_socket.recv(4096)

                # Decrypting the message and decoding from bytes
                message = rsa.decrypt(encrypted_message, privkey)

                # Check if the user wants to leave the chat
                if message == self.control_responses['leave_message']:
                    self.admin_panel.print('\n%s left the server' % username)
                    self.broadcast(username, '%s left the server' % username)
                    client_socket.close()
                    self.users.pop(username)
                    return 0

                # If message is a file
                elif message == b'#FILE#':
                    # Broadcasting that this user is sending a file
                    self.broadcast(username, '#FILE#')

                    # Receiving file name
                    file_name_encrypted = client_socket.recv(4096)
                    file_name = rsa.decrypt(file_name_encrypted, privkey).decode('utf-8')

                    self.admin_panel.print('[*] %s is sending a file called %s' % (username, file_name))

                    # Receiving file
                    data = b''
                    encrypted_file = b''
                    while True:
                        data = client_socket.recv(4096)
                        if b'#EndOfFile#' in data:
                            encrypted_file += data[:-11]
                            break
                        elif data == b'#FAILED#':
                            self.broadcast(username, 'Failed to upload the file')
                            continue
                        else:
                            encrypted_file += data

                    decrypted_file = self.AES_Cipher.decrypt_file(encrypted_file)
                    self.saveFile(file_name, decrypted_file)

                    # File received
                    if username in self.muted_users:
                        self.admin_panel.print('[*] A new file from %s named %s is on the server. But unfortunately he is muted. Only you have access to this file.' % (username, file_name))
                        continue

                    self.admin_panel.print('[*] A new file from %s named %s is on the server. Sending to others...' % (username, file_name))

                    # Preparing Others to receive the file
                    self.broadcast(username, '#FILERECEIVED#:%s' % file_name)

                    # Sendong the file
                    self.broadcast(username, encrypted_file, 'file')
                    continue
                else:
                    # If message is a text
                    self.broadcast(username, message.decode('utf-8'))

            except Exception as e:
                if username in self.users.keys():
                    exc_type, exc_obj, exc_tb = exc_info()
                    self.admin_panel.print("Couldn't keep %s connected anymore. An unexpected error happened:" % username)
                    self.admin_panel.print('%s, %s, line: %s' % (str(e), str(exc_type), str(exc_tb.tb_lineno)))
                    self.broadcast(username, '#LostConnection#')
                    client_socket.close()
                    self.users.pop(username)
                    self.users_public_keys.pop(username)
                return 0

    def broadcast(self, username, message, content_mode = 'text'):
        # Won't send the message if the sender is mute
        if username in self.muted_users:
            return 0

        # Sending encrypted file type message for all users
        if content_mode == 'file':
            for user in self.users.keys():
                if user != username:
                    sending_thread = TracableThreading.TracableThread(target = self.send_file, args = (self.users[user], message,))
                    sending_thread.start()
        else:
            # Sending encrypted text type message for all users

            # Modifying message
            if message == "#FILE#":
                # File broadcast
                modified_message = '#FILE#:[*] %s is uploading a file...' % username
            elif message.split(':')[0] == '#FILERECEIVED#':
                # Recieved a file
                modified_message = "%s:[*] %s's file is received. Downloading..." % (message, username)
            elif message == '#LostConnection#':
                modified_message = '[INFO] %s got into a problem. Server had to disconnect him.' % username
            else:
                # Normal text
                modified_message = '[%s] %s' % (username, message)
            for user in self.users.keys():
                if user != username:
                    encrypted_message = rsa.encrypt(modified_message.encode('utf-8'), self.users_public_keys[user])
                    self.users[user].send(encrypted_message)

    def send_file(self, client, data):
        try:
            client.send(data)
            client.send(b'#EndOfFile#')
            return 1
        except:
            return 0

    def saveFile(self, file_name, file_data):
        try:
            # Extracting the file extension
            filename, file_extension = os.path.splitext(file_name)

            newname = filename + "_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + file_extension

            if not os.path.exists("server_files"):
                os.mkdir("server_files")

            with open(os.path.join("server_files", newname), "wb") as newFile:
                newFile.write(file_data)

            self.admin_panel.print("[*] File \"%s\" is saved under server_files directory" % (newname))
        except Exception as e:
            self.admin_panel.print("[*] Couldn't save the file")
            self.admin_panel.print(str(e))

    def KickUser(self, user_client, username):
        try:
            user_client.send(rsa.encrypt(self.control_responses['kicked'], self.users_public_keys[username]))
            user_client.close()
            self.users.pop(username)
            self.users_public_keys.pop(username)
            self.admin_panel.print('%s got kicked from the chat successfuly.' % username)
            self.broadcast('INFO', '%s got kicked from the chat' % username)
            return 1
        except Exception as e:
            self.admin_panel.print('There was a problem removing %s from the chat' % username)
            self.admin_panel.print(str(e))
            return 0

    def MuteUser(self, username):
        self.muted_users.append(username)
        self.admin_panel.print("%s got muted successfuly" % username)
        self.broadcast('INFO', '%s got muted by the admin' % username)
        return 1

    def UnMuteUser(self, username):
        self.muted_users.remove(username)
        self.admin_panel.print("%s got unmuted successfuly" % username)
        self.broadcast('INFO', '%s is unmuted' % username)
        return 1

    def close(self):
        try:
            # Killing server's main thread
            self.server_thread.kill()
            self.server_thread.join()
            if not self.server_thread.is_alive():
                self.admin_panel.print('Server main thread is terminated, killing user threads...')
            else:
                self.admin_panel.print("Failed to terminate server's main thread... You have to take the server down manually.")

            # Terminating users connections to server
            for user in self.users.keys():
                self.users[user].send(rsa.encrypt(self.control_responses['server_down'], self.users_public_keys[user]))

            for user_thread in self.users_threads:
                user_thread.kill()
                user_thread.join()

            # All threads terminated, Closing server
            self.admin_panel.print("All user threads terminated...")
            return 1
        except:
            return 0
