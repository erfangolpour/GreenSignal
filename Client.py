# Connection libraries
import socket

# Printing
from art import text2art

# Threading
import threading

# Terminal GUI
from Core.Utilities.SeprateTerminal import Window

# Encryption libraries
import rsa
import base64
from Core.Encryptions.AESCipher import AESCipher

# Saving files with current time
from datetime import datetime

# Using system and path
import sys
import os

# Avoiding overflow on send function
from time import sleep


# Clearing out terminal
os.system('clear')

# Chat server ip and port
target_host = '127.0.0.1'
target_port = 4444

# Servers Secret Key
secret_key = '003edc12e5089363c8262fcb878bca74'

# Setting an AES Cipher object
AES_Cipher = AESCipher(secret_key)

# Connection Code Dictionary
control_responses = {
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


def receive_messages(client):
    global control_responses
    global kicked_from_server

    while True:
        try:
            # Receiving new messages from server
            encrypted_message = client.recv(4096)

            # Decrypting the message and decoding from bytes
            message = rsa.decrypt(encrypted_message, privkey)

            # Handling the error
            if message == control_responses['kicked']:
                kicked_from_server = True
                client.close()
                chatbox.print('\nYou got kicked from the server by admin.')
                chatbox.ask('press enter key to exit...')
                chatbox.close()
                exit(0)
            elif message == control_responses['server_down']:
                kicked_from_server = True
                client.close()
                chatbox.print('\nServer is down. Try to reconnect later.')
                chatbox.ask('press enter key to exit...')
                chatbox.close()
                exit(0)
            else:
                # Decrypting the message and decoding from bytes
                message = message.decode('utf-8')

                if message.split(':')[0] == "#FILE#":
                    # Someone's uploading a file
                    chatbox.print(message.split(":")[1])
                elif message.split(':')[0] == '#FILERECEIVED#':
                    # File is ready to download
                    chatbox.print(message.split(":")[2])

                    # Receiving file name
                    file_name = message.split(":")[1]

                    # Downloading the file
                    data = b''
                    encrypted_file = b''
                    while True:
                        data = client.recv(4096)
                        if b'#EndOfFile#' in data:
                            encrypted_file += data[:-11]
                            break
                        else:
                            encrypted_file += data

                    # Decrypting the file and decoding from bytes
                    chatbox.print('[*] Decrypting the file...')
                    decrypted_file = AES_Cipher.decrypt_file(encrypted_file)

                    # Saving the file
                    chatbox.print('[*] Saving the file...')
                    saveFile(file_name, decrypted_file) # File name and File data
                else:
                    # Normal text message
                    chatbox.print(message)
        except Exception as e:
            if kicked_from_server:
                return 0

            chatbox.print('\n[*] An unexpected error happended: %s' % str(e))
            client.close()
            chatbox.ask('press enter key to continue...')
            chatbox.close()
            exit(0)


def send_messages(client):
    global control_responses
    global kicked_from_server

    while True:
        try:
            message = chatbox.ask('[%s] ' % client_name)

            if message.lower() == 'exit()':
                client.send(rsa.encrypt(control_responses['leave_message'], server_pubkey))
                client.close()
                chatbox.close()
                exit(0)
            elif message.lower() == 'file()':
                file_name = chatbox.ask('[File Name](press enter to cancel): ')
                if file_name:
                    try:
                        sendFile(file_name, client)
                    except:
                        pass
                continue
            elif message:
                encrypted_message = rsa.encrypt(message.strip().encode('utf-8'), server_pubkey)
                client.send(encrypted_message)
                chatbox.print('[%s] %s' % (client_name, message))

        except Exception as e:
            if kicked_from_server:
                return 0

            chatbox.print('\n[*] An unexpected error happended: %s' % str(e))

            try:
                client.close()
            except:
                exit(0)

            chatbox.ask('press enter key to continue...')
            chatbox.close()
            exit(0)


def saveFile(file_name, file_data):
    try:
        # Extracting the file extension
        filename, file_extension = os.path.splitext(file_name)

        newname = filename + "_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + file_extension

        if not os.path.exists("Core_Files"):
            os.mkdir("Core_Files")

        with open(os.path.join("Core_Files", newname), "wb") as newFile:
            newFile.write(file_data)

        chatbox.print("[*] File \"%s\" is saved under Core_Files directory" % (newname))
    except:
        chatbox.print("[*] Couldn't receive the file")


def sendFile(file_name, client):
    try:
        # Info
        chatbox.print("[*] File named %s is selected" % file_name)

        # Encrypting the file
        chatbox.print("[*] Encrypting the file... (Large files may take time)")
        encrypted_file = AES_Cipher.encrypt_file(file_name)

        # Preparing the server
        chatbox.print('[*] Preparing server to receive the file')
        client.send(rsa.encrypt(b'#FILE#', server_pubkey))

        # Sending the file name
        client.send(rsa.encrypt(file_name.encode('utf-8'), server_pubkey))
        sleep(1)

        # Sending the file
        chatbox.print("[*] Sending file \"%s\"..." % file_name)
        client.send(encrypted_file)

        # File sent
        client.send(b'#EndOfFile#')

        # File sent
        chatbox.print("[*] File sent!")

        return 1

    except FileNotFoundError:
        chatbox.print("[*] File " + file_name + " does not exist.")
        return 0

    except Exception as e:
        client.send(b'#FAILED#')
        chatbox.print('\n[*] An unexpected error happended: %s' % str(e))
        chatbox.ask('press enter key to continue...')
        return 0



chatbox = Window()

kicked_from_server = False

# CoreChat
chatbox.print('Welcome to')
chatbox.print(text2art('CoreChat', 'rnd-large'))

# Asking for username
client_name = chatbox.ask("Enter a Username: ")

# Connecting to the server
chatbox.print('[*] Entering the chat at %s:%s...' % (target_host, target_port))

try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))
except:
    chatbox.print('[*] Failed to connect the server.')
    chatbox.ask('press enter key to close...')
    chatbox.close()
    exit(0)

server_state = base64.b64decode(client.recv(2048))
if server_state == control_responses['full_server']:
    chatbox.print('\n[*] Server is overcrowded right now. Try again later')
    chatbox.ask('press enter key to close...')
    chatbox.close()
    exit(0)

# The key was correct
chatbox.print("[*] You're Connected! Configuring your connection...\n")

# Encryptiong connection
chatbox.print("[*] Encrypting your connection...")

# Generating keys
(pubkey, privkey) = rsa.newkeys(1024)

# Send public key to the server
pubkey_primes = '%s#%s' % (str(pubkey.n), str(pubkey.e))
pubkey_primes_base64 = base64.b64encode(pubkey_primes.encode('utf-8'))
client.send(pubkey_primes_base64)
chatbox.print("[*] Public Key sent")

# Wait to receive server's public key
server_pubkey_primes_base64 = client.recv(2048)
server_pubkey_primes = base64.b64decode(server_pubkey_primes_base64).decode('utf-8').split('#')
server_pubkey = rsa.PublicKey(int(server_pubkey_primes[0]), int(server_pubkey_primes[1])) # Servers Public key
chatbox.print("[*] Server's Public Key received")

# Sending hashed signature to verify
chatbox.print("[*] Sending hash signature to validate the enryption...")
secret_key_hash = rsa.compute_hash(secret_key.encode('utf-8'), 'SHA-1')
chatbox.print('[*] Secret key hash: %s...' % str(secret_key_hash)[2:9])
signature = rsa.sign_hash(secret_key_hash, privkey, 'SHA-1')
chatbox.print('[*] Signature: %s...' % str(signature[:9])[2:-1])
signature_base64 = base64.b64encode(signature)
client.send(signature_base64)

# Receving servers response
data = client.recv(2048)

if base64.b64decode(data) == control_responses['encryption_failed']:
    chatbox.print("\n[*] Encryption could not be verified! Please try to reconnect...\n")
    client.close()
    chatbox.ask('press enter key to close...')
    chatbox.close()
    exit(0)

# Encryption Verified
chatbox.print("[*] Encryption Verified!")

# Sending secret key to the server
chatbox.print('[*] Sending the secret key...\n')
client.send(rsa.encrypt(secret_key.encode('utf-8'), server_pubkey))

# Receiving server response
response = client.recv(4096)

if rsa.decrypt(response, privkey) == control_responses['wrong_key']:
    # The secret key was wrong
    chatbox.print("The key was wrong, Server aborted the connection...")
    client.close()
    chatbox.ask('press enter key to close...')
    chatbox.close()
    exit(0)

elif rsa.decrypt(response, privkey) == control_responses['greeting']:

    # Sending username
    chatbox.print("Associating this connection with your username...")

    while True: # Username validation loop
        client.send(rsa.encrypt(client_name.encode('utf-8'), server_pubkey))

        # Validating username
        response = rsa.decrypt(client.recv(1024), privkey)

        if response == control_responses['invalid_username']:
            client_name = chatbox.ask("The username is invalid, try another one: ")

        elif response == control_responses['valid_username']:
            # Connection verified
            chatbox.print("\nWelcome to this chat... Have fun!\n")

            # Starting send and receive threads
            read_thread = threading.Thread(target = receive_messages, args = (client,))
            write_thread = threading.Thread(target = send_messages, args = (client,))
            read_thread.start()
            write_thread.start()
            break

        elif response == control_responses['username_limit']:
            chatbox.print("Server aborted your connection as you reached the maximum tries.")
            client.close()
            chatbox.ask('press enter key to close...')
            chatbox.close()
            exit(0)

        else:
            chatbox.print("Potensial Threat: Couldn't verify server's response. Closing the connection...")
            client.close()
            chatbox.ask('press enter key to close...')
            chatbox.close()
            exit(0)
else:
    chatbox.print("Couldn't verify the server...")
    client.close()
    chatbox.ask('press enter key to close...')
    chatbox.close()
    exit(0)
