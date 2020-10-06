# Printing
from art import text2art

# Terminal GUI
from Core.Utilities.SeprateTerminal import Window

# To clear screen
from os import system

# Importing server object from ChatCore
from Core.Core import Server


# Clearing out terminal
system('clear')

# Chat server ip and port
server_ip = '127.0.0.1'
server_port = 4444

# Number of allowed users on server
user_limit = 5

# Servers Secret Key
secret_key = '003edc12e5089363c8262fcb878bca74'

# Seprating Terminal
admin_panel = Window()

# CoreChat
admin_panel.print('Welcome to')
admin_panel.print(text2art('CoreChat', 'rnd-large'))

# Establishing server
admin_panel.print('\n[*] Establishing Connection...')
server = Server(server_ip, server_port, user_limit, secret_key, admin_panel)

# Server is up
admin_panel.print('[*] Server is up!')
admin_panel.print('[*] Listening on %s:%s\n' % (server_ip, server_port))

# Command line
while True:
    command = admin_panel.ask("$Server-Admin-> ").strip()

    admin_panel.print('\n', end = '')

    if not command:
        continue
    elif command.lower() == 'show users':
        if server.users:
            for user in server.users.keys():
                admin_panel.print("%s : %s\n" % (user, server.users[user]))
        else:
            admin_panel.print("[No one is currently in the server]")
    elif command[:4].lower() == 'kick':
        # Exporting username from command
        user_to_kick = command[5:]

        # Check if user exists
        try:
            user_client = server.users[user_to_kick]
        except:
            admin_panel.print("[!] Username doesn't exist\n")
            continue

        # Try to kick user
        server.KickUser(user_client, user_to_kick)

    elif command[:4].lower() == 'mute':
        # Exporting username from command
        user_to_mute = command[5:]

        # Check if user exists and is not muted already        
        if user_to_mute not in server.users.keys():
            admin_panel.print("[!] Couldn't find the user")
        elif user_to_mute in server.muted_users:
            admin_panel.print("[!] This user is already muted")
        else:
            # Try to mute the user
            server.MuteUser(user_to_mute)
    elif command[:6].lower() == 'unmute':
        # Exporting username from command
        user_to_unmute = command[7:]

        # Check if user exists and is not unmuted already
        if user_to_unmute not in server.users.keys():
            admin_panel.print("[!] Couldn't find the user")
        elif user_to_unmute not in server.muted_users:
            admin_panel.print("[!] This user isn't muted")
        else:
            # Try to unmute the user
            server.UnMuteUser(user_to_unmute)
    elif command[:9].lower() == 'broadcast':
        admin_msg = command[10:]
        server.broadcast('ADMIN', admin_msg)
        admin_panel.print('Broadcasted %s from [ADMIN]' % admin_msg)
    elif command.lower() == 'close server':
        if server.close():
            admin_panel.ask("press enter to exit...")
            admin_panel.close()
            exit(0)
        else:
            admin_panel.print("Failed to close the server, you have to close it manually.")
            close_panel = admin_panel.ask("Exit the panel without closing other thread?(y/n)")
            if close_panel.lower() == 'y':
                admin_panel.close()
                exit(0)
    elif command.lower() == 'clear':
        admin_panel.clear()
    elif command.lower() == 'help':
        admin_panel.print("List of Available Commands:                                                             ")
        admin_panel.print("show users          - To get a list of current active users                             ")
        admin_panel.print("kick [user]         - To kick a user from the server                                    ")
        admin_panel.print("mute [user]         - To mute a user                                                    ")
        admin_panel.print("unmute [user]       - To unmute a user                                                  ")
        admin_panel.print("broadcast [message] - To send a message to all the users                                ")
        admin_panel.print("close server        - To close the server (all users will be disconnected automatically)")
        admin_panel.print("clear               - To clear the screen                                               ")
        admin_panel.print("help                - shows this text                                                   ")
    else:
        admin_panel.print("Command not found. Use 'help' command to get a list of available commands.")

    admin_panel.print('\n', end = '')
