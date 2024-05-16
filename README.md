# GreenSignal - A Secure Chat Server

GreenSignal is a secure chat server that utilizes AES and RSA encryption protocols to ensure the confidentiality and integrity of communication between clients and the server. The server is designed to be robust, efficient, and user-friendly, providing a seamless experience for users while prioritizing security.

## Features

- **Secure Communication**: GreenSignal employs AES and RSA encryption protocols to encrypt all communication between clients and the server, ensuring that messages are protected from unauthorized access.
- **User Authentication**: Users are required to authenticate with a valid username before joining the chat server, preventing unauthorized access.
- **Admin Controls**: The server administrator has control over various functionalities, such as kicking or muting users, broadcasting messages, and closing the server.
- **File Transfer**: GreenSignal supports secure file transfers between clients, allowing users to share files within the chat environment.
- **User Management**: The server keeps track of connected users and provides the administrator with the ability to view and manage user connections.

## Installation

To install and run EagleEye on your system, follow these steps:

1. Clone the repository: `git clone https://github.com/erfangolpour/GreenSignal.git`
2. Navigate to the project directory: `cd EagleEye`
3. Install the required dependencies: `pip install -r requirements.txt`

## Usage

### Starting the Server

To start the GreenSignal server, run the following command:

```
python server.py
```

This will launch the server, and you will be presented with the admin panel. From here, you can manage the server and connected users.

### Connecting as a Client

To connect to the GreenSignal server as a client, run the following command:

```
python client.py
```

You will be prompted to enter a username. Once authenticated, you can participate in the chat and exchange messages with other connected clients.

## Admin Panel Commands

The admin panel provides the following commands for server management:

- `show users`: List all currently connected users.
- `kick [user]`: Kick a specified user from the server.
- `mute [user]`: Mute a specified user, preventing them from sending messages.
- `unmute [user]`: Unmute a previously muted user.
- `broadcast [message]`: Broadcast a message to all connected users.
- `close server`: Shut down the server and disconnect all users.
- `clear`: Clear the admin panel screen.
- `help`: Display a list of available commands.

## Screenshots:
<img alt="Screenshots" src="ScreenShots/Screenshot at 2020-10-06 17-47-21.png">
<img alt="Screenshots" src="ScreenShots/Screenshot at 2020-10-06 17-52-44.png">
<img alt="Screenshots" src="ScreenShots/Screenshot at 2020-10-06 18-14-32.png">

## Security Considerations

GreenSignal is designed with security in mind, but it's important to follow best practices to ensure the system remains secure:

- Keep the server software and dependencies up to date.
- Restrict access to the server and admin panel to authorized users only.
- Regularly monitor server logs and activity for any suspicious behavior.

## Contributing

Contributions to GreenSignal are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on the project's GitHub repository.

## License

GreenSignal is released under the [GPLv3 License](LICENSE).
