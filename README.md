

# Tugas Besar 1 Jaringan Komputer II2120: UDP Encrypted Chat Room

A **simple chat room application** that allows multiple users to communicate in real-time using **UDP sockets**. The communication is secured using **RSA encryption**, ensuring that all messages exchanged are encrypted and decrypted properly. This project demonstrates socket programming with **Python** and implements key features like authentication, unique usernames, and encrypted messaging.

## Features

- **UDP Socket Communication**: Clients communicate with the server over UDP.
- **RSA Encryption**: Ensures that all messages are encrypted and secure.
- **Authentication**: Users must enter a chatroom password to join.
- **Unique Usernames**: Users must choose a unique username.
- **Real-time Chat**: Messages are instantly forwarded to all clients in the chatroom.
- **Cross-Platform**: Works on both PC and mobile (using Termux or a Python interpreter).
- **Command to Exit**: Type `/exit` to leave the chatroom.

---

## How to Run

### Prerequisites

- **Python >= 3.10** installed on both server and client machines.
- **For Mobile Testing**: Use **Termux** or another Python interpreter for Android/iOS.

### Setup

1. **Clone the Repository**:

   ```bash
   git clone <your-repository-url>
   cd <your-repository-folder>
   ```

2. **Start the Server**:

   On your PC or any machine that will act as the server, run:

   ```bash
   python server.py
   ```

   You should see:

   ```
   Generating RSA keys...
   Server running on 0.0.0.0:12345
   ```

3. **Run the Client**:

   On another machine or mobile device (using Termux), run:

   ```bash
   python client.py
   ```

4. **Enter Server Details**:

   ```
   Enter server IP: <server-ip>
   Enter server port: 12345
   ```

5. **Join the Chatroom**:

   - Enter the chatroom password and your desired username.
   - If the username is already taken, you will be prompted to enter a new one.

6. **Start Chatting**:

   Type your messages in the client terminal. All messages will be **encrypted and decrypted** using RSA.

---

## Commands

- **Send Message**: Type a message and press Enter to send it.
- **Exit Chatroom**: Type `/exit` to leave the chatroom.

---

## Project Structure

```
├── server.py             # Server-side code to handle multiple clients
├── client.py        # Client-side code (includes RSA encryption for testing)
├── rsa.py                # RSA encryption implementation (integrated into client.py)
├── README.md             # Documentation for the project
```

---

## Example Output

### **Server Output:**

```
Generating RSA keys...
Server running on 0.0.0.0:12345
[DEBUG] Received public key from ('127.0.0.1', 54321): (e, n)
[DEBUG] Decrypted Message from ('127.0.0.1', 54321): AUTH USERNAME asep
[DEBUG] Encrypted USERNAME_OK to ('127.0.0.1', 54321): [123456789, ...]
User asep has joined the chatroom.
```

### **Client Output:**

```
Enter server IP: 127.0.0.1
Enter server port: 12345
Generating RSA keys...
Receiving public key from server...
Enter chatroom password: 1234
Enter your username: asep
Username accepted. Type '/exit' to leave the chat.

You: Hello everyone!
User budi: Hey asep!
```

---

## Troubleshooting

1. **Client Freezes After Entering IP and Port**:
   - Ensure the server is running and accessible over the network.
   - Double-check the IP address and port.

2. **Messages Not Showing Up**:
   - Verify that both the client and server are using the same encryption keys.
   - Check for any errors on the server or client terminal.

3. **Username Already Taken**:
   - Enter a new username when prompted.

---

## Security Considerations

- This project uses **RSA encryption** for educational purposes. The implementation is simplified and may not be suitable for production environments.
- Avoid using `eval()` on untrusted data; use `ast.literal_eval()` for safer parsing if needed.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contributors

- **Arqila** - Developer
- **Daniel** - Developer

---

## Acknowledgments

- Special thanks to the **Computer Networks course** for inspiring this project.
- Thanks to **Python.org** for providing tools and documentation.

---
