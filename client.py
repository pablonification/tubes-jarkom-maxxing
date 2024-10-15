import socket
import threading
import sys

def receive_messages(client_socket):
    while True:
        try:
            data, _ = client_socket.recvfrom(1024)
            message = data.decode('utf-8')

            # Pisahkan tag dari pesan
            tag, actual_message = message.split(' ', 1)

            if tag == "CHAT":
                print(f"\rMessage from {actual_message}\nYou: ", end="")
        except:
            print("Error receiving message")
            break

def main():
    server_ip = input("Enter server IP: ")
    server_port = int(input("Enter server port: "))

    chatroom_password = input("Enter chatroom password: ")
    username = input("Enter your username: ")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Mengirimkan password untuk otentikasi
    client_socket.sendto(f"AUTH PASSWORD {chatroom_password}".encode('utf-8'), (server_ip, server_port))
    # Mengirimkan username untuk pengecekan
    client_socket.sendto(f"AUTH USERNAME {username}".encode('utf-8'), (server_ip, server_port))

    # Menunggu konfirmasi dari server terkait username dan password
    while True:
        data, _ = client_socket.recvfrom(1024)
        response = data.decode('utf-8')
        if response == "USERNAME_OK":
            break
        elif response == "USERNAME_TAKEN":
            username = input("Username already taken in this chatroom. Enter a different username: ")
            client_socket.sendto(f"AUTH USERNAME {username}".encode('utf-8'), (server_ip, server_port))
        elif response == "AUTH_FAILED":
            print("Incorrect chatroom password.")
            sys.exit()

    threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

    while True:
        try:
            message = input("You: ")
            if message.lower() == 'exit':
                print("Exiting...")
                break
            full_message = f"CHAT {username}: {message}"
            client_socket.sendto(full_message.encode('utf-8'), (server_ip, server_port))
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit()

if __name__ == "__main__":
    main()
