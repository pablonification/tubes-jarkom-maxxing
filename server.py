import socket
import threading

chatrooms = {}  # Dictionary untuk menyimpan chatroom dan username
addr_chatroom_map = {}  # Map antara alamat client dengan chatroom yang diikuti
clients = []

def handle_client(data, addr, server_socket):
    message = data.decode('utf-8')
    print(f"Received message from {addr}: {message}")

    # Pisahkan tag dari pesan
    tag, actual_message = message.split(' ', 1)

    if tag == "AUTH":
        key, value = actual_message.split(' ', 1)
        if key == "PASSWORD":
            # Simpan password chatroom untuk alamat client
            chatroom_password = value
            if chatroom_password not in chatrooms:
                chatrooms[chatroom_password] = set()
            addr_chatroom_map[addr] = chatroom_password
        elif key == "USERNAME":
            chatroom_password = addr_chatroom_map[addr]
            if value in chatrooms[chatroom_password]:
                server_socket.sendto("USERNAME_TAKEN".encode('utf-8'), addr)
            else:
                chatrooms[chatroom_password].add(value)
                server_socket.sendto("USERNAME_OK".encode('utf-8'), addr)
                clients.append((addr, value))
                print(f"New client joined: {addr} with username {value} in chatroom {chatroom_password}")

    # Jika tag adalah CHAT, maka diteruskan ke client lain dalam chatroom yang sama
    elif tag == "CHAT":
        chatroom_password = addr_chatroom_map[addr]
        for client, client_username in clients:
            if client != addr and addr_chatroom_map[client] == chatroom_password:
                server_socket.sendto(data, client)

def main():
    server_ip = '0.0.0.0'  # Mendengarkan pada semua interface
    server_port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))
    
    print(f"Server started at {server_ip}:{server_port}")

    while True:
        data, addr = server_socket.recvfrom(1024)
        threading.Thread(target=handle_client, args=(data, addr, server_socket)).start()

if __name__ == "__main__":
    main()