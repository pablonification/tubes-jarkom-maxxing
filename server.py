import socket
import threading

clients = []

def handle_client(data, addr, server_socket):
    message = data.decode('utf-8')
    print(f"Received message from {addr}: {message}")

    # Pisahkan tag dari pesan
    tag, actual_message = message.split(' ', 1)

    # Jika tag adalah CHAT, maka diteruskan ke client lain
    if tag == "CHAT":
        for client in clients:
            if client != addr:
                server_socket.sendto(data, client)

def main():
    server_ip = '10.31.103.70'  # Mendengarkan pada semua interface
    server_port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))
    
    print(f"Server started at {server_ip}:{server_port}")

    while True:
        data, addr = server_socket.recvfrom(1024)
        if addr not in clients:
            clients.append(addr)
            print(f"New client joined: {addr}")
        threading.Thread(target=handle_client, args=(data, addr, server_socket)).start()

if __name__ == "__main__":
    main()
