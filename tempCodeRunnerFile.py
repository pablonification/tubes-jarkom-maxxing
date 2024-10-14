import socket
import threading

clients = []
def handle_client(data, addr, server_socket):
    message = data.decode('utf-8')
    print(f"Received message from {addr}: {message}")
    
    if message.startswith("AUTH"):
        # Hanya mencetak pesan otentikasi dan tidak meneruskan ke client lain
        print(f"Client {addr} is authenticating.")
    elif message.startswith("CHAT"):
        # Meneruskan pesan chat ke semua client lain
        for client in clients:
            if client != addr:
                server_socket.sendto(data, client)

def main():
    server_ip = '127.0.0.1' # Listening to all interface
    server_port = 1234

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))

    print(f"Server is starting and listening on {server_ip}:{server_port}")

    while True:
        data, addr = server_socket.recvfrom(1024)
        if addr not in clients:
            clients.append(addr)
            print(f"New clients are detected and joined : {addr}")
        threading.Thread(target=handle_client, args=(data, addr, server_socket)).start()


if __name__ == "__main__":
    main()