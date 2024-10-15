import socket
import threading
from double_ratchet import DoubleRatchet

# Menyimpan informasi chatroom dan klien
chatrooms = {}  # {chatroom_password: set(username)}
addr_chatroom_map = {}  # {client_address: chatroom_password}
clients = []  # List of tuples (client_address, username)
initial_key = b"this_is_an_initial_key__32bytes!"
ratchets = {}  # {client_address: DoubleRatchet instance}

def handle_client(data, addr, server_socket):
    if addr not in ratchets:
        ratchets[addr] = DoubleRatchet(initial_key)

    try:
        decrypted_message = ratchets[addr].decrypt(data).decode('utf-8')
        print(f"Decrypted Message from {addr}: {decrypted_message}")

        tag, actual_message = decrypted_message.split(' ', 1)

        if tag == "AUTH":
            key, value = actual_message.split(' ', 1)
            if key == "PASSWORD":
                chatroom_password = value
                if chatroom_password not in chatrooms:
                    chatrooms[chatroom_password] = set()
                addr_chatroom_map[addr] = chatroom_password
            elif key == "USERNAME":
                chatroom_password = addr_chatroom_map[addr]
                if value in chatrooms[chatroom_password]:
                    # Username sudah digunakan, kirim 'USERNAME_TAKEN' terenkripsi
                    encrypted_response = ratchets[addr].encrypt(b"USERNAME_TAKEN")
                    server_socket.sendto(encrypted_response, addr)
                else:
                    chatrooms[chatroom_password].add(value)
                    encrypted_response = ratchets[addr].encrypt(b"USERNAME_OK")
                    server_socket.sendto(encrypted_response, addr)
                    clients.append((addr, value))
                    print(f"User {value} has joined the chatroom.")

                    # Notifikasi ke klien lain di chatroom yang sama
                    notification = f"NOTIFY {value} telah bergabung ke chatroom."
                    for client_addr, _ in clients:
                        if client_addr != addr and addr_chatroom_map[client_addr] == chatroom_password:
                            # Pastikan ratchet untuk client_addr ada
                            if client_addr not in ratchets:
                                ratchets[client_addr] = DoubleRatchet(initial_key)
                            encrypted_notification = ratchets[client_addr].encrypt(notification.encode('utf-8'))
                            server_socket.sendto(encrypted_notification, client_addr)
        elif tag == "CHAT":
            print(f"Forwarding message: {decrypted_message}")
            chatroom_password = addr_chatroom_map[addr]
            sender_username = None
            for client_addr, username in clients:
                if client_addr == addr:
                    sender_username = username
                    break

            if sender_username is None:
                print(f"Unknown sender {addr}")
                return

            # Kirim pesan ke semua klien lain di chatroom yang sama
            for client_addr, _ in clients:
                if client_addr != addr and addr_chatroom_map[client_addr] == chatroom_password:
                    # Pastikan ratchet untuk client_addr ada
                    if client_addr not in ratchets:
                        ratchets[client_addr] = DoubleRatchet(initial_key)
                    # Enkripsi pesan asli (plaintext) untuk setiap klien
                    encrypted_message = ratchets[client_addr].encrypt(decrypted_message.encode('utf-8'))
                    server_socket.sendto(encrypted_message, client_addr)
    except Exception as e:
        print(f"Error handling message from {addr}: {e}")

def main():
    server_ip = '0.0.0.0'  # Listen on all interfaces
    server_port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))
    print(f"Server running on {server_ip}:{server_port}")

    while True:
        try:
            data, addr = server_socket.recvfrom(4096)
            threading.Thread(target=handle_client, args=(data, addr, server_socket)).start()
        except KeyboardInterrupt:
            print("\nServer shutting down.")
            break
        except Exception as e:
            print(f"Error in main loop: {e}")

    server_socket.close()

if __name__ == "__main__":
    main()
