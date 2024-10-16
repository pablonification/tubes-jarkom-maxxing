import socket
import threading
from rsa import generate_keypair, encrypt, decrypt

client_keys = {}  # {addr: public_key}
clients = []  # List of tuples (addr, username)
addr_chatroom_map = {}  # {addr: chatroom_password}
chatrooms = {}  # {chatroom_password: set(username)}

def handle_client(addr, server_socket):
    global public_key, private_key
    try:
        data, _ = server_socket.recvfrom(65536)
        if data == b"REQUEST_PUBLIC_KEY":
            # Kirim kunci publik server ke klien
            server_socket.sendto(str(public_key[0]).encode('utf-8'), addr)
            server_socket.sendto(str(public_key[1]).encode('utf-8'), addr)
        else:
            # Menerima kunci publik klien
            client_public_key_e = int(data.decode('utf-8'))
            data, _ = server_socket.recvfrom(65536)
            client_public_key_n = int(data.decode('utf-8'))
            client_public_key = (client_public_key_e, client_public_key_n)
            client_keys[addr] = client_public_key
            print(f"[DEBUG] Received public key from {addr}: {client_public_key}")
    except Exception as e:
        print(f"Error receiving public key from {addr}: {e}")
        return

    while True:
        try:
            data, _ = server_socket.recvfrom(65536)
            if not data:
                break
            # Data yang diterima adalah ciphertext terenkripsi
            ciphertext = eval(data.decode('utf-8'))
            message = decrypt(private_key, ciphertext)
            print(f"[DEBUG] Decrypted Message from {addr}: {message}")
            tag, actual_message = message.split(' ', 1)

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
                        response = "USERNAME_TAKEN"
                        encrypted_response = encrypt(client_keys[addr], response)
                        print(f"[DEBUG] Encrypted USERNAME_TAKEN to {addr}: {encrypted_response}")
                        server_socket.sendto(str(encrypted_response).encode('utf-8'), addr)
                    else:
                        chatrooms[chatroom_password].add(value)
                        response = "USERNAME_OK"
                        encrypted_response = encrypt(client_keys[addr], response)
                        print(f"[DEBUG] Encrypted USERNAME_OK to {addr}: {encrypted_response}")
                        server_socket.sendto(str(encrypted_response).encode('utf-8'), addr)
                        clients.append((addr, value))
                        print(f"User {value} has joined the chatroom.")

                        # Notifikasi ke klien lain
                        notification = f"NOTIFY {value} telah bergabung ke chatroom."
                        for client_addr, _ in clients:
                            if client_addr != addr and addr_chatroom_map[client_addr] == chatroom_password:
                                encrypted_notification = encrypt(client_keys[client_addr], notification)
                                print(f"[DEBUG] Encrypted NOTIFY to {client_addr}: {encrypted_notification}")
                                server_socket.sendto(str(encrypted_notification).encode('utf-8'), client_addr)
                else:
                    response = "AUTH_FAILED"
                    encrypted_response = encrypt(client_keys[addr], response)
                    print(f"[DEBUG] Encrypted AUTH_FAILED to {addr}: {encrypted_response}")
                    server_socket.sendto(str(encrypted_response).encode('utf-8'), addr)
            elif tag == "CHAT":
                print(f"[DEBUG] Forwarding message: {message}")
                chatroom_password = addr_chatroom_map[addr]

                for client_addr, _ in clients:
                    if client_addr != addr and addr_chatroom_map[client_addr] == chatroom_password:
                        encrypted_message = encrypt(client_keys[client_addr], message)
                        print(f"[DEBUG] Encrypted CHAT to {client_addr}: {encrypted_message}")
                        server_socket.sendto(str(encrypted_message).encode('utf-8'), client_addr)
            else:
                print(f"[DEBUG] Unknown tag from {addr}: {tag}")
        except Exception as e:
            print(f"Error handling message from {addr}: {e}")
            break

def handle_packet(data, addr, server_socket):
    global public_key, private_key
    try:
        if data == b"REQUEST_PUBLIC_KEY":
            # Kirim kunci publik server ke klien
            server_socket.sendto(str(public_key[0]).encode('utf-8'), addr)
            server_socket.sendto(str(public_key[1]).encode('utf-8'), addr)
        elif addr not in client_keys:
            # Menerima kunci publik klien
            client_public_key_e = int(data.decode('utf-8'))
            data, addr = server_socket.recvfrom(65536)
            client_public_key_n = int(data.decode('utf-8'))
            client_public_key = (client_public_key_e, client_public_key_n)
            client_keys[addr] = client_public_key
            print(f"[DEBUG] Received public key from {addr}: {client_public_key}")
        else:
            # Data pesan terenkripsi
            ciphertext = eval(data.decode('utf-8'))
            message = decrypt(private_key, ciphertext)
            print(f"[DEBUG] Decrypted Message from {addr}: {message}")
            # Proses pesan seperti sebelumnya
            process_message(addr, message, server_socket)
    except Exception as e:
        print(f"Error handling packet from {addr}: {e}")


def process_message(addr, message, server_socket):
    global client_keys, clients, addr_chatroom_map, chatrooms
    try:
        tag, actual_message = message.split(' ', 1)

        if tag == "AUTH":
            key, value = actual_message.split(' ', 1)
            if key == "PASSWORD":
                chatroom_password = value
                if chatroom_password not in chatrooms:
                    chatrooms[chatroom_password] = set()
                addr_chatroom_map[addr] = chatroom_password
            elif key == "USERNAME":
                chatroom_password = addr_chatroom_map.get(addr)
                if chatroom_password is None:
                    response = "AUTH_FAILED"
                    encrypted_response = encrypt(client_keys[addr], response)
                    server_socket.sendto(str(encrypted_response).encode('utf-8'), addr)
                    return
                if value in chatrooms[chatroom_password]:
                    response = "USERNAME_TAKEN"
                    encrypted_response = encrypt(client_keys[addr], response)
                    print(f"[DEBUG] Encrypted USERNAME_TAKEN to {addr}: {encrypted_response}")
                    server_socket.sendto(str(encrypted_response).encode('utf-8'), addr)
                else:
                    chatrooms[chatroom_password].add(value)
                    response = "USERNAME_OK"
                    encrypted_response = encrypt(client_keys[addr], response)
                    print(f"[DEBUG] Encrypted USERNAME_OK to {addr}: {encrypted_response}")
                    server_socket.sendto(str(encrypted_response).encode('utf-8'), addr)
                    clients.append((addr, value))
                    print(f"User {value} has joined the chatroom.")

                    # Notifikasi ke klien lain
                    notification = f"NOTIFY {value} telah bergabung ke chatroom."
                    for client_addr, _ in clients:
                        if client_addr != addr and addr_chatroom_map.get(client_addr) == chatroom_password:
                            encrypted_notification = encrypt(client_keys[client_addr], notification)
                            print(f"[DEBUG] Encrypted NOTIFY to {client_addr}: {encrypted_notification}")
                            server_socket.sendto(str(encrypted_notification).encode('utf-8'), client_addr)
            else:
                response = "AUTH_FAILED"
                encrypted_response = encrypt(client_keys[addr], response)
                print(f"[DEBUG] Encrypted AUTH_FAILED to {addr}: {encrypted_response}")
                server_socket.sendto(str(encrypted_response).encode('utf-8'), addr)
        elif tag == "CHAT":
            print(f"[DEBUG] Forwarding message: {message}")
            chatroom_password = addr_chatroom_map.get(addr)
            if chatroom_password is None:
                return
            for client_addr, _ in clients:
                if client_addr != addr and addr_chatroom_map.get(client_addr) == chatroom_password:
                    encrypted_message = encrypt(client_keys[client_addr], message)
                    print(f"[DEBUG] Encrypted CHAT to {client_addr}: {encrypted_message}")
                    server_socket.sendto(str(encrypted_message).encode('utf-8'), client_addr)
        else:
            print(f"[DEBUG] Unknown tag from {addr}: {tag}")
    except Exception as e:
        print(f"Error processing message from {addr}: {e}")


def main():
    global public_key, private_key

    server_ip = '0.0.0.0'
    server_port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))

    # Menghasilkan kunci RSA server
    print("Menghasilkan kunci RSA server...")
    public_key, private_key = generate_keypair()

    print(f"Server running on {server_ip}:{server_port}")

    while True:
        try:
            data, addr = server_socket.recvfrom(65536)
            handle_packet(data, addr, server_socket)
        except KeyboardInterrupt:
            print("\nServer shutting down.")
            break
        except Exception as e:
            print(f"Error in main loop: {e}")

    server_socket.close()


if __name__ == "__main__":
    main()
