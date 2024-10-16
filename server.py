import socket
import sys

# Mengimpor fungsi-fungsi RSA dari rsa.py
from rsa import generate_keypair, encrypt, decrypt

# ===============================
# Fungsi Server
# ===============================

def run_server():
    client_keys = {}            # {addr: public_key}
    clients = []                # List of tuples (addr, username)
    addr_chatroom_map = {}      # {addr: chatroom_password}
    chatrooms = {}              # {chatroom_password: set(username)}

    server_ip = '0.0.0.0'
    server_port = get_server_port()         # Port default

    # Membuat socket UDP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))

    print("Menghasilkan kunci RSA server...")
    public_key, private_key = generate_keypair()

    print(f"Server berjalan di {server_ip}:{server_port}")
    print("Menunggu klien untuk terhubung...")

    try:
        while True:
            data, addr = server_socket.recvfrom(65536)
            handle_packet(data, addr, server_socket, public_key, private_key, client_keys, clients, addr_chatroom_map, chatrooms)
    except KeyboardInterrupt:
        print("\nServer dimatikan.")
    except Exception as e:
        print(f"Error dalam loop utama: {e}")
    finally:
        server_socket.close()

def handle_packet(data, addr, server_socket, public_key, private_key, client_keys, clients, addr_chatroom_map, chatrooms):
    try:
        if data == b"REQUEST_PUBLIC_KEY":
            # Mengirim kunci publik server ke klien
            server_socket.sendto(str(public_key[0]).encode('utf-8'), addr)
            server_socket.sendto(str(public_key[1]).encode('utf-8'), addr)
        elif data == b"VALIDATE_IP":
            # Mengirim respon bahwa IP valid
            server_socket.sendto(b"IP_VALID", addr)
        elif addr not in client_keys:
            # Menerima kunci publik klien
            client_public_key_e = int(data.decode('utf-8'))
            data, _ = server_socket.recvfrom(65536)
            client_public_key_n = int(data.decode('utf-8'))
            client_keys[addr] = (client_public_key_e, client_public_key_n)
            print(f"[DEBUG] Menerima kunci publik dari {addr}: {client_keys[addr]}")
        else:
            # Menerima pesan terenkripsi dari klien
            ciphertext = eval(data.decode('utf-8'))
            message = decrypt(private_key, ciphertext)
            print(f"[DEBUG] Pesan didekripsi dari {addr}: {message}")
            process_message(addr, message, server_socket, client_keys, clients, addr_chatroom_map, chatrooms)
    except Exception as e:
        print(f"Error menangani paket dari {addr}: {e}")

def process_message(addr, message, server_socket, client_keys, clients, addr_chatroom_map, chatrooms):
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
                    send_response(server_socket, client_keys[addr], addr, "AUTH_FAILED")
                    return
                if value in chatrooms[chatroom_password]:
                    send_response(server_socket, client_keys[addr], addr, "USERNAME_TAKEN")
                else:
                    chatrooms[chatroom_password].add(value)
                    clients.append((addr, value))
                    send_response(server_socket, client_keys[addr], addr, "USERNAME_OK")
                    print(f"User {value} telah bergabung ke chatroom.")

                    # Notifikasi ke klien lain di chatroom yang sama
                    notify_clients(clients, addr, f"NOTIFY {value} telah bergabung ke chatroom.", server_socket, client_keys, addr_chatroom_map, chatroom_password)
            else:
                send_response(server_socket, client_keys[addr], addr, "AUTH_FAILED")
        elif tag == "CHAT":
            chatroom_password = addr_chatroom_map.get(addr)
            if chatroom_password:
                # Meneruskan pesan ke klien lain di chatroom yang sama
                notify_clients(clients, addr, message, server_socket, client_keys, addr_chatroom_map, chatroom_password)
        else:
            print(f"[DEBUG] Tag tidak dikenal dari {addr}: {tag}")
    except Exception as e:
        print(f"Error memproses pesan dari {addr}: {e}")

def send_response(server_socket, client_public_key, addr, response):
    """Mengenkripsi dan mengirim respons ke klien."""
    encrypted_response = encrypt(client_public_key, response)
    server_socket.sendto(str(encrypted_response).encode('utf-8'), addr)

def notify_clients(clients, sender_addr, message, server_socket, client_keys, addr_chatroom_map, chatroom_password):
    """Mengirim notifikasi ke klien lain di chatroom yang sama."""
    for client_addr, _ in clients:
        if client_addr != sender_addr and addr_chatroom_map.get(client_addr) == chatroom_password:
            encrypted_message = encrypt(client_keys[client_addr], message)
            server_socket.sendto(str(encrypted_message).encode('utf-8'), client_addr)

def get_server_port():
    while True:
        try:
            port = int(input("Masukkan port server (1-65535): ").strip())
            if 1 <= port <= 65535:
                return port
            else:
                print("Port harus berada dalam rentang 1-65535.")
        except ValueError:
            print("Input tidak valid. Silakan masukkan angka.")


if __name__ == "__main__":
    run_server()
