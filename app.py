import socket
import threading
import sys
import random

# ===============================
# Implementasi RSA
# (sama seperti sebelumnya)
# ===============================

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def is_prime(n):
    if n <= 1:
        return False
    for _ in range(5):
        a = random.randint(2, n - 1)
        if gcd(a, n) != 1:
            return False
        if pow(a, n - 1, n) != 1:
            return False
    return True

def generate_prime_candidate(length):
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1  # Pastikan bit teratas dan terendah adalah 1
    return p

def generate_prime_number(length=512):
    p = 4
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None
    else:
        return x % m

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def generate_keypair(keysize=512):
    e = 65537
    p = generate_prime_number(keysize // 2)
    q = generate_prime_number(keysize // 2)
    while q == p:
        q = generate_prime_number(keysize // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        raise Exception('e dan phi(n) tidak relatif prima.')

    d = modinv(e, phi)
    if d is None:
        raise Exception('Gagal menghitung modular inverse.')

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key

def encrypt(pk, plaintext):
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    key, n = pk
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    return ''.join(plain)

# ===============================
# Fungsi untuk Mendapatkan IP Lokal
# ===============================

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Menghubungkan ke alamat IP publik
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

# ===============================
# Fungsi Server
# ===============================

def run_server():
    client_keys = {}  # {addr: public_key}
    clients = []  # List of tuples (addr, username)
    addr_chatroom_map = {}  # {addr: chatroom_password}
    chatrooms = {}  # {chatroom_password: set(username)}

    server_ip = '0.0.0.0'
    server_port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))

    # Menghasilkan kunci RSA server
    print("Menghasilkan kunci RSA server...")
    public_key, private_key = generate_keypair()

    # Mendapatkan IP lokal server
    local_ip = get_local_ip()
    print(f"Server running on IP: {local_ip}, Port: {server_port}")

    print("Menunggu klien untuk terhubung...")

    while True:
        try:
            data, addr = server_socket.recvfrom(65536)
            handle_packet(data, addr, server_socket, public_key, private_key, client_keys, clients, addr_chatroom_map, chatrooms)
        except KeyboardInterrupt:
            print("\nServer shutting down.")
            break
        except Exception as e:
            print(f"Error in main loop: {e}")

    server_socket.close()

def handle_packet(data, addr, server_socket, public_key, private_key, client_keys, clients, addr_chatroom_map, chatrooms):
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
            # Proses pesan
            process_message(addr, message, server_socket, private_key, client_keys, clients, addr_chatroom_map, chatrooms)
    except Exception as e:
        print(f"Error handling packet from {addr}: {e}")

def process_message(addr, message, server_socket, private_key, client_keys, clients, addr_chatroom_map, chatrooms):
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

# ===============================
# Fungsi Klien
# ===============================

def run_client():
    global server_ip, server_port, server_public_key
    server_choice = input("Apakah Anda ingin menggunakan IP server Anda sendiri? (y/n): ").strip().lower()
    if server_choice == 'y':
        # Mendapatkan IP lokal menggunakan fungsi get_local_ip()
        server_ip = get_local_ip()
        print(f"Menggunakan IP lokal Anda sebagai server: {server_ip}")
    else:
        server_ip = input("Masukkan IP server: ")

    server_port_input = input("Masukkan port server (default 12345): ").strip()
    if server_port_input == '':
        server_port = 12345
    else:
        server_port = int(server_port_input)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("Menghasilkan kunci RSA klien...")
    public_key, private_key = generate_keypair()

    print("Menerima kunci publik server...")
    client_socket.sendto(b"REQUEST_PUBLIC_KEY", (server_ip, server_port))
    server_public_key_e, _ = client_socket.recvfrom(65536)
    server_public_key_n, _ = client_socket.recvfrom(65536)
    server_public_key_e = int(server_public_key_e.decode('utf-8'))
    server_public_key_n = int(server_public_key_n.decode('utf-8'))
    server_public_key = (server_public_key_e, server_public_key_n)

    client_socket.sendto(str(public_key[0]).encode('utf-8'), (server_ip, server_port))
    client_socket.sendto(str(public_key[1]).encode('utf-8'), (server_ip, server_port))

    chatroom_password = input("Masukkan password chatroom: ")
    encrypted_message = encrypt(server_public_key, f"AUTH PASSWORD {chatroom_password}")
    client_socket.sendto(str(encrypted_message).encode('utf-8'), (server_ip, server_port))

    while True:
        username = input("Masukkan username Anda: ")
        if username.strip() == "":
            print("Username tidak boleh kosong.")
            continue
        encrypted_message = encrypt(server_public_key, f"AUTH USERNAME {username}")
        client_socket.sendto(str(encrypted_message).encode('utf-8'), (server_ip, server_port))

        data, _ = client_socket.recvfrom(65536)
        ciphertext = eval(data.decode('utf-8'))
        response = decrypt(private_key, ciphertext)

        if response == "USERNAME_OK":
            print("Username diterima. Ketik '/exit' untuk keluar dari chat.")
            break
        elif response == "USERNAME_TAKEN":
            print("Username sudah digunakan.")
        elif response == "AUTH_FAILED":
            print("Password salah.")
            sys.exit()
        else:
            print(f"Unknown response: {response}")
            sys.exit()

    stop_event = threading.Event()
    recv_thread = threading.Thread(
        target=receive_messages, args=(client_socket, private_key, stop_event), daemon=True
    )
    recv_thread.start()

    send_messages(client_socket, server_public_key, username, stop_event)

    recv_thread.join()
    client_socket.close()

def receive_messages(client_socket, private_key, stop_event):
    while not stop_event.is_set():
        try:
            data, _ = client_socket.recvfrom(65536)
            if not data:
                break
            ciphertext = eval(data.decode('utf-8'))
            message = decrypt(private_key, ciphertext)
            tag, actual_message = message.split(' ', 1)

            if tag == "CHAT" or tag == "NOTIFY":
                print('\r' + ' ' * 80 + '\r', end='', flush=True)
                print(f"{actual_message}")
                print("You: ", end='', flush=True)
            else:
                print(f"\nServer message: {message}")
        except Exception as e:
            print(f"\nError receiving message: {e}")
            break

def send_messages(client_socket, server_public_key, username, stop_event):
    while not stop_event.is_set():
        try:
            message = input("You: ")
            if message.strip() == "":
                print("Pesan tidak boleh kosong.")
                continue
            if message.strip().lower() == '/exit':
                print("Exiting...")
                stop_event.set()
                break
            full_message = f"CHAT {username}: {message}"
            encrypted_message = encrypt(server_public_key, full_message)
            client_socket.sendto(str(encrypted_message).encode('utf-8'), (server_ip, server_port))
        except Exception as e:
            print(f"Error sending message: {e}")
            stop_event.set()
            break

# ===============================
# Bagian Utama Program
# ===============================

def main():
    run_client()

if __name__ == "__main__":
    main()
