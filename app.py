import socket
import threading
import sys

# Mengimpor fungsi-fungsi RSA dari rsa.py
from rsa import generate_keypair, encrypt, decrypt, get_local_ip

# ===============================
# Fungsi Klien
# ===============================

def run_client():
    global server_ip, server_port, server_public_key

    # Meminta pengguna untuk memilih penggunaan IP server
    while True:
        server_choice = input("Apakah Anda ingin menggunakan IP server Anda sendiri? (y/n): ").strip().lower()
        if server_choice in ['y', 'n']:
            break
        else:
            print("Input tidak valid. Silakan masukkan 'y' atau 'n'.")

    if server_choice == 'y':
        # Menggunakan IP lokal klien
        server_ip = get_local_ip()
        print(f"Menggunakan IP lokal Anda sebagai server: {server_ip}")
    else:
        # Meminta input IP server
        while True:
            server_ip = input("Masukkan IP server: ").strip()
            if server_ip == '':
                print("IP server tidak boleh kosong. Silakan masukkan IP yang valid.")
                continue
            if validate_ip_format(server_ip):
                # Validasi apakah IP terdaftar di server
                if validate_ip_with_server(server_ip):
                    break
                else:
                    print("IP tidak ditemukan di server. Silakan coba lagi.")
            else:
                print("Format IP tidak valid. Silakan masukkan IP yang valid.")

    # Port default
    server_port = 12345

    # Membuat socket UDP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("Menghasilkan kunci RSA klien...")
    public_key, private_key = generate_keypair()

    # Mencoba terhubung ke server dan melakukan pertukaran kunci
    try:
        print("Meminta kunci publik server...")
        client_socket.sendto(b"REQUEST_PUBLIC_KEY", (server_ip, server_port))

        # Menerima kunci publik server
        server_public_key_e, _ = client_socket.recvfrom(65536)
        server_public_key_n, _ = client_socket.recvfrom(65536)
        server_public_key = (int(server_public_key_e.decode('utf-8')), int(server_public_key_n.decode('utf-8')))

        # Mengirim kunci publik klien ke server
        client_socket.sendto(str(public_key[0]).encode('utf-8'), (server_ip, server_port))
        client_socket.sendto(str(public_key[1]).encode('utf-8'), (server_ip, server_port))
    except Exception as e:
        print(f"Error saat menghubungi server di {server_ip}:{server_port}.")
        print(f"Exception: {e}")
        client_socket.close()
        sys.exit()

    # Autentikasi dengan password chatroom
    chatroom_password = input("Masukkan password chatroom: ")
    encrypted_message = encrypt(server_public_key, f"AUTH PASSWORD {chatroom_password}")
    client_socket.sendto(str(encrypted_message).encode('utf-8'), (server_ip, server_port))

    # Meminta username
    while True:
        username = input("Masukkan username Anda: ").strip()
        if username == "":
            print("Username tidak boleh kosong.")
            continue

        encrypted_message = encrypt(server_public_key, f"AUTH USERNAME {username}")
        client_socket.sendto(str(encrypted_message).encode('utf-8'), (server_ip, server_port))

        data, _ = client_socket.recvfrom(65536)
        response = decrypt(private_key, eval(data.decode('utf-8')))

        if response == "USERNAME_OK":
            print("Username diterima. Ketik '/exit' untuk keluar dari chat.")
            break
        elif response == "USERNAME_TAKEN":
            print("Username sudah digunakan. Silakan pilih username lain.")
        elif response == "AUTH_FAILED":
            print("Password salah.")
            client_socket.close()
            sys.exit()
        else:
            print(f"Respon tidak dikenal dari server: {response}")
            client_socket.close()
            sys.exit()

    # Memulai thread untuk menerima dan mengirim pesan
    stop_event = threading.Event()
    recv_thread = threading.Thread(target=receive_messages, args=(client_socket, private_key, stop_event), daemon=True)
    recv_thread.start()

    send_messages(client_socket, server_public_key, username, stop_event)
    recv_thread.join()
    client_socket.close()

def validate_ip_format(ip):
    """Validasi format IP tanpa menggunakan regex."""
    parts = ip.strip().split('.')
    if len(parts) != 4:
        return False
    for item in parts:
        if not item.isdigit():
            return False
        num = int(item)
        if num < 0 or num > 255:
            return False
    return True

def validate_ip_with_server(ip):
    """Memvalidasi apakah IP terdaftar di server."""
    temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    temp_socket.settimeout(5)  # Timeout 5 detik
    try:
        temp_socket.sendto(b"VALIDATE_IP", (ip, 12345))
        data, _ = temp_socket.recvfrom(65536)
        response = data.decode('utf-8')
        if response == "IP_VALID":
            return True
        else:
            return False
    except socket.timeout:
        print("Timeout saat mencoba menghubungi server. Pastikan IP dan port benar.")
        return False
    except Exception as e:
        print(f"Error saat validasi IP dengan server: {e}")
        return False
    finally:
        temp_socket.close()

def receive_messages(client_socket, private_key, stop_event):
    """Menerima pesan dari server."""
    while not stop_event.is_set():
        try:
            data, _ = client_socket.recvfrom(65536)
            if not data:
                continue

            message = decrypt(private_key, eval(data.decode('utf-8')))
            tag, actual_message = message.split(' ', 1)

            if tag in ["CHAT", "NOTIFY"]:
                print('\r' + ' ' * 80 + '\r', end='', flush=True)
                print(f"{actual_message}")
                print("You: ", end='', flush=True)
            else:
                print(f"\nPesan server: {message}")
        except Exception as e:
            print(f"\nError menerima pesan: {e}")
            break

def send_messages(client_socket, server_public_key, username, stop_event):
    """Mengirim pesan ke server."""
    while not stop_event.is_set():
        try:
            message = input("You: ").strip()
            if message == "":
                print("Pesan tidak boleh kosong.")
                continue

            if message.lower() == '/exit':
                print("Keluar...")
                stop_event.set()
                break

            full_message = f"CHAT {username}: {message}"
            encrypted_message = encrypt(server_public_key, full_message)
            client_socket.sendto(str(encrypted_message).encode('utf-8'), (server_ip, server_port))
        except Exception as e:
            print(f"Error mengirim pesan: {e}")
            stop_event.set()
            break

# ===============================
# Bagian Utama Program
# ===============================

def main():
    run_client()

if __name__ == "__main__":
    main()
