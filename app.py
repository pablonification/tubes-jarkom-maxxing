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

    print("="*50)
    print("       Aplikasi Chat Enkripsi RSA UDP")
    print("="*50)

    # Meminta pengguna untuk memilih penggunaan IP server
    while True:
        try:
            server_choice = input("Apakah Anda ingin menggunakan IP server Anda sendiri? (y/n): ").strip().lower()
            if server_choice in ['y', 'n']:
                break
            else:
                print("[!] Input tidak valid. Silakan masukkan 'y' atau 'n'.")
        except KeyboardInterrupt:
            print("\n[!] Program dihentikan oleh pengguna.")
            sys.exit()

    if server_choice == 'y':
        # Menggunakan IP lokal klien
        server_ip = get_local_ip()
        print(f"[+] Menggunakan IP lokal Anda sebagai server: {server_ip}")
    else:
        # Meminta input IP server
        while True:
            try:
                server_ip = input("Masukkan IP server: ").strip()
                if server_ip == '':
                    print("[!] IP server tidak boleh kosong. Silakan masukkan IP yang valid.")
                    continue
                if validate_ip_format(server_ip):
                    # Coba validasi IP terlebih dahulu
                    if validate_ip(server_ip):
                        break
                    else:
                        print("[!] IP tidak valid atau server tidak merespons. Silakan coba lagi.")
                else:
                    print("[!] Format IP tidak valid. Silakan masukkan IP yang valid.")
            except KeyboardInterrupt:
                print("\n[!] Program dihentikan oleh pengguna.")
                sys.exit()

    # Membuat socket UDP dengan timeout
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(5)  # Timeout 5 detik

    # Meminta input port server dan validasi
    while True:
        try:
            server_port = int(input("Masukkan port server (1024-65535): ").strip())
            if not 1024 <= server_port <= 65535:
                print("[!] Port harus berada dalam rentang 1024-65535.")
                continue
        except ValueError:
            print("[!] Input tidak valid. Silakan masukkan angka.")
            continue
        except KeyboardInterrupt:
            print("\n[!] Program dihentikan oleh pengguna.")
            sys.exit()

        print("[*] Memvalidasi port server...")
        validation_result, pub_key = validate_server(client_socket, server_ip, server_port)
        if validation_result == "VALID":
            print("[+] Port server valid dan kunci publik diterima.")
            server_public_key = pub_key
            break
        elif validation_result == "INVALID_RESPONSE":
            print("[!] Diterima respon tidak valid dari server. Pastikan Anda menghubungkan ke server yang benar.")
        elif validation_result == "NO_RESPONSE":
            print("[!] Tidak ada respons dari server. Pastikan IP dan port benar, serta server sedang berjalan.")
        else:
            print("[!] Silahkan coba masukkan ulang port server.")

    # Menghasilkan kunci RSA klien
    print("[*] Menghasilkan kunci RSA klien...")
    public_key, private_key = generate_keypair()

    # Mengirim kunci publik klien ke server
    try:
        print("[*] Mengirim kunci publik klien ke server...")
        client_socket.sendto(str(public_key[0]).encode('utf-8'), (server_ip, server_port))
        client_socket.sendto(str(public_key[1]).encode('utf-8'), (server_ip, server_port))
    except Exception as e:
        print(f"[!] Error saat mengirim kunci publik ke server: {e}")
        client_socket.close()
        sys.exit()

    # Autentikasi dengan password chatroom
    while True:
        try:
            chatroom_password = input("Masukkan password chatroom: ").strip()
            if chatroom_password == "":
                print("[!] Password tidak boleh kosong.")
                continue
            break
        except KeyboardInterrupt:
            print("\n[!] Program dihentikan oleh pengguna.")
            client_socket.close()
            sys.exit()

    encrypted_message = encrypt(server_public_key, f"AUTH PASSWORD {chatroom_password}")
    client_socket.sendto(str(encrypted_message).encode('utf-8'), (server_ip, server_port))

    # Meminta username
    while True:
        try:
            username = input("Masukkan username Anda: ").strip()
            if username == "":
                print("[!] Username tidak boleh kosong.")
                continue

            encrypted_message = encrypt(server_public_key, f"AUTH USERNAME {username}")
            client_socket.sendto(str(encrypted_message).encode('utf-8'), (server_ip, server_port))

            data, _ = client_socket.recvfrom(65536)
            response = decrypt(private_key, eval(data.decode('utf-8')))

            if response == "USERNAME_OK":
                print("[+] Username diterima. Ketik '/exit' untuk keluar dari chat.")
                break
            elif response == "USERNAME_TAKEN":
                print("[!] Username sudah digunakan. Silakan pilih username lain.")
            elif response == "AUTH_FAILED":
                print("[!] Password salah.")
                client_socket.close()
                sys.exit()
            else:
                print(f"[!] Respon tidak dikenal dari server: {response}")
                client_socket.close()
                sys.exit()
        except socket.timeout:
            print("[!] Tidak ada respons dari server. Pastikan server berjalan dan port benar.")
            client_socket.close()
            sys.exit()
        except KeyboardInterrupt:
            print("\n[!] Program dihentikan oleh pengguna.")
            client_socket.close()
            sys.exit()
        except Exception as e:
            print(f"[!] Error saat menerima respons dari server: {e}")
            client_socket.close()
            sys.exit()

    # Memulai thread untuk menerima dan mengirim pesan
    stop_event = threading.Event()
    recv_thread = threading.Thread(target=receive_messages, args=(client_socket, private_key, stop_event), daemon=True)
    recv_thread.start()

    send_messages(client_socket, server_public_key, username, stop_event)
    recv_thread.join()
    client_socket.close()

def validate_server(client_socket, server_ip, server_port):
    """Memvalidasi apakah server dapat dihubungi dan merespons dengan benar."""
    try:
        # Kirim permintaan kunci publik server
        client_socket.sendto(b"REQUEST_PUBLIC_KEY", (server_ip, server_port))

        # Terima kunci publik server
        server_public_key_e, _ = client_socket.recvfrom(65536)
        server_public_key_n, _ = client_socket.recvfrom(65536)

        # Validasi apakah yang diterima adalah angka
        e = int(server_public_key_e.decode('utf-8'))
        n = int(server_public_key_n.decode('utf-8'))

        # Simple validation: e biasanya adalah 65537
        if e == 65537 and n > e:
            return "VALID", (e, n)
        else:
            return "INVALID_RESPONSE", None
    except socket.timeout:
        return "NO_RESPONSE", None
    except ValueError:
        # Jika tidak dapat mengkonversi ke integer
        return "INVALID_RESPONSE", None
    except Exception as e:
        print(f"[!] Terjadi kesalahan saat validasi server: \n{e}")
        return "ERROR", None

def validate_ip(server_ip):
    """Memvalidasi apakah IP server benar dengan mencoba mendapatkan kunci publik."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(2)  # Timeout 2 detik
    try:
        # Kirim permintaan kunci publik server
        client_socket.sendto(b"REQUEST_PUBLIC_KEY", (server_ip, 12345))  # Gunakan port yang benar jika perlu

        # Terima kunci publik server
        server_public_key_e, _ = client_socket.recvfrom(65536)
        server_public_key_n, _ = client_socket.recvfrom(65536)

        # Validasi apakah yang diterima adalah angka
        e = int(server_public_key_e.decode('utf-8'))
        n = int(server_public_key_n.decode('utf-8'))

        # Simple validation: e biasanya adalah 65537
        if e == 65537 and n > e:
            return True
        else:
            return False
    except:
        return False
    finally:
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

def receive_messages(client_socket, private_key, stop_event):
    """Menerima pesan dari server."""
    while not stop_event.is_set():
        try:
            data, _ = client_socket.recvfrom(65536)
            if not data:
                continue

            # print("[DEBUG] Menerima data dari server...")
            decrypted_data = eval(data.decode('utf-8'))
            message = decrypt(private_key, decrypted_data)
            # print(f"[DEBUG] Pesan didekripsi: {message}")

            tag, actual_message = message.split(' ', 1)

            if tag in ["CHAT", "NOTIFY"]:
                print('\r' + ' ' * 80 + '\r', end='', flush=True)
                print(f"{actual_message}")
                print("You: ", end='', flush=True)
            else:
                print(f"\n[!] Pesan server: {message}")
        except socket.timeout:
            # Tidak melakukan apa-apa dan melanjutkan loop
            continue
        except Exception as e:
            print(f"\n[!] Error menerima pesan: {e}")
            break

def send_messages(client_socket, server_public_key, username, stop_event):
    """Mengirim pesan ke server."""
    while not stop_event.is_set():
        try:
            message = input("You: ").strip()
            if message == "":
                print("[!] Pesan tidak boleh kosong.")
                continue

            if message.lower() == '/exit':
                print("[*] Keluar dari chat...")
                stop_event.set()
                break

            full_message = f"CHAT {username}: {message}"
            encrypted_message = encrypt(server_public_key, full_message)
            client_socket.sendto(str(encrypted_message).encode('utf-8'), (server_ip, server_port))
        except KeyboardInterrupt:
            print("\n[*] Keluar dari chat...")
            stop_event.set()
            break
        except Exception as e:
            print(f"[!] Error mengirim pesan: {e}")
            stop_event.set()
            break

# ===============================
# Bagian Utama Program
# ===============================

def main():
    try:
        run_client()
    except KeyboardInterrupt:
        print("\n[!] Program dihentikan oleh pengguna.")
        sys.exit()

if __name__ == "__main__":
    main()
