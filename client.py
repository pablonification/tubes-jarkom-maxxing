import socket
import threading
import sys
from rsa import generate_keypair, encrypt, decrypt

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
                # Menangani pesan lain
                if message == "USERNAME_TAKEN":
                    print("\nUsername sudah digunakan.")
                    while True:
                        new_username = input("Masukkan username baru: ")
                        if new_username.strip() == "":
                            print("Username tidak boleh kosong.")
                        else:
                            # Kirim username baru ke server
                            encrypted_message = encrypt(server_public_key, f"AUTH USERNAME {new_username}")
                            client_socket.sendto(str(encrypted_message).encode('utf-8'), (server_ip, server_port))
                            break
                elif message == "AUTH_FAILED":
                    print("\nPassword salah. Silakan restart klien.")
                    stop_event.set()
                    break
                elif message == "USERNAME_OK":
                    print("Username diterima. Ketik '/exit' untuk keluar dari chat.")
                else:
                    print(f"\nUnknown message: {message}")
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

def main():
    global server_ip, server_port, server_public_key
    server_ip = input("Enter server IP: ")
    server_port = int(input("Enter server port: "))

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Menghasilkan kunci RSA klien
    print("Menghasilkan kunci RSA klien...")
    public_key, private_key = generate_keypair()

    # Menerima kunci publik server
    print("Menerima kunci publik server...")
    client_socket.sendto(b"REQUEST_PUBLIC_KEY", (server_ip, server_port))
    server_public_key_e, _ = client_socket.recvfrom(65536)
    server_public_key_n, _ = client_socket.recvfrom(65536)
    server_public_key_e = int(server_public_key_e.decode('utf-8'))
    server_public_key_n = int(server_public_key_n.decode('utf-8'))
    server_public_key = (server_public_key_e, server_public_key_n)


    # Mengirim kunci publik klien ke server
    client_socket.sendto(str(public_key[0]).encode('utf-8'), (server_ip, server_port))
    client_socket.sendto(str(public_key[1]).encode('utf-8'), (server_ip, server_port))

    chatroom_password = input("Enter chatroom password: ")

    # Kirim password terenkripsi
    encrypted_message = encrypt(server_public_key, f"AUTH PASSWORD {chatroom_password}")
    client_socket.sendto(str(encrypted_message).encode('utf-8'), (server_ip, server_port))

    while True:
        username = input("Enter your username: ")
        if username.strip() == "":
            print("Username tidak boleh kosong.")
            continue
        # Kirim username terenkripsi
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

    # Event untuk memberitahu thread untuk berhenti
    stop_event = threading.Event()

    # Mulai thread untuk menerima pesan
    recv_thread = threading.Thread(
        target=receive_messages, args=(client_socket, private_key, stop_event), daemon=True
    )
    recv_thread.start()

    # Kirim pesan
    send_messages(client_socket, server_public_key, username, stop_event)

    # Tunggu thread penerima pesan selesai
    recv_thread.join()
    client_socket.close()

if __name__ == "__main__":
    main()
