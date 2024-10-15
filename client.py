import socket
import threading
import sys
from double_ratchet import DoubleRatchet

def receive_messages(client_socket, ratchet, stop_event):
    while not stop_event.is_set():
        try:
            data, _ = client_socket.recvfrom(4096)
            if not data:
                break
            # Semua pesan dienkripsi
            message = ratchet.decrypt(data).decode('utf-8')
            tag, actual_message = message.split(' ', 1)

            if tag == "CHAT" or tag == "NOTIFY":
                # Hapus input yang sedang diketik oleh pengguna
                print('\r' + ' ' * 80 + '\r', end='', flush=True)
                print(f"{actual_message}")
                # Tampilkan kembali prompt tanpa mengganggu input
                print("You: ", end='', flush=True)
            else:
                # Menangani pesan lain (misalnya, USERNAME_TAKEN)
                if message == "USERNAME_TAKEN":
                    print("\nUsername sudah digunakan.")
                    while True:
                        new_username = input("Masukkan username baru: ")
                        if new_username.strip() == "":
                            print("Username tidak boleh kosong.")
                        else:
                            # Kirim username baru ke server
                            client_socket.sendto(
                                ratchet.encrypt(f"AUTH USERNAME {new_username}".encode('utf-8')),
                                (server_ip, server_port)
                            )
                            break
                elif message == "AUTH_FAILED":
                    print("\nPassword salah. Silakan restart klien.")
                    stop_event.set()
                    break
        except socket.error:
            # Socket telah ditutup
            break
        except Exception as e:
            print(f"\nError receiving message: {e}")
            break

def send_messages(client_socket, ratchet, server_ip, server_port, username, stop_event):
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
            encrypted_message = ratchet.encrypt(full_message.encode('utf-8'))
            client_socket.sendto(encrypted_message, (server_ip, server_port))
        except KeyboardInterrupt:
            print("\nExiting...")
            stop_event.set()
            break
        except Exception as e:
            print(f"Error sending message: {e}")
            stop_event.set()
            break

def main():
    global server_ip, server_port  # Ditambahkan agar dapat digunakan di fungsi lain
    server_ip = input("Enter server IP: ")
    server_port = int(input("Enter server port: "))

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    initial_key = b"this_is_an_initial_key__32bytes!"
    ratchet = DoubleRatchet(initial_key)

    chatroom_password = input("Enter chatroom password: ")

    # Kirim password terenkripsi
    client_socket.sendto(
        ratchet.encrypt(f"AUTH PASSWORD {chatroom_password}".encode('utf-8')),
        (server_ip, server_port)
    )

    while True:
        username = input("Enter your username: ")
        if username.strip() == "":
            print("Username tidak boleh kosong.")
            continue
        # Kirim username terenkripsi
        client_socket.sendto(
            ratchet.encrypt(f"AUTH USERNAME {username}".encode('utf-8')),
            (server_ip, server_port)
        )

        data, _ = client_socket.recvfrom(4096)
        response = ratchet.decrypt(data).decode('utf-8')

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
        target=receive_messages, args=(client_socket, ratchet, stop_event), daemon=True
    )
    recv_thread.start()

    # Kirim pesan
    send_messages(client_socket, ratchet, server_ip, server_port, username, stop_event)

    # Tunggu thread penerima pesan selesai
    recv_thread.join()
    client_socket.close()

if __name__ == "__main__":
    main()
