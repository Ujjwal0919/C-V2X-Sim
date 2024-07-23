import socket
from key_management import handle_server
from data_transfer import send_data

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 12345


def run_obu():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_ADDRESS, SERVER_PORT))
        obu_key_pair, session_key = handle_server(sock)
        print(f"OBU Key Pair and Session Key established.")
        send_data(sock, obu_key_pair, session_key)


if __name__ == "__main__":
    run_obu()
