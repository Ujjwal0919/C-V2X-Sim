import socket
import threading


def forward_message(client_socket, target_address, buffer_size=4096):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_socket:
            forward_socket.connect(target_address)
            while True:
                data = client_socket.recv(buffer_size)
                if not data:
                    break
                forward_socket.sendall(data)
                response = forward_socket.recv(buffer_size)
                client_socket.sendall(response)
    finally:
        client_socket.close()


def handle_obu_connection(obu_socket, fms_address):
    print("Connection established with OBU")
    forward_message(obu_socket, fms_address)


def start_rsu_server(rsu_address, fms_address):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as rsu_socket:
        rsu_socket.bind(rsu_address)
        rsu_socket.listen(5)
        print(f"RSU server listening on {rsu_address}")

        while True:
            obu_socket, _ = rsu_socket.accept()
            client_handler = threading.Thread(
                target=handle_obu_connection,
                args=(obu_socket, fms_address)
            )
            client_handler.start()


def main():
    rsu_address = ('localhost', 65433)
    fms_address = ('localhost', 65431)
    start_rsu_server(rsu_address, fms_address)


if __name__ == "__main__":
    main()
