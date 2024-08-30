import socket
import threading


def forward_data(rsu_socket, fms_socket):
    while True:
        data = rsu_socket.recv(4096)
        print("Received Data from Fleet vehicle: " + str(data))
        if not data:
            break
        fms_socket.sendall(data)
        print("Forwarding Data to Fleet Management System")

        response = fms_socket.recv(4096)
        print("Received Response from Fleet Management System: " + str(response))
        if not response:
            break
        rsu_socket.sendall(response)
        print("Forwarding Response to Fleet vehicle")


def start_rsu_server():
    rsu_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rsu_address = ('localhost', 65336)
    rsu_socket.bind(rsu_address)
    rsu_socket.listen(1)

    fms_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fms_address = ('localhost', 65334)
    fms_socket.connect(fms_address)

    while True:
        obu_socket, client_address = rsu_socket.accept()
        print("Connection from", client_address)

        # Create a new thread to handle the communication with the OBU
        thread = threading.Thread(target=forward_data, args=(obu_socket, fms_socket))
        thread.start()


def main():
    start_rsu_server()


if __name__ == "__main__":
    main()
