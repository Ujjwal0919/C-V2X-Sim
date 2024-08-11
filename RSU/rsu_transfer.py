import socket

def relay_message(source_address, destination_address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(source_address)
    sock.listen(1)
    print("RSU waiting for connection...")

    while True:
        connection, client_address = sock.accept()
        try:
            print("Connected from", client_address)
            data = connection.recv(4096)
            print(f"Relaying data: {data.hex()}")

            if data:
                dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dest_sock.connect(destination_address)
                dest_sock.sendall(data)
                dest_sock.close()
            else:
                print("No data received, closing connection.")
                break
        finally:
            connection.close()

def main():
    rsu_address = ('localhost', 65431)  # RSU listens on this address
    fms_address = ('localhost', 65432)  # FMS address where RSU forwards data
    relay_message(rsu_address, fms_address)

if __name__ == "__main__":
    main()
