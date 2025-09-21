import socket

def main():
    print("Logs from your program will appear here.")
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    print("UDP server is listening on port 2053...")
    while True:
        try:
            buf, source_address = udp_socket.recvfrom(512)
            response = b"Hello, DNS client!"
            udp_socket.sendto(response, source_address)
            print(f"Sent response to {source_address}")
        except Exception as e:
            print(f"An error occurred: {e}")
            break 
if __name__ == "__main__":
    main()