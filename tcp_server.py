import socket

def tcp_server():
    host = '0.0.0.0'  # Listen on all interfaces
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"TCP Server listening on port {port}...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connection from {addr}")
            data = conn.recv(1024).decode('utf-8')
            print(f"Received: {data}")
            if data:
                response = "Message received"
                conn.send(response.encode('utf-8'))
                print("Response sent back to client.")

if __name__ == '__main__':
    tcp_server()
