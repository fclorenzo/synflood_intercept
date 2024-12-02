import socket

def tcp_client():
    server_ip = '192.168.2.2'  # IP of h2
    server_port = 12345
    message = "Hello from h1!"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((server_ip, server_port))
        print(f"Connected to TCP server at {server_ip}:{server_port}")

        client_socket.send(message.encode('utf-8'))
        print(f"Sent: {message}")

        response = client_socket.recv(1024).decode('utf-8')
        print(f"Received from server: {response}")

if __name__ == '__main__':
    tcp_client()
