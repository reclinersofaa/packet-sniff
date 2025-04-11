import socket
import threading

HOST = '0.0.0.0'   # Listen on all interfaces
PORT = 8000    # Match this with the port you send to from Streamlit

def handle_tcp_client(conn, addr):
    print(f"[TCP] Connected by {addr}")
    try:
        data = conn.recv(1024)
        if data:
            print(f"[TCP] Received from {addr}: {data.decode(errors='ignore')}")
    except Exception as e:
        print(f"[TCP] Error: {e}")
    finally:
        conn.close()

def start_tcp_server():
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((HOST, PORT))
    tcp_sock.listen(5)
    print(f"[TCP] Listening on {HOST}:{PORT}")
    while True:
        conn, addr = tcp_sock.accept()
        threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()

def start_udp_server():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((HOST, PORT))
    print(f"[UDP] Listening on {HOST}:{PORT}")
    while True:
        try:
            data, addr = udp_sock.recvfrom(1024)
            print(f"[UDP] Received from {addr}: {data.decode(errors='ignore')}")
        except Exception as e:
            print(f"[UDP] Error: {e}")

# Run both servers in threads
if __name__ == "__main__":
    threading.Thread(target=start_tcp_server, daemon=True).start()
    threading.Thread(target=start_udp_server, daemon=True).start()
    print("Server is running. Press Ctrl+C to stop.")
    
    # Keep the main thread alive
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Server shutting down.")