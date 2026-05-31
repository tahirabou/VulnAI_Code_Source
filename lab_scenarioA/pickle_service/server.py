import socket
import pickle
import os

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 9090))
    s.listen(5)
    print("[*] Pickle service en écoute sur le port 9090...")
    
    while True:
        conn, addr = s.accept()
        print(f"[+] Connexion de {addr}")
        data = conn.recv(4096)
        if data:
            try:
                # VULNÉRABILITÉ INTENTIONNELLE : désérialisation sans validation
                obj = pickle.loads(data)
                result = str(obj)
                conn.send(result.encode())
            except Exception as e:
                conn.send(f"Erreur: {e}".encode())
        conn.close()

if __name__ == "__main__":
    start_server()
