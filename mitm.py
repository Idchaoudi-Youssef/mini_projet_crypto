import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading
import struct

# CONFIGURATION
REAL_SERVER_IP = '10.160.42.57'  # <--- METTRE IP DU SERVEUR
REAL_SERVER_PORT = 5000
ATTACKER_PORT = 5000

class AttackerInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("SERVEUR PIÈGE (MitM)")
        self.root.geometry("600x650")
        self.root.configure(bg="#37474f")

        tk.Label(root, text="💀 INTERFACE ATTAQUANT", font=("Impact", 18), bg="#37474f", fg="#ff5252").pack(pady=10)
        
        # ZONE ACTIONS
        frame = tk.LabelFrame(root, text=" Scénarios d'Attaque ", bg="#37474f", fg="white", font=("Arial", 10, "bold"))
        frame.pack(pady=10, fill="x", padx=20)

        # CHECKBOX 1 : INTÉGRITÉ
        self.var_corrupt_file = tk.BooleanVar()
        tk.Checkbutton(frame, text="1. Attaque sur l'INTÉGRITÉ (Modifier Fichier)", var=self.var_corrupt_file, 
                       bg="#37474f", fg="#ffab91", selectcolor="black", font=("Arial", 11, "bold")).pack(anchor="w", padx=10, pady=5)
        
        tk.Label(frame, text="   ↳ Le fichier change, la signature ne matche plus le hash.", bg="#37474f", fg="gray").pack(anchor="w", padx=30)

        # CHECKBOX 2 : AUTHENTICITÉ (NOUVEAU !)
        self.var_corrupt_sig = tk.BooleanVar()
        tk.Checkbutton(frame, text="2. Attaque sur l'AUTHENTICITÉ (Falsifier Signature)", var=self.var_corrupt_sig, 
                       bg="#37474f", fg="#ffab91", selectcolor="black", font=("Arial", 11, "bold")).pack(anchor="w", padx=10, pady=5)

        tk.Label(frame, text="   ↳ Le fichier est bon, mais la signature est remplacée/fausse.", bg="#37474f", fg="gray").pack(anchor="w", padx=30)

        # Logs
        self.log_area = scrolledtext.ScrolledText(root, height=15, bg="black", fg="#ff5252")
        self.log_area.pack(pady=10, padx=10)

        threading.Thread(target=self.start_listener, daemon=True).start()

    def log(self, msg):
        self.log_area.insert(tk.END, f"> {msg}\n")
        self.log_area.see(tk.END)

    def recv_all(self, sock, n):
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet: return None
            data += packet
        return data

    def start_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', ATTACKER_PORT))
        s.listen(5)
        self.log(f"En attente de victimes sur le port {ATTACKER_PORT}...")

        while True:
            client, addr = s.accept()
            threading.Thread(target=self.handle_victim, args=(client,), daemon=True).start()
    # =================================================================
    # [4] PARTIE RESPONSABLE DES INJECTIONS (MITM)
    # =================================================================
    def handle_victim(self, client):
        try:
            # 1. RÉCEPTION
            lk = struct.unpack("I", self.recv_all(client, 4))[0]
            pem_key = self.recv_all(client, lk)

            ls = struct.unpack("I", self.recv_all(client, 4))[0]
            signature = self.recv_all(client, ls) # La vraie signature

            ln = struct.unpack("I", self.recv_all(client, 4))[0]
            filename = self.recv_all(client, ln)

            lf = struct.unpack("I", self.recv_all(client, 4))[0]
            file_data = self.recv_all(client, lf) # Le vrai fichier

            self.log(f"Intercepté : {filename.decode()}")

            # 2. ATTAQUES

            # CAS A : INTÉGRITÉ (On touche au fichier)
            if self.var_corrupt_file.get():
                self.log("ATTACK: Injection de virus dans le fichier...")
                file_data = file_data + b"\n<VIRUS>"
            
            # CAS B : AUTHENTICITÉ (On touche à la signature)
            if self.var_corrupt_sig.get():
                self.log("ATTACK: Tentative de falsification de signature...")
                # L'attaquant essaie de signer mais il n'a pas la clé privée.
                # Il envoie donc n'importe quoi (ou une signature faite avec SA clé à lui)
                # Ici, on remplace la signature par des zéros pour simuler une fausse signature
                signature = b'\x00' * len(signature)

            # 3. RELAI
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.connect((REAL_SERVER_IP, REAL_SERVER_PORT))

            srv.sendall(struct.pack("I", len(pem_key)) + pem_key)
            srv.sendall(struct.pack("I", len(signature)) + signature) # Signature potentiellement fausse
            srv.sendall(struct.pack("I", len(filename)) + filename)
            srv.sendall(struct.pack("I", len(file_data)) + file_data) # Fichier potentiellement faux

            srv.close()
            client.close()
            self.log("✅ Données relayées.")

        except Exception as e:
            self.log(f"Erreur : {e}")

if __name__ == "__main__":
    root = tk.Tk()
    AttackerInterface(root)
    root.mainloop()
