import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading
import struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.exceptions import InvalidSignature

class RealServer:
    def __init__(self, root):
        self.root = root
        self.root.title("SERVEUR OFFICIEL (secure-portal.com)")
        self.root.geometry("600x500")
        self.root.configure(bg="#1b5e20") # Vert foncé (Confiance)

        tk.Label(root, text="🛡️ SERVEUR DE VALIDATION", font=("Arial", 16, "bold"), bg="#1b5e20", fg="white").pack(pady=15)
        
        self.log_area = scrolledtext.ScrolledText(root, height=18, bg="black", fg="#00e676", font=("Consolas", 10))
        self.log_area.pack(pady=10, padx=10)

        self.status = tk.Label(root, text="En attente de documents...", font=("Arial", 12), bg="#2e7d32", fg="white")
        self.status.pack(fill="x", side="bottom", pady=5)

        # Démarrage écoute
        threading.Thread(target=self.start_server, daemon=True).start()

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

    def start_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', 5000)) # Port Officiel
        s.listen(5)
        self.log("Service démarré sur le port 5000.")

        while True:
            conn, addr = s.accept()
            self.log(f"Connexion entrante : {addr}")
            try:
                # Réception Protocole Strict
                # 1. Clé
                lk = struct.unpack("I", self.recv_all(conn, 4))[0]
                pem_key = self.recv_all(conn, lk)
                public_key = serialization.load_pem_public_key(pem_key)

                # 2. Signature
                ls = struct.unpack("I", self.recv_all(conn, 4))[0]
                signature = self.recv_all(conn, ls)

                # 3. Nom
                ln = struct.unpack("I", self.recv_all(conn, 4))[0]
                filename = self.recv_all(conn, ln).decode()

                # 4. Fichier
                lf = struct.unpack("I", self.recv_all(conn, 4))[0]
                file_data = self.recv_all(conn, lf)

                self.log(f"Fichier reçu : {filename} ({lf} octets)")
                self.verify(public_key, signature, file_data, filename)

            except Exception as e:
                self.log(f"Erreur transmission : {e}")
            finally:
                conn.close()


    def verify(self, pub_key, sig, data, filename): 
        try:
            # 1. Vérification Mathématique
            pub_key.verify(sig, data, hashes.SHA256())
            
            # 2. Si on arrive ici, c'est que c'est VALIDE.
            # ALORS, on sauvegarde le fichier sur le disque.
            nom_final = "RECU_" + filename
            with open(nom_final, "wb") as f:
                f.write(data)
            
            self.status.config(text=f"✅ VALIDE. Sauvegardé sous : {nom_final}", bg="#00c853")
            messagebox.showinfo("Succès", f"Fichier authentique !\nIl a été enregistré sous le nom :\n{nom_final}")

        except InvalidSignature:
            self.status.config(text="❌ ALERTE : DOCUMENT FALSIFIÉ (Rejeté)", bg="#d50000")
            messagebox.showerror("ALERTE", "Signature invalide ! Le fichier a été rejeté et NON sauvegardé.")

if __name__ == "__main__":
    root = tk.Tk()
    RealServer(root)
    root.mainloop()
