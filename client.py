import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import socket
import struct
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa

# --- CONFIGURATION DNS SIMULÉE ---
DESTINATIONS = {
    "secure-portal.com (Site Officiel)": "192.168.11.150",   # IP Vrai Serveur 
    "secure-portall.com (Lien reçu par email)": "10.160.42.40" # IP Attaquant 
}

class SenderClient:
    def __init__(self, root):
        self.root = root
        self.root.title("CLIENT D'ENVOI SÉCURISÉ")
        self.root.geometry("500x550")
        
        self.private_key = None
        self.public_key = None
        self.file_path = None
        self.signature = None
        self.data_to_send = None

        tk.Label(root, text="Envoi de Document Certifié", font=("Arial", 16, "bold")).pack(pady=15)

        # 1. CHOIX DE LA DESTINATION (Le Piège)
        frame_dest = tk.LabelFrame(root, text="1. Serveur de Destination", padx=10, pady=10)
        frame_dest.pack(fill="x", padx=20, pady=5)
        
        tk.Label(frame_dest, text="Sélectionnez le serveur :").pack(anchor="w")
        self.dest_combo = ttk.Combobox(frame_dest, values=list(DESTINATIONS.keys()), state="readonly", width=40)
        self.dest_combo.current(0) # Sélectionne le premier par défaut
        self.dest_combo.pack(pady=5)

        # 2. GENERATION CLES
        tk.Button(root, text="2. Générer mes Clés DSA", command=self.gen_keys, bg="#e3f2fd").pack(fill="x", padx=20, pady=5)

        # 3. FICHIER
        tk.Button(root, text="3. Sélectionner Fichier (PDF/IMG)", command=self.select_file, bg="#e3f2fd").pack(fill="x", padx=20, pady=5)
        self.lbl_file = tk.Label(root, text="Aucun fichier", fg="gray")
        self.lbl_file.pack()

        # 4. SIGNATURE
        tk.Button(root, text="4. Signer le Fichier (SHA-256)", command=self.sign_file, bg="#fff3e0").pack(fill="x", padx=20, pady=5)

        # 5. ENVOI
        tk.Button(root, text="5. ENVOYER LE DOCUMENT 🚀", command=self.send_data, bg="#4caf50", fg="white", font=("Arial", 12, "bold")).pack(pady=20, padx=20)
    # =================================================================
    # [1] PARTIE RESPONSABLE DE LA GÉNÉRATION DES CLÉS
    # =================================================================
    def gen_keys(self):
        self.private_key = dsa.generate_private_key(key_size=2048)
        self.public_key = self.private_key.public_key()
        messagebox.showinfo("Clés", "Paire de clés DSA générée en mémoire.")

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.lbl_file.config(text=os.path.basename(path), fg="black")
    # =================================================================
    # [2] PARTIE RESPONSABLE DU HACHAGE ET DE LA SIGNATURE
    # =================================================================
    def sign_file(self):
        if not self.file_path or not self.private_key:
            messagebox.showerror("Erreur", "Clés ou fichier manquant.")
            return
        with open(self.file_path, "rb") as f:
            self.data_to_send = f.read()
        
        self.signature = self.private_key.sign(self.data_to_send, hashes.SHA256())
        messagebox.showinfo("Signature", "Fichier signé numériquement.")
    # =================================================================
    # [3] PARTIE RESPONSABLE DE L'ENVOI (PROTOCOLE RÉSEAU)
    # =================================================================
    def send_data(self):
        if not self.signature:
            messagebox.showwarning("Stop", "Veuillez signer le fichier avant d'envoyer.")
            return

        # Récupération de l'IP basée sur le choix du menu déroulant
        choice_name = self.dest_combo.get()
        target_ip = DESTINATIONS[choice_name]
        
        print(f"Connexion à : {choice_name} -> {target_ip}") # Debug console

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, 5000)) # Connexion sur port 5000

            # Packaging
            pem = self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            name = os.path.basename(self.file_path).encode()

            # Envoi
            s.sendall(struct.pack("I", len(pem)) + pem)#pk
            s.sendall(struct.pack("I", len(self.signature)) + self.signature)#signature
            s.sendall(struct.pack("I", len(name)) + name)#filename
            s.sendall(struct.pack("I", len(self.data_to_send)) + self.data_to_send)#data

            s.close()
            messagebox.showinfo("Envoyé", f"Document envoyé à {choice_name}")

        except Exception as e:
            messagebox.showerror("Erreur Réseau", f"Impossible de joindre le serveur : {e}")

if __name__ == "__main__":
    root = tk.Tk()
    SenderClient(root)
    root.mainloop()