# 🔐 Secure Document Transmission (Mini Project)

## Overview
Mini project demonstrating **secure document transmission** using **digital signatures (DSA + SHA-256)** to ensure **integrity** and **authenticity**, and to detect **Man-in-the-Middle (MitM) attacks**.

---

## Components

* **Client**: signs and sends a document
* <img width="732" height="514" alt="image" src="https://github.com/user-attachments/assets/29893f98-e6f2-4a7c-93f1-0b5e9b41a8a3" />
* **Official Server**: verifies the digital signature
* <img width="607" height="541" alt="image" src="https://github.com/user-attachments/assets/e8e25bb6-01a1-4028-aae0-cc5418e57272" />
* **Attacker (MitM)**: modifies file or signature
* <img width="731" height="623" alt="image" src="https://github.com/user-attachments/assets/980caf72-9816-4dc5-83b8-2d5de070e7b8" />

---

## Execution

```bash
python serveur.py
python mitm.py      
python client.py
```

---


