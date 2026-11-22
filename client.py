import base64
import os
import socket
import threading
import time
import tkinter.filedialog as filedialog
import customtkinter as ctk
from tkinter import messagebox

from common import CHUNK_SIZE, DEFAULT_PORT, recv_json, send_json, sha256_file
from crypto_utils import fingerprint, wrap_aes_key, new_gcm_encryptor

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG = "#0B1220"
PANEL = "#121E31"
PANEL2 = "#17263D"
TEXT = "#E8EEF8"
MUTED = "#91A3BD"
ACCENT = "#3B82F6"
GREEN = "#22C55E"
RED = "#F87171"

class ClientGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SecureLAN | Secure File Transfer")
        self.geometry("1060x780")
        self.minsize(900, 700)
        self.configure(fg_color=BG)
        self.file_path = ""
        self.server_var = ctk.StringVar()
        self.port_var = ctk.StringVar(value=str(DEFAULT_PORT))
        self.fp_var = ctk.StringVar()
        self.mode_var = ctk.StringVar(value="secure")
        self.busy = False
        self._build()
        self._log("Ready. Connect both laptops to the same Wi-Fi/LAN.")

    def card(self, parent, title, subtitle=None):
        frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=16, border_width=1, border_color="#22324A")
        if title:
            ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=15, weight="bold"), text_color=TEXT).pack(anchor="w", padx=18, pady=(15, 2))
        if subtitle:
            ctk.CTkLabel(frame, text=subtitle, font=ctk.CTkFont(size=11), text_color=MUTED).pack(anchor="w", padx=18, pady=(0, 10))
        return frame

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=30, pady=(24, 16))
        ctk.CTkLabel(header, text="SECURELAN", font=ctk.CTkFont(size=28, weight="bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(header, text="SECURE FILE TRANSFER  /  SENDER CONSOLE", font=ctk.CTkFont(size=11, weight="bold"), text_color=ACCENT).pack(anchor="w", pady=(2, 0))
        ctk.CTkLabel(header, text="Transfer files across your local network with cryptographic protection and integrity verification.", font=ctk.CTkFont(size=12), text_color=MUTED).pack(anchor="w", pady=(8, 0))

        stats = ctk.CTkFrame(self, fg_color="transparent")
        stats.pack(fill="x", padx=30, pady=(0, 14))
        for title, value, sub in [
            ("PROTOCOL", "TCP / IPv4", "Reliable stream transport"),
            ("ENCRYPTION", "AES-256-GCM", "RSA-OAEP key wrapping"),
            ("INTEGRITY", "SHA-256", "End-to-end digest check"),
        ]:
            box = ctk.CTkFrame(stats, fg_color=PANEL, corner_radius=14, border_width=1, border_color="#22324A")
            box.pack(side="left", fill="x", expand=True, padx=(0, 10))
            ctk.CTkLabel(box, text=title, text_color=MUTED, font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=15, pady=(12, 1))
            ctk.CTkLabel(box, text=value, text_color=TEXT, font=ctk.CTkFont(size=17, weight="bold")).pack(anchor="w", padx=15)
            ctk.CTkLabel(box, text=sub, text_color=MUTED, font=ctk.CTkFont(size=10)).pack(anchor="w", padx=15, pady=(0, 12))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=30, pady=(0, 24))
        left = ctk.CTkFrame(body, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))
        right = ctk.CTkFrame(body, fg_color="transparent", width=330)
        right.pack(side="right", fill="both", expand=False)

        conn = self.card(left, "01  Receiver connection", "Enter the receiver details shown on the server laptop.")
        conn.pack(fill="x", pady=(0, 12))
        grid = ctk.CTkFrame(conn, fg_color="transparent")
        grid.pack(fill="x", padx=18, pady=(4, 16))
        ctk.CTkLabel(grid, text="Receiver LAN IP", text_color=MUTED).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(grid, text="Port", text_color=MUTED).grid(row=0, column=1, sticky="w", padx=(12, 0))
        ctk.CTkEntry(grid, textvariable=self.server_var, placeholder_text="e.g. 192.168.1.10", height=40).grid(row=1, column=0, sticky="ew", pady=(5, 10))
        ctk.CTkEntry(grid, textvariable=self.port_var, width=110, height=40).grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=(5, 10))
        ctk.CTkLabel(grid, text="Trusted server fingerprint  ·  Required for Secure mode", text_color=MUTED).grid(row=2, column=0, columnspan=2, sticky="w")
        ctk.CTkEntry(grid, textvariable=self.fp_var, placeholder_text="Paste fingerprint from receiver window", height=40, font=ctk.CTkFont(family="Consolas", size=11)).grid(row=3, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        grid.grid_columnconfigure(0, weight=1)

        filecard = self.card(left, "02  Select file", "Choose the file that will be transferred to the receiver.")
        filecard.pack(fill="x", pady=(0, 12))
        fileinner = ctk.CTkFrame(filecard, fg_color="transparent")
        fileinner.pack(fill="x", padx=18, pady=(4, 16))
        ctk.CTkButton(fileinner, text="＋  Browse files", height=42, command=self.choose_file, fg_color=ACCENT, hover_color="#2563EB").pack(side="left")
        self.file_label = ctk.CTkLabel(fileinner, text="No file selected", text_color=MUTED, anchor="w")
        self.file_label.pack(side="left", padx=14, fill="x", expand=True)

        mode = self.card(left, "03  Transfer security", "Choose a mode. Normal mode is intentionally unencrypted for lab comparison only.")
        mode.pack(fill="x")
        self.secure_radio = ctk.CTkRadioButton(mode, text="Secure transfer  —  RSA-OAEP + AES-256-GCM", variable=self.mode_var, value="secure", text_color=TEXT, fg_color=ACCENT)
        self.secure_radio.pack(anchor="w", padx=20, pady=(8, 5))
        self.normal_radio = ctk.CTkRadioButton(mode, text="Normal transfer  —  plaintext TCP (demo only)", variable=self.mode_var, value="normal", text_color=TEXT, fg_color=ACCENT)
        self.normal_radio.pack(anchor="w", padx=20, pady=(5, 15))

        summary = self.card(right, "Transfer control", "Live status and measured performance.")
        summary.pack(fill="both", expand=True)
        self.status_dot = ctk.CTkLabel(summary, text="●  READY", text_color=GREEN, font=ctk.CTkFont(size=12, weight="bold"))
        self.status_dot.pack(anchor="w", padx=18, pady=(8, 12))
        self.progress = ctk.CTkProgressBar(summary, height=12, progress_color=ACCENT)
        self.progress.pack(fill="x", padx=18)
        self.progress.set(0)
        self.progress_label = ctk.CTkLabel(summary, text="Waiting for file transfer", text_color=MUTED, font=ctk.CTkFont(size=11))
        self.progress_label.pack(anchor="w", padx=18, pady=(7, 14))
        self.send_button = ctk.CTkButton(summary, text="SEND FILE  →", height=48, font=ctk.CTkFont(size=14, weight="bold"), fg_color=ACCENT, hover_color="#2563EB", command=self.send_clicked)
        self.send_button.pack(fill="x", padx=18, pady=(0, 16))
        ctk.CTkLabel(summary, text="LATEST RESULT", text_color=MUTED, font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=18)
        self.result_label = ctk.CTkLabel(summary, text="No transfers yet", text_color=TEXT, justify="left", wraplength=275, anchor="w")
        self.result_label.pack(fill="x", padx=18, pady=(5, 16))
        ctk.CTkLabel(summary, text="ACTIVITY LOG", text_color=MUTED, font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=18)
        self.log_box = ctk.CTkTextbox(summary, height=190, fg_color="#09111E", text_color="#C9D6E8", corner_radius=10, font=ctk.CTkFont(family="Consolas", size=10))
        self.log_box.pack(fill="both", expand=True, padx=18, pady=(7, 16))
        self.log_box.configure(state="disabled")

    def _log(self, msg):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", time.strftime("[%H:%M:%S] ") + msg + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def choose_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path = path
            size = os.path.getsize(path)
            self.file_label.configure(text=f"{os.path.basename(path)}  ·  {size:,} bytes", text_color=TEXT)
            self._log(f"Selected {os.path.basename(path)}")

    def send_clicked(self):
        if self.busy:
            return
        if not self.file_path:
            messagebox.showwarning("Select a file", "Choose a file before sending.")
            return
        if not self.server_var.get().strip():
            messagebox.showwarning("Receiver IP required", "Enter the receiver laptop's LAN IP address.")
            return
        if self.mode_var.get() == "secure" and not self.fp_var.get().strip():
            messagebox.showwarning("Fingerprint required", "Paste the fingerprint shown in the receiver window.")
            return
        try:
            int(self.port_var.get())
        except ValueError:
            messagebox.showwarning("Invalid port", "Port must be a number.")
            return
        self.busy = True
        self.send_button.configure(state="disabled", text="TRANSFERRING…")
        self.status_dot.configure(text="●  CONNECTING", text_color="#FBBF24")
        self.progress.set(0)
        threading.Thread(target=self._send_worker, daemon=True).start()

    def _ui(self, callback, *args):
        self.after(0, lambda: callback(*args))

    def _send_worker(self):
        try:
            path = self.file_path
            size = os.path.getsize(path)
            mode = self.mode_var.get()
            started = time.perf_counter()
            self._ui(self._log, "Calculating SHA-256 and connecting…")
            digest = sha256_file(path)
            with socket.create_connection((self.server_var.get().strip(), int(self.port_var.get())), timeout=10) as sock:
                sock.settimeout(120)
                key_len = int.from_bytes(self._recv_exact(sock, 4), "big")
                if key_len <= 0 or key_len > 10000:
                    raise ValueError("Invalid server public key received.")
                public_pem = self._recv_exact(sock, key_len)
                server_fp = fingerprint(public_pem)
                if mode == "secure":
                    supplied = self.fp_var.get().strip().lower().replace(":", "").replace(" ", "")
                    if supplied != server_fp.lower():
                        raise ValueError("Server fingerprint mismatch. The server identity was not verified.")
                header = {"filename": os.path.basename(path), "size": size, "mode": mode, "sha256": digest}
                cipher = None
                if mode == "secure":
                    from Crypto.Random import get_random_bytes
                    aes_key = get_random_bytes(32)
                    wrapped_key = wrap_aes_key(public_pem, aes_key)
                    cipher, nonce = new_gcm_encryptor(aes_key)
                    header.update({"wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
                                   "nonce": nonce.hex(), "cipher": "AES-256-GCM"})
                send_json(sock, header)
                sent = 0
                with open(path, "rb") as f:
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        sock.sendall(cipher.encrypt(chunk) if cipher else chunk)
                        sent += len(chunk)
                        self._ui(self._progress_update, sent, size)
                if cipher:
                    sock.sendall(cipher.digest())
                result = recv_json(sock)
            elapsed = max(time.perf_counter() - started, 0.000001)
            if not result.get("ok"):
                raise RuntimeError(result.get("message", "Transfer failed."))
            mbps = (size / (1024 * 1024)) / elapsed
            self._ui(self._finish_success, size, elapsed, mbps, mode, os.path.basename(path), digest)
        except Exception as exc:
            self._ui(self._finish_error, str(exc))
    def _progress_update(self, sent, total):
        self.progress.set(sent / total if total else 1)
        self.progress_label.configure(text=f"{sent:,} / {total:,} bytes  ·  {(sent / total * 100) if total else 100:.1f}%")
        self.status_dot.configure(text="●  TRANSFERRING", text_color="#FBBF24")
    def _finish_success(self, size, elapsed, mbps, mode, name, digest):
        self.busy = False
        self.send_button.configure(state="normal", text="SEND FILE  →")
        self.progress.set(1)
        self.status_dot.configure(text="●  TRANSFER VERIFIED", text_color=GREEN)
        self.progress_label.configure(text="Transfer completed successfully")
        self.result_label.configure(text=f"{name}\n{size:,} bytes  ·  {elapsed:.2f}s\n{mbps:.2f} MB/s  ·  SHA-256 verified")
        self._log(f"SUCCESS | {mode.upper()} | {name} | {mbps:.2f} MB/s | SHA-256 OK")
    def _finish_error(self, error):
        self.busy = False
        self.send_button.configure(state="normal", text="SEND FILE  →")
        self.status_dot.configure(text="●  TRANSFER FAILED", text_color=RED)
        self.progress_label.configure(text="Check connection, firewall and fingerprint.")
        self.result_label.configure(text=error)
        self._log("ERROR | " + error)
    @staticmethod
    def _recv_exact(sock, size):
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Receiver disconnected during handshake.")
            data.extend(chunk)
        return bytes(data)

if __name__ == "__main__":
    ClientGUI().mainloop()
