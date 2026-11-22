import os
import socket
import threading
import time
import hashlib
import base64
from pathlib import Path
import customtkinter as ctk
from tkinter import messagebox

from common import (CHUNK_SIZE, DEFAULT_PORT, local_ipv4_addresses,
                    recv_exact, recv_json, safe_filename, send_json)
from crypto_utils import ensure_server_keys, fingerprint, unwrap_aes_key, new_gcm_decryptor

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG = "#0B1220"
PANEL = "#121E31"
TEXT = "#E8EEF8"
MUTED = "#91A3BD"
ACCENT = "#3B82F6"
GREEN = "#22C55E"
RED = "#F87171"

BASE_DIR = Path(__file__).resolve().parent
RECEIVED_DIR = BASE_DIR / "received_files"
RECEIVED_DIR.mkdir(exist_ok=True)

class SecureLANServer:
    def __init__(self, log_callback, status_callback, transfer_callback):
        self.log = log_callback
        self.status = status_callback
        self.transfer_callback = transfer_callback
        self.running = False
        self.listener = None
        self.private_key, self.public_pem = ensure_server_keys()
        self.fingerprint = fingerprint(self.public_pem)

    def start(self, port):
        if self.running:
            return
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("0.0.0.0", port))
            listener.listen(8)
        except OSError:
            listener.close()
            raise
        self.listener = listener
        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        self.status(f"RUNNING  ·  TCP PORT {port}")

    def stop(self):
        self.running = False
        if self.listener:
            try:
                self.listener.close()
            except OSError:
                pass
            self.listener = None
        self.status("STOPPED")

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.listener.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
            except OSError:
                break

    def _handle_client(self, conn, addr):
        temp_path = None
        try:
            with conn:
                conn.settimeout(180)
                conn.sendall(len(self.public_pem).to_bytes(4, "big") + self.public_pem)
                header = recv_json(conn)
                filename = safe_filename(header["filename"])
                size = int(header["size"])
                mode = header["mode"]
                expected_hash = str(header["sha256"]).lower()
                if size < 0 or size > 2 * 1024 * 1024 * 1024:
                    raise ValueError("File size must be between 0 and 2 GB.")
                if mode not in ("normal", "secure"):
                    raise ValueError("Unknown transfer mode.")
                final_path = RECEIVED_DIR / filename
                if final_path.exists():
                    stem, suffix = final_path.stem, final_path.suffix
                    counter = 1
                    while (RECEIVED_DIR / f"{stem}_{counter}{suffix}").exists():
                        counter += 1
                    final_path = RECEIVED_DIR / f"{stem}_{counter}{suffix}"
                temp_path = str(final_path) + ".part"
                started = time.perf_counter()
                digest = hashlib.sha256()
                remaining = size
                if mode == "secure":
                    wrapped = base64.b64decode(header["wrapped_key"], validate=True)
                    nonce = bytes.fromhex(header["nonce"])
                    aes_key = unwrap_aes_key(self.private_key, wrapped)
                    cipher = new_gcm_decryptor(aes_key, nonce)
                    with open(temp_path, "wb") as out:
                        while remaining:
                            block = recv_exact(conn, min(CHUNK_SIZE, remaining))
                            plain = cipher.decrypt(block)
                            out.write(plain)
                            digest.update(plain)
                            remaining -= len(block)
                        cipher.verify(recv_exact(conn, 16))
                else:
                    with open(temp_path, "wb") as out:
                        while remaining:
                            block = recv_exact(conn, min(CHUNK_SIZE, remaining))
                            out.write(block)
                            digest.update(block)
                            remaining -= len(block)
                actual_hash = digest.hexdigest()
                if actual_hash != expected_hash:
                    raise ValueError("SHA-256 integrity check FAILED.")
                os.replace(temp_path, final_path)
                temp_path = None
                elapsed = max(time.perf_counter() - started, 0.000001)
                mbps = (size / (1024 * 1024)) / elapsed
                send_json(conn, {"ok": True, "message": "Transfer complete", "sha256": actual_hash,
                                 "elapsed": elapsed, "mb_per_sec": mbps, "saved_as": final_path.name})
                self.log(f"{addr[0]}  |  {mode.upper()}  |  {filename}  |  {size:,} B  |  SHA-256 OK  |  {mbps:.2f} MB/s")
                self.transfer_callback(size, mbps)
        except Exception as exc:
            self.log(f"{addr[0]}  |  ERROR  |  {exc}")
            try:
                send_json(conn, {"ok": False, "message": str(exc)})
            except Exception:
                pass
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

class ServerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SecureLAN | Receiver Console")
        self.geometry("1060x780")
        self.minsize(900, 700)
        self.configure(fg_color=BG)
        self.events = []
        self.total_transfers = 0
        self.total_bytes = 0
        self.status_var = ctk.StringVar(value="STOPPED")
        self.port_var = ctk.StringVar(value=str(DEFAULT_PORT))
        self.server = SecureLANServer(self.log, self.set_status, self.on_transfer)
        self._build()
        self._refresh()
        self._log("Receiver initialized. Start the server when ready.")

    def _card(self, parent, title, subtitle=None):
        frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=16, border_width=1, border_color="#22324A")
        ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=15, weight="bold"), text_color=TEXT).pack(anchor="w", padx=18, pady=(15, 2))
        if subtitle:
            ctk.CTkLabel(frame, text=subtitle, font=ctk.CTkFont(size=11), text_color=MUTED).pack(anchor="w", padx=18, pady=(0, 10))
        return frame

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=30, pady=(24, 16))
        ctk.CTkLabel(header, text="SECURELAN", font=ctk.CTkFont(size=28, weight="bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(header, text="SECURE FILE TRANSFER  /  RECEIVER CONSOLE", font=ctk.CTkFont(size=11, weight="bold"), text_color=ACCENT).pack(anchor="w", pady=(2, 0))
        ctk.CTkLabel(header, text="Monitor incoming TCP transfers, verify file integrity and manage received files.", font=ctk.CTkFont(size=12), text_color=MUTED).pack(anchor="w", pady=(8, 0))

        stats = ctk.CTkFrame(self, fg_color="transparent")
        stats.pack(fill="x", padx=30, pady=(0, 14))
        self.transfer_stat = self._stat(stats, "COMPLETED TRANSFERS", "0")
        self.data_stat = self._stat(stats, "DATA RECEIVED", "0 B")
        self.port_stat = self._stat(stats, "LISTENING PORT", str(DEFAULT_PORT))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=30, pady=(0, 24))
        left = ctk.CTkFrame(body, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))
        right = ctk.CTkFrame(body, fg_color="transparent", width=350)
        right.pack(side="right", fill="both", expand=False)

        net = self._card(left, "01  Network listener", "Start the TCP server and share the LAN address with the sender.")
        net.pack(fill="x", pady=(0, 12))
        inner = ctk.CTkFrame(net, fg_color="transparent")
        inner.pack(fill="x", padx=18, pady=(4, 15))
        ctk.CTkLabel(inner, text="SERVER STATUS", text_color=MUTED, font=ctk.CTkFont(size=10, weight="bold")).grid(row=0, column=0, sticky="w")
        self.status_label = ctk.CTkLabel(inner, textvariable=self.status_var, text_color=RED, font=ctk.CTkFont(size=12, weight="bold"))
        self.status_label.grid(row=0, column=1, sticky="w", padx=12)
        ctk.CTkLabel(inner, text="TCP port", text_color=MUTED).grid(row=1, column=0, sticky="w", pady=(12, 0))
        ctk.CTkEntry(inner, textvariable=self.port_var, width=110, height=38).grid(row=1, column=1, sticky="w", padx=12, pady=(12, 0))
        ctk.CTkButton(inner, text="START SERVER", height=38, fg_color=ACCENT, hover_color="#2563EB", command=self.start).grid(row=1, column=2, padx=5, pady=(12, 0))
        ctk.CTkButton(inner, text="STOP", height=38, fg_color="#334155", hover_color="#475569", command=self.stop).grid(row=1, column=3, padx=5, pady=(12, 0))
        inner.grid_columnconfigure(2, weight=1)

        addresses = ", ".join(local_ipv4_addresses())
        ipcard = self._card(left, "02  Share these connection details", "Use the LAN IP address from this laptop in the sender app.")
        ipcard.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(ipcard, text="LAN IPv4 ADDRESS", text_color=MUTED, font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=18, pady=(3, 3))
        ctk.CTkLabel(ipcard, text=addresses, text_color=TEXT, font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=18, pady=(0, 12))
        ctk.CTkLabel(ipcard, text="SERVER PUBLIC-KEY FINGERPRINT  ·  COPY TO SENDER", text_color=MUTED, font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=18)
        self.fp_entry = ctk.CTkEntry(ipcard, height=40, font=ctk.CTkFont(family="Consolas", size=11))
        self.fp_entry.insert(0, self.server.fingerprint)
        self.fp_entry.configure(state="readonly")
        self.fp_entry.pack(fill="x", padx=18, pady=(5, 15))
        ctk.CTkButton(ipcard, text="OPEN RECEIVED FILES FOLDER", height=38, fg_color="#24364F", hover_color="#304967", command=self.open_folder).pack(anchor="w", padx=18, pady=(0, 15))

        logcard = self._card(right, "Incoming activity", "Live receiver events and integrity results.")
        logcard.pack(fill="both", expand=True)
        self.log_box = ctk.CTkTextbox(logcard, fg_color="#09111E", text_color="#C9D6E8", corner_radius=10, font=ctk.CTkFont(family="Consolas", size=10))
        self.log_box.pack(fill="both", expand=True, padx=16, pady=(6, 16))
        self.log_box.configure(state="disabled")

    def _stat(self, parent, title, value):
        box = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=14, border_width=1, border_color="#22324A")
        box.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkLabel(box, text=title, text_color=MUTED, font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=15, pady=(12, 1))
        label = ctk.CTkLabel(box, text=value, text_color=TEXT, font=ctk.CTkFont(size=20, weight="bold"))
        label.pack(anchor="w", padx=15, pady=(0, 12))
        return label

    def log(self, message):
        self.events.append(("log", message))
    def set_status(self, value):
        self.events.append(("status", value))
    def on_transfer(self, size, speed):
        self.events.append(("transfer", (size, speed)))
    def _log(self, message):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", time.strftime("[%H:%M:%S] ") + message + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")
    def _refresh(self):
        while self.events:
            kind, value = self.events.pop(0)
            if kind == "status":
                self.status_var.set(value)
                self.status_label.configure(text_color=GREEN if value.startswith("RUNNING") else RED)
            elif kind == "log":
                self._log(value)
            else:
                size, speed = value
                self.total_transfers += 1
                self.total_bytes += size
                self.transfer_stat.configure(text=str(self.total_transfers))
                self.data_stat.configure(text=self._format_bytes(self.total_bytes))
                self._log(f"TRANSFER COMPLETE  |  {size:,} bytes  |  {speed:.2f} MB/s")
        self.after(150, self._refresh)
    @staticmethod
    def _format_bytes(value):
        units = ["B", "KB", "MB", "GB"]
        amount = float(value)
        for unit in units:
            if amount < 1024 or unit == "GB":
                return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"
            amount /= 1024
    def start(self):
        try:
            port = int(self.port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
            self.server.start(port)
            self.port_stat.configure(text=str(port))
            self._log(f"Listening on 0.0.0.0:{port}")
        except Exception as exc:
            messagebox.showerror("Could not start server", str(exc))
    def stop(self):
        self.server.stop()
    def open_folder(self):
        os.startfile(str(RECEIVED_DIR))
    def close(self):
        self.server.stop()
        self.destroy()

if __name__ == "__main__":
    app = ServerGUI()
    app.protocol("WM_DELETE_WINDOW", app.close)
    app.mainloop()
