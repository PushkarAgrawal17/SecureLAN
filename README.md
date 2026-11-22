# SecureLAN — Final Windows LAN Project

SecureLAN is a two-laptop Computer Networks demonstration with a modern dark dashboard UI.

## Included features
- TCP socket file transfer over the same Wi-Fi/LAN.
- Normal mode for controlled plaintext comparison in Wireshark.
- Secure mode: RSA-OAEP wraps a fresh AES-256 key; AES-256-GCM encrypts and authenticates the file.
- Receiver identity verification using a SHA-256 fingerprint copied from the receiver window.
- SHA-256 file digest verification before the receiver saves the final file.
- Live progress, transfer speed, elapsed time, status and activity logs.
- Receiver statistics: completed transfers and total data received.
- Files are saved in `received_files/`.

## Requirements
- Windows 10/11 on both laptops.
- Python 3.10+ on both laptops.
- Both laptops on the same non-guest Wi-Fi/LAN.
- Wireshark for packet inspection (optional for running the app).

## Install (both laptops)
1. Extract the complete `SecureLAN_Final` folder.
2. Open PowerShell or Command Prompt inside that folder.
3. Run:
   `py -m pip install -r requirements.txt`

## Receiver laptop
1. Run `py server.py`.
2. Click **START SERVER**.
3. Share the displayed LAN IPv4 address, port, and public-key fingerprint with the sender.
4. If Windows Firewall prompts, allow Python on **Private networks** only.
5. Received files appear in `received_files/`.

## Sender laptop
1. Run `py client.py`.
2. Enter the receiver's LAN IP and port (default 5000).
3. For Secure mode, paste the exact fingerprint displayed by the receiver.
4. Choose a file and click **SEND FILE**.
5. Check the receiver's `received_files/` folder.

## Wireshark
Display filter:
`tcp.port == 5000`

Follow a TCP stream to inspect the application traffic. In Normal mode the original file bytes are sent without encryption. In Secure mode the file payload is AES-GCM ciphertext; protocol metadata and traffic characteristics can still be visible. IP addresses, TCP ports, packet lengths, timing and traffic volume remain observable.

The custom protocol is TCP with RSA-OAEP + AES-256-GCM; it is **not TLS**. Do not describe it as a TLS handshake.

## Important
- Normal mode is intentionally insecure and only for harmless classroom demonstration data.
- Secure mode's server identity check depends on manually copying the fingerprint from the trusted receiver window.
- This is a lab prototype, not a production file-transfer service.
- The implemented key transport is RSA-OAEP. Diffie-Hellman and NS-2 are not part of this runnable version; confirm with your instructor whether those synopsis items are mandatory or can be discussed as future extensions.
