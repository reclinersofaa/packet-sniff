import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

PORT = 8000

# --- Packet Sending Function ---
def send_packet(protocol, target_ip, message, log_output):
    try:
        if protocol == "TCP":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_ip, PORT))
                s.sendall(message.encode())
        elif protocol == "UDP":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(message.encode(), (target_ip, PORT))

        log_output.configure(state='normal')
        log_output.insert(tk.END, f"[Sent] {protocol} to {target_ip}:{PORT} > {message}\n", 'sent')
        log_output.configure(state='disabled')
    except Exception as e:
        log_output.configure(state='normal')
        log_output.insert(tk.END, f"[Error] {e}\n", 'error')
        log_output.configure(state='disabled')


# --- Packet Sniffing Function ---
def start_sniffing(log_output, expected_src_ip, filter_enabled):
    def packet_callback(packet):
        try:
            if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                src = packet[IP].src
                dst = packet[IP].dst
                proto = "TCP" if packet.haslayer(TCP) else "UDP"
                length = len(packet)
                timestamp = datetime.now().strftime("%H:%M:%S")

                ttl = packet[IP].ttl
                ip_id = packet[IP].id
                ip_checksum = packet[IP].chksum

                flags = packet.sprintf("%TCP.flags%") if packet.haslayer(TCP) else "-"
                payload = packet[Raw].load.decode(errors='ignore') if packet.haslayer(Raw) else ""

                tag = 'tcp' if proto == 'TCP' else 'udp'
                extra = f"TTL: {ttl}, IP-ID: {ip_id}, IP-Chk: {ip_checksum}"

                if proto == "TCP":
                    seq = packet[TCP].seq
                    ack = packet[TCP].ack
                    tcp_checksum = packet[TCP].chksum
                    extra += f", SEQ: {seq}, ACK: {ack}, TCP-Chk: {tcp_checksum}"

                if not filter_enabled or src == expected_src_ip:
                    log_output.configure(state='normal')
                    log_output.insert(tk.END,
                        f"[{timestamp}] {proto} {flags} from {src} to {dst} ({length} bytes)\n",
                        tag)
                    log_output.insert(tk.END, f"   {extra}\n", tag)

                    if proto == "TCP" and payload.strip() != "":
                        log_output.insert(tk.END, f"   Payload: {payload}\n\n", ('bold', tag))
                    else:
                        payload_display = payload if payload else "<No Payload>"
                        log_output.insert(tk.END, f"   Payload: {payload_display}\n\n", tag)

                    log_output.configure(state='disabled')

        except Exception as e:
            log_output.configure(state='normal')
            log_output.insert(tk.END, f"[Sniff Error] {e}\n", 'error')
            log_output.configure(state='disabled')

    log_output.configure(state='normal')
    msg = f"[*] Sniffing packets on port {PORT}"
    if filter_enabled:
        msg += f" from {expected_src_ip}"
    log_output.insert(tk.END, msg + "...\n", 'info')
    log_output.configure(state='disabled')

    sniff(filter=f"tcp port {PORT} or udp port {PORT}", prn=packet_callback, store=0)


# --- GUI Setup ---
def create_app():
    root = tk.Tk()
    root.title("Packet Tool")
    root.geometry("850x700")
    root.configure(bg="#121212")

    style = ttk.Style()
    style.theme_use("default")
    style.configure("TFrame", background="#121212")
    style.configure("TLabel", background="#121212", foreground="#FFFFFF", font=("Segoe UI", 10))
    style.configure("TButton", background="#007acc", foreground="white", font=("Segoe UI", 10, "bold"))
    style.configure("TCheckbutton", background="#121212", foreground="white")
    style.configure("TLabelframe", background="#121212", foreground="#FFFFFF", font=("Segoe UI", 10, "bold"))
    style.configure("TLabelframe.Label", background="#121212", foreground="#FFFFFF")

    send_frame = ttk.LabelFrame(root, text="Send Packet")
    send_frame.pack(fill="x", padx=10, pady=5)

    ttk.Label(send_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
    ip_entry = ttk.Entry(send_frame, width=30)
    ip_entry.insert(0, "127.0.0.1")
    ip_entry.grid(row=0, column=1, padx=5, pady=5)

    ttk.Label(send_frame, text="Protocol:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
    protocol_var = tk.StringVar(value="TCP")
    protocol_combo = ttk.Combobox(send_frame, textvariable=protocol_var, values=["TCP", "UDP"], state="readonly", width=10)
    protocol_combo.grid(row=1, column=1, padx=5, pady=5, sticky="w")

    ttk.Label(send_frame, text="Message:").grid(row=2, column=0, padx=5, pady=5, sticky="ne")
    message_entry = tk.Text(send_frame, height=3, width=60, bg="#1e1e1e", fg="#FFFFFF", insertbackground="#FFFFFF")
    message_entry.grid(row=2, column=1, padx=5, pady=5)

    send_button = ttk.Button(send_frame, text="Send",
                             command=lambda: send_packet(protocol_var.get(), ip_entry.get(), message_entry.get("1.0", tk.END).strip(), output_text))
    send_button.grid(row=3, column=1, sticky="e", pady=5)

    sniff_frame = ttk.LabelFrame(root, text="Sniff Packets")
    sniff_frame.pack(fill="x", padx=10, pady=5)

    filter_var = tk.BooleanVar(value=True)
    filter_checkbox = ttk.Checkbutton(sniff_frame, text="Filter by Source IP", variable=filter_var)
    filter_checkbox.pack(pady=2)

    sniff_button = ttk.Button(sniff_frame, text="Start Sniffing",
                              command=lambda: threading.Thread(target=start_sniffing, args=(output_text, ip_entry.get(), filter_var.get()), daemon=True).start())
    sniff_button.pack(pady=5)

    clear_button = ttk.Button(sniff_frame, text="Clear Packets", command=lambda: output_text.configure(state='normal') or output_text.delete(1.0, tk.END) or output_text.configure(state='disabled'))
    clear_button.pack(pady=5)

    global output_text
    output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=25, bg="#1e1e1e", fg="white", insertbackground="white")
    output_text.pack(fill="both", expand=True, padx=10, pady=10)

    # Tag styles
    output_text.tag_config('tcp', foreground="#4EC9B0")
    output_text.tag_config('udp', foreground="#C586C0")
    output_text.tag_config('sent', foreground="#9CDCFE")
    output_text.tag_config('error', foreground="#F44747")
    output_text.tag_config('info', foreground="#DCDCAA")
    output_text.tag_config('bold', font=("Segoe UI", 10, "bold"))

    output_text.configure(state='disabled')
    root.mainloop()


if __name__ == "__main__":
    create_app()

