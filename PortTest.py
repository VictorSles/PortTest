import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import platform
import socket
import threading

# Flag de controle para parar scanner
stop_scan = False

# ----------- Funções Utilitárias -----------

def ping_ip(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", ip]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

def scan_ip_range(prefix, output_box, button_start, button_stop):
    global stop_scan
    stop_scan = False

    prefix = prefix.strip()
    blocks = prefix.split(".")
    output_box.delete(1.0, tk.END)

    button_start["state"] = "disabled"
    button_stop["state"] = "normal"

    if not all(block.isdigit() and 0 <= int(block) <= 255 for block in blocks):
        output_box.insert(tk.END, "❌ Prefixo inválido. Use algo como 192.168.0 ou 10.0\n")
        button_start["state"] = "normal"
        button_stop["state"] = "disabled"
        return

    while len(blocks) < 3:
        blocks.append("0")

    if len(blocks) != 3:
        output_box.insert(tk.END, "❌ O prefixo precisa ter 1 a 3 blocos (ex: 192.168.1)\n")
        button_start["state"] = "normal"
        button_stop["state"] = "disabled"
        return

    base = ".".join(blocks)
    ips_validos = []
    ips_invalidos = []

    output_box.insert(tk.END, f"🔎 Escaneando: {base}.0 - {base}.255\n\n")

    threads = []
    lock = threading.Lock()

    def ping_and_print(ip):
        global stop_scan
        if stop_scan:
            return

        if ping_ip(ip):
            with lock:
                ips_validos.append(ip)
                output_box.insert(tk.END, f"✅ {ip} está ativo\n")
        else:
            with lock:
                ips_invalidos.append(ip)

        output_box.see(tk.END)

    for i in range(256):
        if stop_scan:
            break

        ip = f"{base}.{i}"
        t = threading.Thread(target=ping_and_print, args=(ip,))
        threads.append(t)
        t.start()

        if len(threads) >= 100:
            for th in threads:
                th.join()
            threads = []

    for th in threads:
        th.join()

    if not stop_scan:
        if not ips_validos:
            output_box.insert(tk.END, "\n⚠️ Nenhum IP respondeu ao ping.\n")
        output_box.insert(tk.END, "\n--- IPs inativos ---\n")
        for ip in ips_invalidos:
            output_box.insert(tk.END, f"❌ {ip} sem resposta\n")

    if stop_scan:
        output_box.insert(tk.END, "\n⛔ Scanner interrompido pelo usuário.\n")

    button_start["state"] = "normal"
    button_stop["state"] = "disabled"

def stop_ip_scan():
    global stop_scan
    stop_scan = True

def run_traceroute(entry, output_box):
    target = entry.get()
    if not target:
        messagebox.showwarning("Aviso", "Digite um domínio ou IP de destino.")
        return

    output_box.delete(1.0, tk.END)
    system = platform.system()
    command = ["tracert", target] if system == "Windows" else ["traceroute", target]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        output = result.stdout if result.stdout else result.stderr
        output_box.insert(tk.END, f"--- Traceroute para {target} ---\n{output}")
    except Exception as e:
        messagebox.showerror("Erro", str(e))

def get_dns_info(entry, output_box):
    target = entry.get()
    output_box.delete(1.0, tk.END)

    if not target:
        messagebox.showwarning("Aviso", "Digite um domínio ou IP de destino.")
        return

    try:
        ips = socket.gethostbyname_ex(target)
        output_box.insert(tk.END, f"Host principal: {ips[0]}\nAliases:\n")
        for alias in ips[1]:
            output_box.insert(tk.END, f" - {alias}\n")
        output_box.insert(tk.END, "Endereços IP:\n")
        for ip in ips[2]:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                output_box.insert(tk.END, f" - {ip} ({hostname})\n")
            except:
                output_box.insert(tk.END, f" - {ip} (sem hostname)\n")
    except Exception as e:
        output_box.insert(tk.END, f"Erro: {str(e)}\n")

def scan_port(host, port, output_box):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except:
                service = "desconhecido"
            output_box.insert(tk.END, f"✅ {host}:{port} aberto ({service})\n")
        sock.close()
    except:
        pass

def scan_host_ports(entry, output_box):
    host = entry.get().strip()
    output_box.delete(1.0, tk.END)
    if not host:
        output_box.insert(tk.END, "⚠️ Digite um IP ou hostname válido!\n")
        return

    def run_scan():
        threads = []
        for port in range(1, 1025):
            t = threading.Thread(target=scan_port, args=(host, port, output_box))
            threads.append(t)
            t.start()

            if len(threads) >= 300:
                for th in threads:
                    th.join()
                threads.clear()
        for th in threads:
            th.join()

    threading.Thread(target=run_scan).start()

# ----------- GUI PRINCIPAL -----------

app = tk.Tk()
app.title("Ferramenta de Rede - Estilo Kali Linux")
app.geometry("850x600")
app.configure(bg="#000000")

# Estilo escuro
style = ttk.Style()
style.theme_use("clam")
style.configure("TNotebook", background="#000000", borderwidth=0)
style.configure("TNotebook.Tab", background="#111111", foreground="#00ffff", padding=10, font=("Consolas", 10))
style.map("TNotebook.Tab", background=[("selected", "#222222")])
style.configure("TLabel", background="#000000", foreground="#00ffff", font=("Consolas", 11))
style.configure("TButton", background="#222222", foreground="#ffffff", font=("Consolas", 10))
style.map("TButton", background=[('active', '#444444')])

notebook = ttk.Notebook(app)
notebook.pack(fill="both", expand=True)

# ----------- Aba 1: Ferramentas de Rede -----------

frame_main = tk.Frame(notebook, bg="#000000")
notebook.add(frame_main, text="Ferramentas de Rede")

entry_target = tk.Entry(frame_main, width=40, font=("Consolas", 11),
                        fg="#00ff00", bg="#111111", insertbackground="#00ff00")
entry_target.pack(pady=10)

frame_buttons = ttk.Frame(frame_main)
frame_buttons.pack()

ttk.Button(frame_buttons, text="Traceroute", command=lambda: run_traceroute(entry_target, text_output_main)).pack(side="left", padx=5)
ttk.Button(frame_buttons, text="Ver IPs/Hostnames", command=lambda: get_dns_info(entry_target, text_output_main)).pack(side="left", padx=5)
ttk.Button(frame_buttons, text="Varredura de Portas", command=lambda: scan_host_ports(entry_target, text_output_main)).pack(side="left", padx=5)

text_output_main = tk.Text(frame_main, wrap="word", bg="#000000", fg="#00ff00", insertbackground="#00ff00",
                           font=("Consolas", 10))
text_output_main.pack(padx=10, pady=10, fill="both", expand=True)

# ----------- Aba 2: Scanner de IPs -----------

frame_ip_scan = tk.Frame(notebook, bg="#000000")
notebook.add(frame_ip_scan, text="Scanner de IPs (Faixa)")

label_ip_range = ttk.Label(frame_ip_scan, text="Digite o prefixo de IP (ex: 192.168.0 ou 10.0):")
label_ip_range.pack(pady=10)

entry_ip_range = tk.Entry(frame_ip_scan, width=30, font=("Consolas", 11),
                          fg="#00ff00", bg="#111111", insertbackground="#00ff00")
entry_ip_range.pack()

frame_ip_buttons = ttk.Frame(frame_ip_scan)
frame_ip_buttons.pack(pady=5)

btn_start_ip = ttk.Button(frame_ip_buttons, text="Iniciar Scanner de IPs")
btn_start_ip.pack(side="left", padx=5)

btn_stop_ip = ttk.Button(frame_ip_buttons, text="Parar Scanner", command=stop_ip_scan, state="disabled")
btn_stop_ip.pack(side="left", padx=5)

btn_start_ip.config(command=lambda: threading.Thread(target=scan_ip_range, args=(entry_ip_range.get(), text_output_ips, btn_start_ip, btn_stop_ip)).start())

text_output_ips = tk.Text(frame_ip_scan, wrap="word", bg="#000000", fg="#00ff00", insertbackground="#00ff00",
                          font=("Consolas", 10))
text_output_ips.pack(padx=10, pady=10, fill="both", expand=True)

# ----------- Iniciar o App -----------

app.mainloop()
