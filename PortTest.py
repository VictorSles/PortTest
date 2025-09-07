import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

# Função para escanear uma porta
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
            output_box.insert(tk.END, f"✅ {host}:{port}/TCP aberto ({service})\n")
            output_box.see(tk.END)  # rola para o final
        sock.close()
    except:
        pass

# Função principal para iniciar o scan
def scan_host(host, output_box):
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"\n🔎 Escaneando {host} (1–65535)...\n\n")
    threads = []

    for port in range(1, 65536):
        t = threading.Thread(target=scan_port, args=(host, port, output_box))
        threads.append(t)
        t.start()

        if len(threads) >= 500:  # limita threads simultâneas
            for th in threads:
                th.join()
            threads = []

    for th in threads:  # finaliza as restantes
        th.join()

# Função chamada pelo botão
def start_scan(entry, output_box):
    host = entry.get().strip()
    if host:
        threading.Thread(target=scan_host, args=(host, output_box)).start()
    else:
        output_box.insert(tk.END, "⚠️ Digite um IP ou hostname válido!\n")

# GUI com Tkinter
def main():
    root = tk.Tk()
    root.title("Scanner de Portas TCP")
    root.geometry("700x500")

    # Label
    tk.Label(root, text="Digite o IP ou Hostname:", font=("Arial", 12)).pack(pady=5)

    # Input
    entry = tk.Entry(root, width=40, font=("Arial", 12))
    entry.pack(pady=5)

    # Botão
    btn = tk.Button(root, text="Iniciar Varredura", font=("Arial", 12), 
                    command=lambda: start_scan(entry, output_box))
    btn.pack(pady=10)

    # Caixa de texto para saída
    output_box = scrolledtext.ScrolledText(root, width=80, height=20, font=("Consolas", 10))
    output_box.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
