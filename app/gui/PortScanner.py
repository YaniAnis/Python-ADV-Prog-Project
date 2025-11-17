import asyncio
import tkinter as tk
from tkinter import ttk
import re
import time

# ==========================
#   SCAN ASYNCIO
# ==========================
async def scan_port(host, port):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=1
        )
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None


async def scan_ports(host, ports, concurrency=500):
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def sem_task(p):
        async with semaphore:
            return await scan_port(host, p)

    tasks = [asyncio.create_task(sem_task(p)) for p in ports]
    for t in asyncio.as_completed(tasks):
        r = await t
        if r:
            results.append(r)

    return results


# ================ UTILS ================

def clean_num(s: str) -> str:
    """Supprime tous les espaces et caractères invisibles."""
    if not s:
        return ""
    return re.sub(r"\s+", "", s)


# ==========================
#  GUI PORT SCANNER
# ==========================
class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Port Scanner — Asyncio Ultra-Fast")
        root.geometry("650x520")   # Taille modifiable
        root.minsize(650, 520)

        # ------ Style moderne ------
        style = ttk.Style()
        style.configure("TLabel", font=("Segoe UI", 11))
        style.configure("TButton", font=("Segoe UI", 11), padding=6)
        style.configure("TEntry", font=("Segoe UI", 11))

        # Cadre principal
        frame = ttk.Frame(root, padding=20)
        frame.pack(fill="both", expand=True)

        # ================= CHAMPS =================
        ttk.Label(frame, text="Adresse IP / Host :").grid(row=0, column=0, sticky="w")
        self.entry_host = ttk.Entry(frame, width=30)
        self.entry_host.grid(row=0, column=1, pady=5, sticky="w")

        ttk.Label(frame, text="Port début :").grid(row=1, column=0, sticky="w")
        self.entry_start = ttk.Entry(frame, width=10)
        self.entry_start.grid(row=1, column=1, sticky="w")
        self.entry_start.insert(0, "1")

        ttk.Label(frame, text="Port fin :").grid(row=2, column=0, sticky="w")
        self.entry_end = ttk.Entry(frame, width=10)
        self.entry_end.grid(row=2, column=1, sticky="w")
        self.entry_end.insert(0, "1024")

        ttk.Label(frame, text="Concurrency (tâches simultanées) :").grid(row=3, column=0, sticky="w")
        self.entry_concurrency = ttk.Entry(frame, width=10)
        self.entry_concurrency.grid(row=3, column=1, sticky="w")
        self.entry_concurrency.insert(0, "500")

        # ================= BOUTON =================
        self.button_scan = ttk.Button(frame, text="Démarrer le scan", command=self.run_scan)
        self.button_scan.grid(row=4, column=0, columnspan=2, pady=15)

        # ================= ZONE DE TEXTE =================
        self.output = tk.Text(frame, height=15, width=70, font=("Consolas", 11), bg="#1e1e1e", fg="#dcdcdc")
        self.output.grid(row=5, column=0, columnspan=2, pady=10)

    # Ajouter texte dans l'output
    def append_output(self, text):
        self.output.insert(tk.END, text)
        self.output.see(tk.END)

    # =============== LOGIQUE DE SCAN ===============
    def run_scan(self):
        host = (self.entry_host.get() or "").strip()

        start_str = clean_num(self.entry_start.get())
        end_str = clean_num(self.entry_end.get())
        concurrency_str = clean_num(self.entry_concurrency.get())

        # Valeurs par défaut
        if start_str == "": start_str = "1"
        if end_str == "": end_str = "1024"
        if concurrency_str == "": concurrency_str = "500"

        # Validation numérique
        try:
            start = int(start_str)
            end = int(end_str)
            concurrency = int(concurrency_str)
        except ValueError:
            self.append_output("⚠️ Erreur : Valeurs non numériques.\n")
            return

        # Bornes
        if start < 1: start = 1
        if end > 65535: end = 65535
        if start > end:
            self.append_output("⚠️ Erreur : Port début doit être ≤ port fin.\n\n")
            return
        if concurrency < 1:
            self.append_output("⚠️ Erreur : concurrency doit être ≥ 1.\n\n")
            return

        ports = range(start, end + 1)

        self.append_output(f"🚀 Scan de {host} ({start} → {end}) avec concurrency={concurrency}\n")
        t0 = time.time()

        # Lancer asyncio dans Tkinter
        self.root.after(50, lambda: self.async_scan(host, ports, concurrency, t0))

    # Exécuter asyncio sans bloquer Tkinter
    def async_scan(self, host, ports, concurrency, t0):
        result = asyncio.run(scan_ports(host, ports, concurrency))

        self.append_output(f"✅ Ports ouverts : {result}\n")
        self.append_output(f"⏱ Temps écoulé : {time.time() - t0:.2f}s\n\n")


# ==========================
#     MAIN
# ==========================
if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()
