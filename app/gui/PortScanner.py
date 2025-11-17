import asyncio
import threading
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import time

# ---------------------------------------------------
#  PORT SCANNER ASYNC
# ---------------------------------------------------

async def scan_port(host, port, timeout=1.0):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True
    except Exception:
        return port, False


async def scan_ports(host, ports, concurrency=500, timeout=1.0):
    sem = asyncio.Semaphore(concurrency)

    async def sem_scan(p):
        async with sem:
            return await scan_port(host, p, timeout)

    tasks = [asyncio.create_task(sem_scan(p)) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted([p for p, ok in results if ok])


# ---------------------------------------------------
#  INTERFACE TK + TTKBOOTSTRAP
# ---------------------------------------------------

class PortScannerUI:

    def __init__(self, master):
        self.window = master
        self.window.title("Port Scanner")
        self.window.geometry("600x500")
        self.window.resizable(False, False)

        # --- Inputs
        tb.Label(self.window, text="Host :", font=("Helvetica", 12)).place(x=30, y=30)
        self.entry_host = tb.Entry(self.window, width=25)
        self.entry_host.place(x=120, y=30)

        tb.Label(self.window, text="Start Port :", font=("Helvetica", 12)).place(x=30, y=70)
        self.entry_start = tb.Entry(self.window, width=10)
        self.entry_start.place(x=120, y=70)

        tb.Label(self.window, text="End Port :", font=("Helvetica", 12)).place(x=250, y=70)
        self.entry_end = tb.Entry(self.window, width=10)
        self.entry_end.place(x=330, y=70)

        # --- Scan Button
        tb.Button(
            self.window,
            text="Scanner",
            bootstyle="success",
            command=self.start_scan_thread
        ).place(x=450, y=65)

        # --- Logs output
        self.text_output = tb.ScrolledText(self.window, width=70, height=20)
        self.text_output.place(x=30, y=120)

    # ---------------------------------------------------
    #  THREAD POUR LANCER ASYNCIO SANS BLOQUER TKINTER
    # ---------------------------------------------------
    def start_scan_thread(self):
        t = threading.Thread(target=self.run_scan, daemon=True)
        t.start()

    def run_scan(self):
        host = self.entry_host.get()
        try:
            start = int(self.entry_start.get())
            end = int(self.entry_end.get())
        except:
            self.append_output("⚠️ Ports invalides")
            return

        ports = range(start, end + 1)

        self.append_output(f"\n🔍 Scanning {host} {start}-{end}...\n")

        t0 = time.time()
        result = asyncio.run(scan_ports(host, ports))

        self.append_output(f"✔ Ports ouverts : {result}\n")
        self.append_output(f"⏱ Temps écoulé : {time.time() - t0:.2f}s\n")

    # ---------------------------------------------------
    #  MISE À JOUR DU TEXTBOX (thread-safe)
    # ---------------------------------------------------
    def append_output(self, text):
        self.text_output.insert("end", text)
        self.text_output.see("end")


# ---------------------------------------------------
#  MAIN WINDOW
# ---------------------------------------------------

if __name__ == "__main__":
    app = tb.Window(themename="darkly")
    PortScannerUI(app)
    app.mainloop()
