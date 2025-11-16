import ttkbootstrap as tb
from ttkbootstrap.constants import *
from PasswordCracker import PasswordCracker 
from PortScanner import PortScanner
from DirectoryFuzzer import DirectoryFuzzer
from HashCracking import HashCracking
from SubdomainFinder import SubdomainFinderGUI

class Home(tb.Window):
    def __init__(self):
        super().__init__(themename="minty")
        self.title("Multi-tool")
        self.geometry("1280x720")
        self.resizable(False, False)
        self.ui()
        self.mainloop()

    def ui(self):
        self.var_dark = tb.IntVar(value=0)
        self.dark_switch = tb.Checkbutton(
            self,
            text="Light Mode",
            variable=self.var_dark,
            bootstyle="info,round-toggle",
            command=self.toggle_darkmode
        )
        self.dark_switch.place(x=1150, y=60)

        exit_button = tb.Button(
            self,
            text="Exit",
            bootstyle="danger,outline",
            command=self.destroy,
            width=20,
            padding=10
        )
        exit_button.place(x=1090, y=10)

        self.group_text = tb.Label(
            self,
            text="Our group members : Cherfaoui Mohamed Amine, Mohammed Mariche Anis, Tifahi Mohamed, Likou Yani Anis, Tali Mamar Nacim",
            font=("Arial", 12),
            bootstyle="dark",
            padding=10
        )
        self.group_text.place(x=250, y=680)

        self.tools_text = tb.Label(
            self,
            text="Tools : ",
            font=("Arial", 20, "bold", "underline"),
            bootstyle="dark",
            padding=10
        )
        self.tools_text.place(x=50, y=20)

        tb.Button(
            self,
            text="Password Cracker",
            bootstyle="info",
            width=20,
            padding=10,
            command=lambda: PasswordCracker(self)
        ).place(x=50, y=150)

        tb.Button(
            self,
            text="Port Scanner",
            bootstyle="primary",
            width=20,
            padding=10,
            command=lambda: PortScanner(self)
        ).place(x=50, y=250)

        

        tb.Button(
            self,
            text="Directory Fuzzer",
            bootstyle="warning",
            width=20,
            padding=10,
            command=lambda: DirectoryFuzzer(self)
        ).place(x=50, y=350)

        frame = tb.LabelFrame(
            self,
            text="Présentation",
            padding=12,
            bootstyle="info"
        )
        frame.pack(expand=True)

        self.explication_label = tb.Label(
            frame,
            text=(
                "Welcome to our multi-tool application!\n"
                "It's an educational tool for our Advanced Programming TP.\n\n"
                "Available Tools:\n"
                "- Password Cracker - Crack various password types\n"
                "- Port Scanner - Network port enumeration\n"
                "- Exploit Manager - Vulnerability testing framework\n"
                "- Directory Fuzzer - Web directory discovery\n"
                "- Hash Cracking - Password hash analysis\n"
                "- Subdomain Finder - Comprehensive subdomain enumeration\n\n"
                "Choose a tool to get started with your cybersecurity testing!"
            ),
            font=("Arial", 12),
            bootstyle="dark",
            padding=8,
            justify="left",
            wraplength=520
        )
        self.explication_label.pack(fill="both", expand=True)
        
        tb.Button(
            self,
            text="Hash Cracking",
            bootstyle="danger",
            width=20,
            padding=10,
            command=lambda: HashCracking(self)
        ).place(x=50, y=450)

        tb.Button(
            self,
            text="Subdomain Finder",
            bootstyle="success",
            width=20,
            padding=10,
            command=lambda: SubdomainFinderGUI(self)
        ).place(x=300, y=550)
            

    def toggle_darkmode(self):
        if self.var_dark.get() == 1:
            self.style.theme_use("vapor")
            self.dark_switch.config(text="Dark Mode", bootstyle="success,round-toggle")
            self.group_text.config(bootstyle="light")
            self.tools_text.config(bootstyle="light")
            self.explication_label.config(bootstyle="light")
        else:
            self.style.theme_use("minty")
            self.dark_switch.config(text="Light Mode", bootstyle="info,round-toggle")
            self.group_text.config(bootstyle="dark")
            self.tools_text.config(bootstyle="dark")
            self.explication_label.config(bootstyle="dark")

if __name__ == "__main__":
    Home()
