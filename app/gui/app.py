import ttkbootstrap as tb
from ttkbootstrap.constants import *
from PasswordCracker import PasswordCracker 
from PortScanner import PortScanner
from ExploitManager import ExploitManager
from WebScanner import WebScanner

class Home(tb.Window):
    def __init__(self):
        super().__init__(themename="minty")
        self.overrideredirect(True)
        self.title("Multi-tool")
        self.geometry("1280x720")
        self.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
        self.resizable(False, False)
        self.ui()
        self.mainloop()

    def ui(self):
        self.topbar = tb.Frame(self, height=48)
        self.topbar.place(x=0, y=0, relwidth=1)

        self.logo = tb.PhotoImage(file="app/assets/logo-tete-de-mort-png.png")
        self.logo_label = tb.Label(self.topbar, image=self.logo, bootstyle="light")
        self.logo_label.place(x=10, y=6)

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
        exit_button.place_forget()
        exit_button.master = self.topbar
        exit_button.place(x=1120, y=10)

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
        ).place(x=50, y=100)

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
            text="Exploit Manager",
            bootstyle="secondary",
            width=20,
            padding=10,
            command=lambda: ExploitManager(self)
        ).place(x=50, y=400)

        tb.Button(
            self,
            text="Web Scanner",
            bootstyle="warning",
            width=20,
            padding=10,
            command=lambda: WebScanner(self)
        ).place(x=50, y=550)

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
                "You can find :\n"
                "- Password Cracker\n"
                "- Port Scanner\n"
                "- Exploit Manager\n"
                "- Web Scanner\n\n"
                "Choose a tool from the left to get started."
            ),
            font=("Arial", 12),
            bootstyle="dark",
            padding=8,
            justify="left",
            wraplength=520
        )
        self.explication_label.pack(fill="both", expand=True)

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
