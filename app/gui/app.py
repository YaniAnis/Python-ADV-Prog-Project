import ttkbootstrap as tb
from ttkbootstrap.constants import *

root = tb.Window(themename="minty")
root.geometry("1280x720")
root.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
root.title("Multi-tool")
root.resizable(False, False)



def open_passcracker():
    new_win = tb.Toplevel(root)
    new_win.title("Password Cracker")
    new_win.geometry("1024x600")
    new_win.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
    new_win.resizable(False, False)

   
    password_label=tb.Label(new_win, text="Bienvenue dans Password Cracker !", font=("Helvetica", 14),padding=10)
    password_label.place(x=150, y=40)  # position en pixels
    password_exit=tb.Button(new_win, text="Fermer", bootstyle="danger", command=new_win.destroy)
    password_exit.place(x=950, y=10)
    



def open_webscanner():
    new_win2 = tb.Toplevel(root)
    new_win2.title("Web Scanner")
    new_win2.geometry("1024x600")
    new_win2.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
    new_win2.resizable(False, False)

   
    Web_label=tb.Label(new_win2, text="Bienvenue dans Web_scanner!", font=("Helvetica", 14),padding=10)
    Web_label.place(x=150, y=40)  # position en pixels
    Web_exit=tb.Button(new_win2, text="Fermer", bootstyle="danger", command=new_win2.destroy)
    Web_exit.place(x=950, y=10)


def open_Exploiter():
    new_win3 = tb.Toplevel(root)
    new_win3.title("Web Scanner")
    new_win3.geometry("1024x600")
    new_win3.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
    new_win3.resizable(False, False)

   
    Exploiter_label=tb.Label(new_win3, text="Bienvenue dans Exploiter!", font=("Helvetica", 14),padding=10)
    Exploiter_label.place(x=150, y=40)  # position en pixels
    Exploiter_exit=tb.Button(new_win3, text="Fermer", bootstyle="danger", command=new_win3.destroy)
    Exploiter_exit.place(x=950, y=10)




def open_PortScan():
    new_win4 = tb.Toplevel(root)
    new_win4.title("Port Scanner")
    new_win4.geometry("1024x600")
    new_win4.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
    new_win4.resizable(False, False)

   
    Port_label=tb.Label(new_win4, text="Bienvenue dans Port Scanner!", font=("Helvetica", 14),padding=10)
    Port_label.place(x=150, y=40)  # position en pixels
    Port_exit=tb.Button(new_win4, text="Fermer", bootstyle="danger", command=new_win4.destroy)
    Port_exit.place(x=950, y=10)


var_dark = tb.IntVar()

def toggle_darkmode():
   
    if var_dark.get() == 1:
        root.style.theme_use("vapor")
        Darkmode_switch.config(text="Dark Mode", bootstyle="success,round-toggle")
        group_text.config(bootstyle="light")
        Tools_text.config(bootstyle="light")
        explication_label.config(bootstyle="light")
        PassCracker_button.config(bootstyle="info,outline")
        PortScanner_button.config(bootstyle="primary,outline")
        Exploiter_button.config(bootstyle="secondary,outline")
        webscanner_button.config(bootstyle="warning,outline")
     
    else:
        root.style.theme_use("minty")
        Darkmode_switch.config(text="Light Mode", bootstyle="info,round-toggle")
        group_text.config(bootstyle="dark")
        Tools_text.config(bootstyle="dark")
        explication_label.config(bootstyle="dark")
        PassCracker_button.config(bootstyle="info")
        PortScanner_button.config(bootstyle="primary")
        Exploiter_button.config(bootstyle="secondary")
        webscanner_button.config(bootstyle="warning")
       



Darkmode_switch = tb.Checkbutton(
    text="Light Mode",
    variable=var_dark,
    bootstyle="info,round-toggle , font= ('Arial', 12)",
    command=toggle_darkmode
)

Darkmode_switch.place(x=1150, y=60)


exit_button = tb.Button(
    text="Exit",
    bootstyle="danger,outline",
    command=root.destroy,
    width=20,
    padding=10
)
exit_button.place(x=1120, y=10)


group_text = tb.Label(
    root,
    text=" Our group members : Cherfaoui Mohamed Amine , Mohammed Mariche Anis , Tifahi Mohamed , Likou Yani Anis , Tali Mamar Nacim",
    font=("Arial", 12),
    bootstyle="Dark",
    padding=10
)
group_text.place(x=330, y=680)


Tools_text = tb.Label(
    root,
    text=" Tools : ",
    font=("Arial", 20,"bold","underline"),
    bootstyle="Dark",
    padding=10
)
Tools_text.place(x=50, y=20)


PassCracker_button = tb.Button(
    text="Password Cracker",
    bootstyle="info",
    width=20,
    padding=10,
    command=open_passcracker
)
PassCracker_button.place(x=50, y=100)

PortScanner_button = tb.Button(
    text="Port Scanner",
    bootstyle="primary",
    width=20,
    padding=10,
    command=open_PortScan
)
PortScanner_button.place(x=50, y=250)

Exploiter_button = tb.Button(
    text="Exploit Manager",
    bootstyle="secondary",
    width=20,
    padding=10,
    command=open_Exploiter
)
Exploiter_button.place(x=50, y=400)

webscanner_button = tb.Button(
    text="Web Scanner",
    bootstyle="warning",
    width=20,
    padding=10,
    command=open_webscanner
)
webscanner_button.place(x=50, y=550)

frame = tb.LabelFrame(
    root,
    text="Présentation",
    padding=12,
    bootstyle="info"   # style du cadre
)
frame.pack(expand=True)


explication_label = tb.Label(
    frame,
    text=(
        "Welcome to our multi-tool application!\n"
        "It's a tool in an educative way for our advanced programming TP.\n\n"
        "You can find :\n"
        "- password cracker\n"
        "- port scanner\n"
        "- exploit manager\n"
        "- web scanner\n\n"
        "Choose a tool from the left to get started."
    ),
    font=("Arial", 12),
    bootstyle="dark",
    padding=8,
    justify="left",
    wraplength=520   # limite la largeur du texte et force le retour à la ligne
)
explication_label.pack(fill="both", expand=True)

root.mainloop()
