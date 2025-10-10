import ttkbootstrap as tb
from ttkbootstrap.constants import *

root = tb.Window(themename="minty")
root.geometry("1280x720")
root.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
root.title("Multi-tool")
root.resizable(False, False)



is_dark = False
var_dark = tb.IntVar()

def toggle_darkmode():
    global is_dark
    if var_dark.get() == 1:
        root.style.theme_use("vapor")
        Darkmode_switch.config(text="Dark Mode", bootstyle="success,round-toggle")
        group_text.config(bootstyle="light")
        Tools_text.config(bootstyle="light")
        PassCracker_button.config(bootstyle="info,outline")
        PortScanner_button.config(bootstyle="primary,outline")
        Exploiter_button.config(bootstyle="secondary,outline")
        webscanner_button.config(bootstyle="warning,outline")
        is_dark = True
    else:
        root.style.theme_use("minty")
        Darkmode_switch.config(text="Light Mode", bootstyle="info,round-toggle")
        group_text.config(bootstyle="dark")
        Tools_text.config(bootstyle="dark")
        PassCracker_button.config(bootstyle="info")
        PortScanner_button.config(bootstyle="primary")
        Exploiter_button.config(bootstyle="secondary")
        webscanner_button.config(bootstyle="warning")
        is_dark = False



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
    font=("Arial", 20),
    bootstyle="Dark",
    padding=10
)
Tools_text.place(x=50, y=20)


PassCracker_button = tb.Button(
    text="Password Cracker",
    bootstyle="info",
    width=20,
    padding=10
)
PassCracker_button.place(x=50, y=100)

PortScanner_button = tb.Button(
    text="Port Scanner",
    bootstyle="primary",
    width=20,
    padding=10
)
PortScanner_button.place(x=50, y=250)

Exploiter_button = tb.Button(
    text="Exploit Manager",
    bootstyle="secondary",
    width=20,
    padding=10
)
Exploiter_button.place(x=50, y=400)

webscanner_button = tb.Button(
    text="Web Scanner",
    bootstyle="warning",
    width=20,
    padding=10
)
webscanner_button.place(x=50, y=550)

root.mainloop()
