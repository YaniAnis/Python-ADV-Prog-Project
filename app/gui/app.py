import ttkbootstrap as tb
from ttkbootstrap.constants import *

root = tb.Window(themename="minty")
root.geometry("1280x720")
root.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
root.title("Multi-tool")
root.resizable(False, False)


is_dark = False  

def Darkmodefunc():
    global is_dark
    if not is_dark:
        root.style.theme_use("vapor")
        Darkmode_button.config(text="Light Mode", bootstyle="light,outline,toolbutton")
        group_text.config(bootstyle="light")
        is_dark = True
    else:
        root.style.theme_use("minty")
        Darkmode_button.config(text="Dark Mode", bootstyle="dark,outline,toolbutton")
        group_text.config(bootstyle="dark")
        is_dark = False



        



Darkmode_button = tb.Button(
    text="Dark Mode",
    bootstyle="dark,outline,toolbutton",
    command=Darkmodefunc,
    width=20,             
    padding=10 
)
Darkmode_button.place(x=1120, y=60)

exit_button = tb.Button(
    text="Exit",
    bootstyle="danger,outline,toolbutton",
    command=root.destroy,
    width=20,             
    padding=10 
)
exit_button.place(x=1120, y=10)


group_text = tb.Label(root,
                      text=" Our group members : Cherfaoui Mohamed Amine , Mohammed Mariche Anis , Tifahi Mohamed , Likou Yani Anis , Tali Mamar Nacim",
                      font=("Arial", 12),
                      bootstyle="Dark",
                        padding=10
                        )
group_text.place(x=330, y=680)






root.mainloop()
