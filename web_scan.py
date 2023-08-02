#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# GUI module generated by PAGE version 5.3
#  in conjunction with Tcl version 8.6
#    Jun 11, 2020 02:48:45 PM EDT  platform: Linux

import sys

try:
    import Tkinter as tk
except ImportError:
    import tkinter as tk

try:
    import ttk
    py3 = False
except ImportError:
    import tkinter.ttk as ttk
    py3 = True

import web_scan_support
import os.path


def vp_start_gui():
    '''Starting point when module is the main routine.'''
    global val, w, root
    global prog_location
    prog_call = sys.argv[0]
    prog_location = os.path.split(prog_call)[0]
    root = tk.Tk()
    top = Toplevel1 (root)
    web_scan_support.init(root, top)
    root.mainloop()


w = None


def create_Toplevel1(rt, *args, **kwargs):
    '''Starting point when module is imported by another module.
       Correct form of call: 'create_Toplevel1(root, *args, **kwargs)' .'''
    global w, w_win, root
    global prog_location
    prog_call = sys.argv[0]
    prog_location = os.path.split(prog_call)[0]
    #rt = root
    root = rt
    w = tk.Toplevel(root)
    top = Toplevel1(w)
    web_scan_support.init(w, top, *args, **kwargs)
    return w, top


def destroy_Toplevel1():
    global w
    w.destroy()
    w = None


class Toplevel1:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''
        _bgcolor = '#d9d9d9'  # X11 color: 'gray85'
        _fgcolor = '#000000'  # X11 color: 'black'
        _compcolor = '#d9d9d9'  # X11 color: 'gray85'
        _ana1color = '#d9d9d9'  # X11 color: 'gray85'
        _ana2color = '#ececec'  # Closest X11 color: 'gray92'
        self.style = ttk.Style()
        if sys.platform == "win32":
            self.style.theme_use('winnative')
        self.style.configure('.', background=_bgcolor)
        self.style.configure('.', foreground=_fgcolor)
        self.style.configure('.', font="TkDefaultFont")
        self.style.map('.', background=[('selected', _compcolor), ('active', _ana2color)])

        top.geometry("844x532+590+212")
        top.minsize(750, 460)
        top.maxsize(1905, 945)
        top.resizable(1, 1)
        top.title("Web Scanner")
        top.configure(background="#c5d8d7")
        top.configure(highlightcolor="black")

        self.Entry1 = tk.Entry(top)
        self.Entry1.place(relx=0.15, rely=0.068,height=33, relwidth=0.28)
        self.Entry1.configure(background="white")
        self.Entry1.configure(font="TkFixedFont")
        self.Entry1.configure(selectbackground="#c4c4c4")
        self.tooltip_font = "TkDefaultFont"
        self.Entry1_tooltip = \
        ToolTip(self.Entry1, self.tooltip_font, '''URL au format http(s)://[...]''')

        self.Logo = tk.Button(top)
        self.Logo.place(relx=0.025, rely=0.0, height=81, width=81)
        self.Logo.configure(activebackground="#f9f9f9")
        self.Logo.configure(background="#c5d8d7")
        self.Logo.configure(highlightthickness="0")
        photo_location = os.path.join(prog_location,"./logo.png")
        global _img0
        _img0 = tk.PhotoImage(file=photo_location)
        self.Logo.configure(image=_img0)
        self.Logo.configure(relief="flat")
        self.Logo.configure(text='''Button''')

        self.Label1 = tk.Label(top)
        self.Label1.place(relx=0.142, rely=0.019, height=15, width=139)
        self.Label1.configure(activebackground="#f9f9f9")
        self.Label1.configure(background="#c5d8d7")
        self.Label1.configure(font="-family Lato -size 14 -weight normal -slant roman -underline 0 -overstrike 0")
        self.Label1.configure(text='''URL à scanner :''')

        self.Button1 = tk.Button(top)
        self.Button1.place(relx=0.463, rely=0.068, height=32, width=171)
        self.Button1.configure(activebackground="#f9f9f9")
        self.Button1.configure(command=web_scan_support.btn_scan_click)
        self.Button1.configure(compound='left')
        photo_location = os.path.join(prog_location,"./scan.png")
        global _img1
        _img1 = tk.PhotoImage(file=photo_location)
        self.Button1.configure(image=_img1)
        self.Button1.configure(text='''Scanner''')
        self.tooltip_font = "TkDefaultFont"
        self.Button1_tooltip = \
        ToolTip(self.Button1, self.tooltip_font, '''Démarre la recherche de lien (crawler)''')

        self.Button2 = tk.Button(top)
        self.Button2.place(relx=0.699, rely=0.068, height=32, width=186)
        self.Button2.configure(activebackground="#f9f9f9")
        self.Button2.configure(command=web_scan_support.btn_stop_click)
        self.Button2.configure(compound='left')
        photo_location = os.path.join(prog_location,"./stop.png")
        global _img2
        _img2 = tk.PhotoImage(file=photo_location)
        self.Button2.configure(image=_img2)
        self.Button2.configure(text='''Arrêter''')

        self.Listbox1 = tk.Listbox(top)
        self.Listbox1.place(relx=0.071, rely=0.226, relheight=0.278
                , relwidth=0.853)
        self.Listbox1.configure(background="white")
        self.Listbox1.configure(font="TkFixedFont")
        self.Listbox1.configure(selectbackground="#c4c4c4")
        self.Listbox1.configure(selectmode='multiple')
        self.tooltip_font = "TkDefaultFont"
        self.Listbox1_tooltip = \
        ToolTip(self.Listbox1, self.tooltip_font, '''Clic droit pour chercher les vulnérabilités des liens sélectionnés''')
        if (root.tk.call('tk', 'windowingsystem')=='aqua'):
            self.Listbox1.bind('<Control-1>', lambda e: self.popup1(e,1))
            self.Listbox1.bind('<Button-2>', lambda e: self.popup1(e,1))
        else:
            self.Listbox1.bind('<Button-3>', lambda e: self.popup1(e,1))
        self.Listbox1.bind('<Key-Control_L>a', web_scan_support.select_all)

        self.menubar = tk.Menu(top, font="TkMenuFont", bg=_bgcolor, fg=_fgcolor)
        top.configure(menu=self.menubar)

        self.sub_menu = tk.Menu(top, tearoff=0)
        self.menubar.add_cascade(menu=self.sub_menu, activebackground="#ececec", activeforeground="#000000",
                                 background="#d9d9d9", font="TkMenuFont", foreground="#000000", label="Fichier")
        self.sub_menu.add_command(
                activebackground="#ececec",
                activeforeground="#000000",
                background="#d9d9d9",
                command=web_scan_support.btn_save_click,
                font="TkMenuFont",
                foreground="#000000",
                label="Exporter Rapport HTML")
        self.sub_menu.add_command(
                activebackground="#ececec",
                activeforeground="#000000",
                background="#d9d9d9",
                command=web_scan_support.btn_quit_click,
                font="TkMenuFont",
                foreground="#000000",
                label="Quitter")
        self.menubar.add_command(
                activebackground="#ececec",
                activeforeground="#000000",
                background="#d9d9d9",
                command=web_scan_support.btn_help_click,
                font="TkMenuFont",
                foreground="#000000",
                label="Aide")
        self.sub_menu1 = tk.Menu(top, tearoff=0)
        self.menubar.add_cascade(menu=self.sub_menu1,
                activebackground="#ececec",
                activeforeground="#000000",
                background="#d9d9d9",
                compound="left",
                font="TkMenuFont",
                foreground="#000000",
                label="Infos Login")
        self.sub_menu1.add_command(
                activebackground="#ececec",
                activeforeground="#000000",
                background="#d9d9d9",
                command=web_scan_support.fill_login_info,
                compound="left",
                font="TkMenuFont",
                foreground="#000000",
                label="Ajouter Informations Login")

        self.Text1 = tk.Text(top)
        self.Text1.place(relx=0.071, rely=0.62, relheight=0.34, relwidth=0.853)
        self.Text1.configure(background="white")
        self.Text1.configure(font="TkTextFont")
        self.Text1.configure(selectbackground="#c4c4c4")
        self.Text1.configure(wrap="word")

        self.Label2 = tk.Label(top)
        self.Label2.place(relx=0.071, rely=0.564, height=16, width=119)
        self.Label2.configure(activebackground="#f9f9f9")
        self.Label2.configure(background="#c5d8d7")
        self.Label2.configure(font="-family Lato -size 13 -weight normal -slant roman -underline 0 -overstrike 0")
        self.Label2.configure(text='''Vulnérabilités :''')

        self.TSeparator1 = ttk.Separator(top)
        self.TSeparator1.place(relx=0.0, rely=0.526, relwidth=1.013)

        self.Label3 = tk.Label(top)
        self.Label3.place(relx=0.036, rely=0.169, height=19, width=170)
        self.Label3.configure(activebackground="#f9f9f9")
        self.Label3.configure(background="#c5d8d7")
        self.Label3.configure(font="-family Lato -size 13 -weight normal -slant roman -underline 0 -overstrike 0")
        self.Label3.configure(text='''Liens trouvés :''')

        self.Label4 = tk.Label(top)
        self.Label4.place(relx=0.5, rely=1.0, height=21, width=1847, anchor=tk.S)
        self.Label4.configure(activebackground="#f9f9f9")
        self.Label4.configure(anchor='s')
        self.Label4.configure(font="-family {Bitstream Charter} -size 8 -weight normal -slant roman -underline 0 -overstrike 0")
        self.Label4.configure(padx="10")
        self.Label4.configure(text='''/!\ Vérifiez que vous avez l'autorisation d'utiliser cet outil sur les sites ciblés''')

        self.Label5 = tk.Label(top)
        self.Label5.place(relx=0.521, rely=0.169, height=21, width=334)
        self.Label5.configure(activebackground="#c5d8d7")
        self.Label5.configure(anchor='e')
        self.Label5.configure(background="#c5d8d7")
        self.Label5.configure(justify='right')
        self.Label5.configure(text='''Scan non démarré''')

    @staticmethod
    def popup1(event, *args, **kwargs):
        Popupmenu1 = tk.Menu(root, tearoff=0)
        Popupmenu1.configure(activebackground="#f9f9f9")
        Popupmenu1.add_command(
                activebackground="#ececec",
                activeforeground="#000000",
                background="#d9d9d9",
                command=web_scan_support.btn_check_vuln,
                font="TkMenuFont",
                foreground="#000000",
                label="Chercher les vulnérabilités")
        Popupmenu1.post(event.x_root, event.y_root)

    @staticmethod
    def popup2(event, *args, **kwargs):
        Popupmenu2 = tk.Menu(root, tearoff=0)
        Popupmenu2.configure(activebackground="#f9f9f9")
        Popupmenu2.post(event.x_root, event.y_root)



from time import time, localtime, strftime


class ToolTip(tk.Toplevel):
    """
    Provides a ToolTip widget for Tkinter.
    To apply a ToolTip to any Tkinter widget, simply pass the widget to the
    ToolTip constructor
    """
    def __init__(self, wdgt, tooltip_font, msg=None, msgFunc=None,
                 delay=0.5, follow=True):
        """
        Initialize the ToolTip

        Arguments:
          wdgt: The widget this ToolTip is assigned to
          tooltip_font: Font to be used
          msg:  A static string message assigned to the ToolTip
          msgFunc: A function that retrieves a string to use as the ToolTip text
          delay:   The delay in seconds before the ToolTip appears(may be float)
          follow:  If True, the ToolTip follows motion, otherwise hides
        """
        self.wdgt = wdgt
        # The parent of the ToolTip is the parent of the ToolTips widget
        self.parent = self.wdgt.master
        # Initalise the Toplevel
        tk.Toplevel.__init__(self, self.parent, bg='black', padx=1, pady=1)
        # Hide initially
        self.withdraw()
        # The ToolTip Toplevel should have no frame or title bar
        self.overrideredirect(True)

        # The msgVar will contain the text displayed by the ToolTip
        self.msgVar = tk.StringVar()
        if msg is None:
            self.msgVar.set('No message provided')
        else:
            self.msgVar.set(msg)
        self.msgFunc = msgFunc
        self.delay = delay
        self.follow = follow
        self.visible = 0
        self.lastMotion = 0
        # The text of the ToolTip is displayed in a Message widget
        tk.Message(self, textvariable=self.msgVar, bg='#FFFFDD', font=tooltip_font, aspect=1000).grid()

        # Add bindings to the widget.  This will NOT override
        # bindings that the widget already has
        self.wdgt.bind('<Enter>', self.spawn, '+')
        self.wdgt.bind('<Leave>', self.hide, '+')
        self.wdgt.bind('<Motion>', self.move, '+')

    def spawn(self, event=None):
        """
        Spawn the ToolTip.  This simply makes the ToolTip eligible for display.
        Usually this is caused by entering the widget

        Arguments:
          event: The event that called this funciton
        """
        self.visible = 1
        # The after function takes a time argument in milliseconds
        self.after(int(self.delay * 1000), self.show)

    def show(self):
        """
        Displays the ToolTip if the time delay has been long enough
        """
        if self.visible == 1 and time() - self.lastMotion > self.delay:
            self.visible = 2
        if self.visible == 2:
            self.deiconify()

    def move(self, event):
        self.lastMotion = time()
        # If the follow flag is not set, motion within the
        # widget will make the ToolTip disappear
        #
        if self.follow is False:
            self.withdraw()
            self.visible = 1

        # Offset the ToolTip 10x10 pixes southwest of the pointer
        self.geometry('+%i+%i' % (event.x_root+20, event.y_root-10))
        try:
            # Try to call the message function.  Will not change
            # the message if the message function is None or
            # the message function fails
            self.msgVar.set(self.msgFunc())
        except:
            pass
        self.after(int(self.delay * 1000), self.show)

    def hide(self, event=None):
        """
        Hides the ToolTip.  Usually this is caused by leaving the widget
        Arguments:
          event: The event that called this function
        """
        self.visible = 0
        self.withdraw()

    def update(self, msg):
        """
        Updates the Tooltip with a new message. Added by Rozen
        """
        self.msgVar.set(msg)




if __name__ == '__main__':
    vp_start_gui()

