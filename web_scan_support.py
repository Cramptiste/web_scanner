#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
import ast
import multiprocessing
import re
import sys
from urllib.parse import urlparse
from tkinter import messagebox
import webbrowser

import web_scanner

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

w = None
top_level = None
root = None
mqueue_crawl = multiprocessing.Queue()
mqueue_check_vuln = multiprocessing.Queue()
ws = None
isscanning = False
new_win = None
logged = False


def init(top, gui, *args, **kwargs):
    global w, top_level, root
    w = gui
    top_level = top
    root = top


def select_all(event):
    """
    Sélectionne tous les éléments de la listbox
    :param event: objet événement retourné par l'interface (inutilisé)
    :return:
    """
    global w
    w.Listbox1.select_set(0, tk.END)


def btn_scan_click():
    global w, ws, isscanning, logged

    target = w.Entry1.get()

    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http(s):// ou  ftp(s)
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domaine
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...ou ip
        r'(?::\d+)?'  # port optionnel
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    if not re.match(regex, target):
        messagebox.showerror("Erreur d'URL", "L'URL saisie n'est pas valide !")
        return

    if not target.endswith("/") and not target.endswith(".php") and not target.endswith(".html"):
        target = target + "/"

    if ws is None:  # si l'objet ws n'existe pas encore, on l'instancie ici
        ws = web_scanner.WebScanner(target)
    elif urlparse(ws.url).netloc not in target:  # si on change de domaine, créé un nouveau scanner
        ws.stopped = True
        ws = web_scanner.WebScanner(target)
    elif logged:  # si une session de login existe, on s'assure d'avoir bien l'URL à tester et non celle du login
        ws.url = target

    if isscanning:
        rep = messagebox.askquestion("Scan en cours", "Un scan est déjà en cours, souhaitez-vous l'arrêter ?")
        if rep == "yes":
            ws.stopped = True
            w.Label5['text'] = "Scan arrêté."
            isscanning = False
            sys.stdout.flush()
            return

    ws.stopped = False
    w.Label5['text'] = "Scan en cours..."
    ws.crawl(mqueue_crawl)
    isscanning = True
    root.after(1000, process_queue_crawl)


def process_queue_crawl():
    global isscanning, ws, w
    try:
        msg = mqueue_crawl.get(0)
        while msg != "END":  # récupère des messages d'arrière-plan jusqu'au message de fin
            w.Listbox1.insert(tk.END, msg)
            w.Listbox1.see(tk.END)
            msg = mqueue_crawl.get(0)
        if msg == "END":
            w.Label5["text"] = "Scan terminé !"
            isscanning = False
            ws.stopped = True
    except Exception as e:  # passe les exceptions sous silence (notamment la queue vide)
        root.after(1000, process_queue_crawl)


def process_queue_check_vuln():
    global isscanning, ws, w
    try:
        msg = mqueue_check_vuln.get(0)
        while msg != "END":
            w.Text1.insert(tk.END, msg)
            w.Text1.see(tk.END)
            msg = mqueue_check_vuln.get(0)
        if msg == "END":
            w.Label5["text"] = "Vérification de vulnérabilités terminée"
            isscanning = False
            ws.stopped = True
    except Exception as e:
        root.after(1000, process_queue_check_vuln)


def btn_stop_click():
    global ws, isscanning, w
    if ws is not None:
        ws.stopped = True
    isscanning = False
    w.Label5['text'] = "Scan arrêté."


def login_callback():
    global ws, new_win, logged
    login_info = new_win.nametowidget("entry_login").get()
    login_url = new_win.nametowidget("entry_url").get()
    if ws is None:
        ws = web_scanner.WebScanner(login_url)

    if ws.get_login_session(ast.literal_eval(login_info), login_url) is not None:
        messagebox.showinfo("Login réussi !", "Le scanner est bien connecté.")
        logged = True
        new_win.destroy()
    else:
        messagebox.showerror("Login non réussi !", "Erreur de connexion, vérifiez les informations.")
        logged = False


def fill_login_info():
    global new_win
    new_win = tk.Toplevel(root)  # créé une nouvelle fenêtre à la volée
    new_win.geometry("500x200")
    lbl = tk.Label(new_win, text="Données de login (ex: {\"username\":\"admin\",\"password\":...})")
    lbl.pack()
    ety = tk.Entry(new_win, name="entry_login", width=50)
    ety.insert(0, '{"username": "admin", "password": "password", "Login":"Login"}')
    ety.pack()
    lbl2 = tk.Label(new_win, text="URL de login")
    lbl2.pack()
    ety2 = tk.Entry(new_win, name="entry_url", width=50)
    ety2.pack()
    btn = tk.Button(new_win, text="OK", width=25, command=login_callback)
    btn.pack()
    new_win.mainloop()
    sys.stdout.flush()


def btn_check_vuln():
    global root, ws, w
    link_list = []
    for el in w.Listbox1.curselection():
        link_list.append(w.Listbox1.get(el))
    w.Label5['text'] = "Vérification de vulnérabilités en cours..."
    ws.check_vuln(mqueue_check_vuln, link_list)
    root.after(1000, process_queue_check_vuln)
    sys.stdout.flush()


def btn_help_click():
    webbrowser.open("https://cyberini.com")


def btn_quit_click():
    destroy_window()


def btn_save_click():
    header = "<!DOCTYPE html><head><style>table,th,tr,td{border:1px solid blue;}</style>\
            </head><body><table><tr><th>Liens trouvés</th></tr>"
    try:
        with open("./rapport_web_scanner.html", "w") as f:
            f.write(header)
            for link in ws.link_list:
                f.write("<tr><td><a href='" + link + "'>" + link + "</a></td></tr>")
            f.write("</table><table><tr><th>Vulnérabilités</th></tr>")
            for vuln in w.Text1.get("1.0", "end").split("\n"):
                if vuln != "":
                    f.write("<tr><td>" + vuln + "</td></tr>")
            f.write("</table><table><tr><th>Cookies</th><th>Valeur</th><th>Domaine</th><th>Chemin</th></tr>")
            for cookie in ws.get_cookies():
                f.write("<tr><td>" + cookie.name + "</td><td>" + cookie.value + "</td><td>" + cookie.domain +
                        "</td><td>" + cookie.path + "</td></tr>")
            footer = "</table></body></html>"
            f.write(footer)
            messagebox.showinfo("Exportation terminée !", "Rapport exporté avec succès !")
    except IOError as ioe:
        messagebox.showerror("Erreur d'export", "Erreur : veuillez vérifier que vous avez les droits d'écriture dans \
                                                le dossier courant - " + str(ioe))

    sys.stdout.flush()


def destroy_window():
    global top_level
    top_level.destroy()
    top_level = None


if __name__ == '__main__':
    import web_scan
    web_scan.vp_start_gui()
