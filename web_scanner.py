#!/usr/bin/env python3
# coding:utf-8
import random
import sys
import threading
import urllib
import urllib.request
import urllib.response
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


class WebScanner:

    def __init__(self, url, proxy=None, user_agent="Mozilla/5.0 (X11; Linux i686; rv:68.0)\
    Gecko/20100101 Firefox/68.0"):
        if not url.endswith("/") and not url.endswith(".php") and not url.endswith(".html"):
            self.url = url + "/"
        else:
            self.url = url
        self.proxy = proxy
        self.user_agent = user_agent
        self.session = requests.Session()
        self.link_list = []
        self.stopped = False

    def print_link_list(self):
        """
        Affiche la liste de liens ("crawlés") dans le Terminal
        :return:
        """
        for link in self.link_list:
            print(link)

    def get_page_source(self, page=None):
        """
        Obtient le code source d'une page web
        :param page: optionnel : la page recherchée, sinon utilise self.url
        :return: Le code source HTML de la page
        """
        if page is None:
            page = self.url
        page = page.strip()
        user_agent = {"User-agent": self.user_agent}

        try:
            if self.proxy:
                res = self.session.get(page, headers=user_agent, proxies=self.proxy)
            else:
                res = self.session.get(page, headers=user_agent)
        except Exception as e:
            print("[-] Erreur pour la page : " + page + " " + str(e))
            return None
        return res.text

    def get_page_links(self, page=None):
        """
        Obtient les liens disponibles sur une page web (href), excluant les liens externes
        :param page: la page recherchée, sinon utilise self.url
        :return: une liste contenant les liens d'une page, ou une liste vide à défaut
        """
        link_list = []  # la liste de liens internes à "page"

        if page is None:
            page = self.url
        source = self.get_page_source(page)

        if source is not None:
            soup = BeautifulSoup(source, "html.parser")
            uparse = urlparse(page)
            for link in soup.find_all("a"):
                if not link.get("href") is None:
                    href = link.get("href")
                    if "#" in href:  # ex : http://site.fr/page.php#anchor
                        href = href.split("#")[0]  # récupère juste http://site.fr/page.php

                    new_link = urllib.parse.urljoin(page, href)

                    if uparse.hostname in new_link and new_link not in link_list:
                        link_list.append(new_link)
            return link_list
        else:
            return []

    def print_cookies(self):
        """
        Affiche les cookies de la session courante dans le Terminal
        :return:
        """
        for cookie in self.session.cookies:
            print(cookie)

    def get_cookies(self):
        """
        Retourne la liste des cookies de la session courante
        :return: La liste (dictionnaire) des cookies
        """
        return self.session.cookies

    def _do_crawl(self, queue, page=None):
        """
        Tâche d'arrière-plan pour "crawler" une page
        :param queue: queue multiprocessing pour y placer les messages (liens)
        :param page: la page recherchée, sinon utilise self.url
        :return:
        """
        try:

            page_links = self.get_page_links(page)
            for link in page_links:
                if self.stopped:  # si l'utilisateur souhaite arrêter le scan via le bouton
                    break
                if link not in self.link_list:
                    self.link_list.append(link)
                    queue.put(link)
                    self._do_crawl(queue, link)
        except KeyboardInterrupt:
            print("\nProgramme terminé par l'utilisateur.")
            sys.exit(1)
        except Exception as e:
            print("Erreur : " + str(e))
            sys.exit(1)

    def _crawl_end_callback(self, crawl_thread, crawl_queue):
        """
        Tâche d'arrière-plan permettant de savoir lorsque le crawling est terminé
        :param crawl_thread: crawl thread à vérifier
        :param crawl_queue: queue multiprocessing à utiliser pour envoyer le message de fin
        :return:
        """
        crawl_thread.join()
        crawl_queue.put("END")

    def crawl(self, crawl_queue, page=None):
        """
        Crawl une page via une tâche d'arrière-plan
        :param crawl_queue: multiprocessing queue à utiliser pour les communications
        :param page: la page recherchée, sinon utilise self.url
        :return:
        """
        crawl_thread = threading.Thread(target=self._do_crawl, args=(crawl_queue, page))
        crawl_thread.start()
        watch_thread = threading.Thread(target=self._crawl_end_callback, args=(crawl_thread, crawl_queue))
        watch_thread.start()

    def check_sqli_form(self, page=None):
        """
        Chercher des vulnérabilités par injection SQL dans un forumulaire
        :param page: la page recherchée, sinon utilise self.url
        :return:
        """
        if page is None:
            page = self.url
        source = self.get_page_source(page)
        if source is not None:
            soup = BeautifulSoup(source, "html.parser")
            forms_list = soup.find_all("form")

            payload = "'" + random.choice("abcdef")
            ret = ""
            for form in forms_list:
                form_action = form.get("action")
                form_method = form.get("method")
                target_url = urllib.parse.urljoin(page, form_action)

                input_list = form.find_all("input")
                param_list = {}

                for input_ in input_list:
                    input_name = input_.get("name")
                    input_type = input_.get("type")
                    input_value = input_.get("value")

                    if "?" + input_name not in target_url and "&" + input_name not in target_url:
                        if input_type == "text" or input_type == "password":
                            param_list[input_name] = payload
                        elif input_value is not None:
                            param_list[input_name] = input_value
                        else:
                            param_list[input_name] = ""

                    if form_method.lower() == "get":
                        res = self.session.get(target_url, params=param_list)

                    elif form_method.lower() == "post":
                        res = self.session.post(target_url, data=param_list)

                    if "You have an error in your SQL syntax;" in res.text:
                        print("INJECTION SQL DETECTEE DANS FORM : " + res.url + " (" + form_action + ")")
                        ret = ret + "INJECTION SQL DETECTEE DANS FORM : " + res.url + " (" + form_action + ")\n"

            return ret

    def check_sqli_link(self, page=None):
        """
        Cherche des vulnérabilités par injection sql dans une URL
        :param page: la page recherchée, sinon utilise self.url
        :return:
        """
        if page is None:
            page = self.url
        payload = "'" + random.choice("abcdef")
        page = page.replace("=", "=" + payload)

        res = self.session.get(page)

        if "You have an error in your SQL syntax;" in res.text:
            print("INJECTION SQL DETECTEE DANS LIEN : " + res.url)
            return "INJECTION SQL DETECTEE DANS LIEN : " + res.url + "\n"
        else:
            return ""

    def get_login_session(self, credentials, page=None):
        """
        Ouvre une session de login sur un site
        :param credentials: un dictionnaire des données POST à envoyer
        :param page: la page recherchée, sinon utilise self.url
        :return: Retourne soit un objet response, soit un objet nul
        """
        if page is None:
            page = self.url

        res = self.session.post(page, data=credentials)
        if res.status_code != "403": #and "You have logged in" in res.text
            return res
        else:
            return None

    def check_xss_form(self, page=None):
        """
        Cherche des vulnérabilités par faille XSS dans un formulaire
        :param page: la page recherchée, sinon utilise self.url
        :return:
        """
        if page is None:
            page = self.url
        source = self.get_page_source(page)
        soup = BeautifulSoup(source, "html.parser")
        forms_list = soup.find_all("form")
        payload = "<script>alert('test');</script>"
        ret = ""
        for form in forms_list:
            form_action = form.get("action")
            form_method = form.get("method")

            input_list = form.find_all("input")
            target_url = urllib.parse.urljoin(page, form_action)
            param_list = {}
            for input_ in input_list:
                input_name = input_.get("name")
                input_type = input_.get("type")
                input_value = input_.get("value")

                if "?" + input_name not in target_url and "&" + input_name not in target_url:
                    if input_type == "text" or input_type == "password":
                        param_list[input_name] = payload
                    elif input_value is not None:
                        param_list[input_name] = input_value
                    else:
                        param_list[input_name] = ""

                if form_method.lower() == "get":
                    res = self.session.get(target_url, params=param_list)

                elif form_method.lower() == "post":
                    res = self.session.post(target_url, data=param_list)

                if payload in res.text:
                    print("XSS DETECTE DANS FORM : " + res.url + " (" + form_action + ")")
                    ret = ret + "XSS DETECTE DANS FORM : " + res.url + " (" + form_action + ")\n"
        return ret

    def check_xss_link(self, page=None):
        """
        Cherche des vulnérabilités par XSS dans une URL
        :param page: la page recherchée, sinon utilise self.url
        :return:
        """
        if page is None:
            page = self.url
        payload = "<script>alert('test');</script>"
        page = page.replace("=", "=" + payload)

        res = self.session.get(page)

        if payload in res.text:
            print("XSS DETECTE DANS LIEN : " + res.url)
            return "XSS DETECTE DANS LIEN : " + res.url + "\n"
        else:
            return ""

    def _do_check_vuln(self, queue, link_list):
        """
        Fonction d'arrière-plan utilisée pour lancer la vérification automatique de vulnérabilités
        :param queue: une queue multiprocessing pour envoyer les messages
        :param link_list: la liste de liens à vérifier
        :return:
        """
        try:
            for link in link_list:
                chk_xss_link = self.check_xss_link(link)
                if chk_xss_link != "":
                    queue.put(chk_xss_link)
                chk_xss_form = self.check_xss_form(link)
                if chk_xss_form != "":
                    queue.put(chk_xss_form)
                chk_sqli_link = self.check_sqli_link(link)
                if chk_sqli_link != "":
                    queue.put(chk_sqli_link)
                chk_sqli_form = self.check_sqli_form(link)
                if chk_sqli_form != "":
                    queue.put(chk_sqli_form)
        except KeyboardInterrupt:
            print("\nProgramme arrêté par l'utilisateur.")
            sys.exit(1)
        except Exception as e:
            print("Erreur : " + str(e))
            sys.exit(1)

    def _check_vuln_end_callback(self, check_thread, check_queue):
        """
        Tâche d'arrière-plan permettant de savoir lorsque la vérification de vulnérabilités est terminée
        :param check_thread: thread à observer
        :param check_queue: queue à utiliser pour l'envoi du message de fin
        :return:
        """
        check_thread.join()
        check_queue.put("END")

    def check_vuln(self, check_queue, link_list):
        """
        Fonction de vérification des vulnérabilités web
        :param check_queue: queue multiprocessing à utiliser pour les communications
        :param link_list: liste de liens à vérifier
        :return:
        """
        check_thread = threading.Thread(target=self._do_check_vuln, args=(check_queue, link_list))
        check_thread.start()
        watch_thread = threading.Thread(target=self._check_vuln_end_callback, args=(check_thread, check_queue))
        watch_thread.start()
