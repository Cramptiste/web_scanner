#!/usr/bin/env python3
# coding:utf-8

import web_scanner

ws = web_scanner.WebScanner("http://192.168.0.47/dvwa/login.php")
ws.get_login_session({"username":"admin","password":"password","Login":"Login"})
print(ws.get_page_source("http://192.168.0.47/dvwa/"))
