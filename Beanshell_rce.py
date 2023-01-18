#!/usr/bin/python
#encoding:utf-8

import requests

filename = input("输入文件名:") #输入文件名
str(filename)
check_file = open(filename, "r", encoding='utf-8')
for line in check_file.readlines():
    line = line.strip()
    print('[+]%s'% line)  #打印fil
print("确认是否加载正确")
choose = input("[y/n]:")  #如果是则添加exp;如果不是退出
str(choose)
if choose == 'y':
    check_file = open(filename, "r", encoding='utf-8')
    for line in check_file.readlines():
        line = line.strip()
        # noinspection PyBroadException
        try:
            vul_url = line + "/servlet/~ic/bsh.servlet.BshServlet"
            r = requests.get(vul_url, timeout=5, verify=False).status_code
            if r == 200:
                print("[+]存在Beanshell_rce漏洞: "+vul_url)
            else:
                print("[-]不存在Beanshell_rce漏洞: "+vul_url)
            pass
        except:
            print("ERROR:无法连接:  "+vul_url)



