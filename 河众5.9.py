# -*- coding: utf-8 -*-
import hashlib
import os
import string
import sys
import threading
import threading as thre
import time
import tkinter as tk
import tkinter.messagebox
import warnings
from configparser import ConfigParser
from tkinter import ttk
from tkinter.filedialog import *

import requests  # 导入库
import tkinterweb as th3
from cefpython3 import cefpython as cef

'''
apikey = "************************************************"
url = "https://www.virustotal.com/vtapi/v2/file/report"
param = {'resource': md5, 'apikey': apikey, 'allinfo': '1'}
try:
    result = requests.post(url, param, timeout=0.2)  # 向virustotal发送请求
except Exception:
    pass
time.sleep(1)
jo = result.text
joe = json.loads(jo)
can1 = joe.get('scans')
can = can1.get('ESET-NOD32')
out = can['result']
'''

try:
    webget = tk.Tk()
except KeyboardInterrupt:
    pass

webget.withdraw()

warnings.filterwarnings("ignore")
try:
    update_list = requests.get('http://bbs.flexible-world.com/down/update.dll', verify=False, timeout=5).text
except Exception:
    tk.messagebox.showinfo('提示', '无法连接云端！！！')
root = tk.Tk()  # 创建窗口
update_window = tk.Tk()
update_window.title('河众在线更新向导')
update_window.geometry('400x400')
uptext_1 = tk.Label(update_window, text='下载文件：', font=('微软雅黑', 10))
uptext_1.pack(anchor='sw')
uptext_2 = tk.Label(update_window, text='', font=('微软雅黑', 10))
uptext_2.pack(anchor='sw')
uptext_3 = tk.Label(update_window, text='更新源：https://bbs.flexible-world.com/', font=('微软雅黑', 10))
uptext_3.pack(anchor='sw')
update_window.withdraw()
root.title("河众杀毒")
root.iconbitmap('logo.ico')
root.resizable(True, True)
root.geometry('400x400')
showfile = tk.Label(root, text='正在扫描：')
showfile.pack(anchor='sw')
rt_label = tk.Label(root, text='扫描文件：')
rt2_label = tk.Label(root, text='感染文件：', fg='red')
rt_label.pack(anchor='sw')
rt2_label.pack(anchor='sw')
text_print = tk.Text(root, width=150, height=40, undo=True, autoseparators=False)
scroll = tk.Scrollbar(command=text_print.yview)
scrollx = tk.Scrollbar(orient=tk.HORIZONTAL, command=text_print.xview)
# 放到窗口的右侧, 填充Y竖直方向

# scroll.pack(side=tkinter.RIGHT, fill=tkinter.Y)
scroll.pack(side=tk.RIGHT, fill='y')
scrollx.pack(side=tk.BOTTOM, fill='x')
# 4个控件关联
scroll.config(command=text_print.yview)
scrollx.config(command=text_print.xview)
text_print.config(yscrollcommand=scroll.set)
text_print.pack()
text_print.config(yscrollcommand=scrollx.set)
text_print.pack()
jd_text = tk.Label(root, text='进度：',  # 设置文本内容
                   anchor='nw',  # 设置文本在label的方位：西北方位
                   font=('微软雅黑', 18),  # 设置字体：微软雅黑，字号：18
                   padx=20,  # 设置x方向内边距：20
                   pady=10
                   )
jd_text.pack()
p1 = ttk.Progressbar(root, length=200, mode="determinate", orient=tk.HORIZONTAL)
p1.pack(pady=20)
p1['maximum'] = 100
p1['value'] = 0


def get_disklist():  # 获取文件夹名的函数
    disk_list = []
    for c in string.ascii_uppercase:
        disk = c + ':'
        if os.path.isdir(disk):
            disk_list.append(disk)
    return disk_list


def qpsm():  # 留着先不用
    global io
    io = ''
    disk = get_disklist()
    for i in disk:
        io += i


nemberfiles = 0
probar = tkinter.ttk.Progressbar(root, length=200, mode='indeterminate', orient=tkinter.HORIZONTAL)
probar.pack(anchor='n')


def list_all_files(rootdir):  # 得到文件名
    global nemberfiles
    _files = []
    # 列出文件夹下所有的目录与文件
    list = os.listdir(rootdir)
    for i in range(0, len(list)):
        nemberfiles += 1
        # 构造路径
        path = os.path.join(rootdir, list[i])
        # 判断路径是否为文件目录或者文件
        # 如果是目录则继续递归
        if os.path.isdir(path):
            _files.extend(list_all_files(path))
        if os.path.isfile(path):
            _files.append(path)
        text_print.insert(tk.INSERT, "已发现{}个文件/目录".format(nemberfiles))
        text_print.update()
        text_print.delete(0.0, tk.END)
    return _files


a = ''
bdk = ''  # 定义变量，留着备用

global file_name


def GetMD5FromLocalFile(filename):  # 获取MD5
    file_object = open(filename, 'rb')
    file_name = filename
    file_content = file_object.read()
    file_object.close()
    file_md5 = hashlib.md5(file_content)
    file_object.close()
    return file_md5.hexdigest()


class Infinit:
    def __iter__(self):
        return self

    def __next__(self):
        return None


def ap(jr):
    b = ''
    with open(jr, 'rb') as f:
        for ift in Infinit():
            a = f.read(1)
            if not a:
                break
            temp = ("%x" % (ord(a)) + ' ')
            if len(temp) == 2:
                temp = '0' + temp
            b += temp
    return b


def hezhong_tzHEUR(frj, md5):
    global HEUR_ok
    global HEUR_define
    t1 = time.time()
    rr = HEUR_define.split('`')
    bb = ap(frj)
    print(bb)
    d1 = any(word.strip() if word.strip() in bb else False for word in rr)
    print(d1)
    if d1:
        print('she:', 'Trojan.HEUR!{}'.format(md5))
        HEUR_ok = 'Trojan.HEUR!{}'.format(md5)
    else:
        HEUR_ok = 'Noj'


global HEUR_define

global HEUR_ok


def scan():  # 杀毒主函数
    global HEUR_ok
    global HEUR_define
    HEUR_ok = None
    with open('bd/data.vdb') as f:
        HEUR_define = f.read()
    with open('bd/data1.vdb') as f:
        white_HEUR = f.read()
    text_print.config(state=tk.NORMAL)
    conf = ConfigParser()  # 需要实例化一个ConfigParser对象
    conf.read('1.ini')  # 需要添加上config.ini的路径，不需要open打开，直接给文件路径就读取，也可以指定encoding='utf-8'
    t = conf['scan']['tz']  # 读取user段的name变量的值，字符串格式
    if t == 'N':
        open_hetz = False
    else:
        open_hetz = True
    text_print.delete(0.0, tk.END)
    text_print.config(state=tk.DISABLED)
    with open('bd/bd.dll', 'r') as f:
        bdk = f.read()
    global bdfile  # 全局滑稽
    vir_log = ''
    fj = 0
    bdfj = 0
    bdfile = ''
    timestart = time.time()  # 计时
    text_print.config(state=tk.DISABLED)
    for i in psd:
        try:
            FileMD5 = GetMD5FromLocalFile(i)  # 如果不出错，获取MD5
        except Exception as err:
            with open('deflog.log', 'a+') as f:
                f.write('错误：{}'.format(err) + '\n')
        ss = i + '-->' + FileMD5
        ssd = ss.split("-->")  # 遍历MD5，查验病毒库
        bd = ssd[1]
        bdf = ssd[0]
        try:
            if bd in bdk:
                text_print.config(state=tk.NORMAL)
                text_print.see(tk.END)
                showfile['text'] = "正在扫描：{}".format(bdf)
                rt2_label['text'] = "感染文件：{}".format(bdfj)
                rt_label['text'] = '扫描文件：{}'.format(fj)
                jd_text['text'] = '扫描进度：{}%'.format(str(int(fj / nemberfiles * 100)))
                text_print.insert(tk.INSERT, bdf + "，威胁名称：Trojan.{}\n".format(bd))
                vir_log += '检测到：文件{}受感染Trojan.{}。\n'.format(i, bd)
                text_print.update()
                bdfile += bdf
                bdfile += '{-*-}'
                bdfj += 1
            else:
                if open_hetz:
                    thred_1 = thre.Thread(target=hezhong_tzHEUR, args=(i, bd,))
                    thred_1.start()
                    while 1:
                        if HEUR_ok is not None:
                            break
                    if HEUR_ok == 'Noj':
                        text_print.config(state=tk.NORMAL)
                        text_print.see(tk.END)
                        showfile['text'] = "正在扫描：{}".format(bdf)
                        rt_label['text'] = '扫描文件：{}'.format(fj)
                        rt2_label['text'] = "感染文件：{}".format(bdfj)
                        jd_text['text'] = '扫描进度：{}%'.format(str(int(fj / nemberfiles * 100)))
                        vir_log += '安全的：文件{}没有受感染。\n'.format(i, bd)
                    else:
                        if bd in white_HEUR:
                            text_print.config(state=tk.NORMAL)
                            text_print.see(tk.END)
                            showfile['text'] = "正在扫描：{}".format(bdf)
                            rt_label['text'] = '扫描文件：{}'.format(fj)
                            rt2_label['text'] = "感染文件：{}".format(bdfj)
                            jd_text['text'] = '扫描进度：{}%'.format(str(int(fj / nemberfiles * 100)))
                            vir_log += '安全的：文件{}没有受感染。\n'.format(i, bd)
                        else:
                            text_print.config(state=tk.NORMAL)
                            text_print.see(tk.END)
                            showfile['text'] = "正在扫描：{}".format(bdf)
                            rt2_label['text'] = "感染文件：{}".format(bdfj)
                            rt_label['text'] = '扫描文件：{}'.format(fj)
                            jd_text['text'] = '扫描进度：{}%'.format(str(int(fj / nemberfiles * 100)))
                            text_print.insert(tk.INSERT, bdf + "，威胁名称：{} \n".format(HEUR_ok))
                            vir_log += '检测到：文件{}受感染{}。\n'.format(i, HEUR_ok)
                            text_print.update()
                            bdfile += bdf
                            bdfile += '{-*-}'
                            bdfj += 1
                else:
                    text_print.config(state=tk.NORMAL)
                    text_print.see(tk.END)
                    showfile['text'] = "正在扫描：{}".format(bdf)
                    rt_label['text'] = '扫描文件：{}'.format(fj)
                    rt2_label['text'] = "感染文件：{}".format(bdfj)
                    jd_text['text'] = '扫描进度：{}%'.format(str(int(fj / nemberfiles * 100)))
                    vir_log += '安全的：文件{}没有受感染。\n'.format(i, bd)
            fj += 1
        except Exception:
            pass
        text_print.config(state=tk.DISABLED)
        p1['value'] = fj / nemberfiles * 100
        root.title('扫描文件······{}%'.format(str(int(fj / nemberfiles * 100))))
        root.update()
        time.sleep(0.01)
    timeend = time.time()
    p1['value'] = 100
    jd_text['text'] = '扫描结束！'
    root.title('扫描完成！')
    text_print.update()
    try:
        f = open('log.log', 'w')
        f.write(vir_log)
        f.close()
        # print('杀毒完成！发现威胁{}个！'.format(bdfj) + '用时{}秒！'.format(timeend - timestart))
        fileline = bdfile.split("{-*-}")
        f = open('deflog.log', 'a+')
        f.write('扫描：威胁{}个，用时{}秒，共{}个文件'.format(bdfj, timeend - timestart, fj))
        f.close()
        # print('威胁：')
        '''
        for fri, trojan_name in zip(fileline, vir_md5_list):
            if trojan_name == '':
                break
            print(fri + '，威胁名称：{}'.format(trojan_name))
            text_print.insert(tk.INSERT, fri + "，威胁名称：{}\n".format(trojan_name))
            text_print.update()
            with open('deflog.log', 'a+') as f:
            f.write(fri + '，威胁名称：{}\n'.format(trojan_name))
        '''
    except Exception:
        pass
    if bdfj != 0:
        s = tkinter.messagebox.askyesno(title='扫描完成！',
                                        message='扫描完成！用时{}秒，共扫描{}个文件，发现{}个威胁！是否处理？'.format(timeend - timestart, fj,
                                                                                           bdfj))

        if s:

            jq = 0
            for iii in fileline:
                if iii == '':
                    tkinter.messagebox.showinfo(title='提示！！', message='处理完成！')
                else:
                    jq += 1
                    try:
                        p1['value'] = jq / bdfj * 100
                        root.title('处理威胁······{}%'.format(str(int(jq / bdfj * 100))))
                        root.update()
                        os.remove(iii)  # 处理bd
                    except Exception as err:
                        pass

    else:
        pass


def main_run(fdper):  # 主调用
    a = None

    fdper = str(fdper)

    fd = ''
    global psd
    #  手动滑稽吧
    try:
        ver = requests.get('https://bbs.flexible-world.com/down/ver.txt', verify=False, timeout=2)
        ver.encoding = 'utf-8'
    except Exception:
        pass
    if fdper == '1':
        fd = 'C:/windows/system32/'  # 关键位置x1
        root.deiconify()
        probar.start()

        try:
            psd = list_all_files(fd)  # 万一权限不够

        except PermissionError as err:
            if '指定的路径' in str(err):
                pass
            else:
                tk.messagebox.showinfo('提示！', 'ERROR {}'.format(err))

        probar.stop()
        probar.pack_forget()
    elif fdper == '3':
        ver = requests.get('https://bbs.flexible-world.com/down/ver.txt', verify=False)
        ver.encoding = 'utf-8'

        with open('bd/ver.dll') as f:
            fedll = f.read()

        if str(fedll) == str(ver.text):
            tkinter.messagebox.showinfo(title='信息提示！', message='你已使用最新版本！')
            a = True
        else:
            update_window.deiconify()
            tkinter.messagebox.showinfo(title='更新内容', message='更新内容：{}'.format(update_list))
            uptext_1['text'] = '正在下载：bd.fne'
            update_window.update()
            re = requests.get('https://bbs.flexible-world.com/down/bd.fne', verify=False).text
            uptext_1['text'] = '正在下载：ver.txt'
            update_window.update()
            tas = requests.get('https://bbs.flexible-world.com/down/ver.txt', verify=False).text
            uptext_1['text'] = '正在下载：data.vdb'
            update_window.update()
            re2 = requests.get('https://bbs.flexible-world.com/down/data.vdb', verify=False).text
            uptext_1['text'] = '正在下载：data1.vdb'
            update_window.update()
            re3 = requests.get('https://bbs.flexible-world.com/down/data1.vdb', verify=False).text

            uptext_1['text'] = '正在写入：bd.fne'

            update_window.update()

            with open('bd/bd.dll', 'w') as f:
                f.write(re)

            uptext_1['text'] = '正在写入：ver.txt'

            update_window.update()

            with open('bd/ver.dll', 'w') as f:
                f.write(tas)
            uptext_1['text'] = '正在写入：data.vdb'

            update_window.update()
            with open('bd/data.vdb', 'w') as f:
                f.write(re2)

            uptext_1['text'] = '正在写入：data1.vdb'

            update_window.update()

            with open('bd/data1.vdb', 'w') as f:
                f.write(re3)
            p1['value'] = 100
            tkinter.messagebox.showinfo(title='信息提示！', message='升级完成！')
            with open('bd/ver.dll', 'r') as f:
                ve = f.read()

            with open('bd/ve.dll', 'r') as f:
                vee = f.read()
            svm['text'] = '病毒库版本：{}，程序版本：{}'.format(ve, vee)
            a = True
            update_window.withdraw()
    elif fdper == '2':
        fd = askdirectory()
        probar.start()
        try:
            global nemberfiles

            nemberfiles = 0
            fj = 0
            root.deiconify()
            psd = list_all_files(fd)
        except PermissionError as err:
            if '指定' in str(err):
                pass
            else:
                tk.messagebox.showinfo('提示！', 'ERROR {}'.format(err))

        probar.stop()
        probar.pack_forget()
    else:
        pass
    if a:
        pass
    else:
        try:
            scan()
        except Exception:
            pass


def filescan():
    main_run(2)


def fastscan():
    main_run(1)


def upvirscan():
    main_run(3)


tem = None


def embed_browser_thread(frame, _rect):
    sys.excepthook = cef.ExceptHook
    window_info = cef.WindowInfo(frame.winfo_id())
    window_info.SetAsChild(frame.winfo_id(), _rect)
    cef.Initialize()
    cef.CreateBrowserSync(window_info, url='https://bbs.flexible-world.com/')
    cef.MessageLoop()


def upexe():
    vet = requests.get('https://bbs.flexible-world.com/down/ve.dll', verify=False).text
    with open('bd/ve.dll', 'r') as f:
        ve = f.read()

    if float(ve) != float(vet):

        tkinter.messagebox.showinfo(title='信息提示！', message='升级中······时间可能较长，请耐心等待······')

        for i in range(1, 51):
            p1['value'] = i
            root.update()
            time.sleep(0.1)

        exe = requests.get('https://bbs.flexible-world.com/down/Setup.exe', verify=False)
        with open('setup.exe', 'wb') as f:
            f.write(exe.content)
        for i in range(1, 51):
            p1['value'] = i
            root.update()
            time.sleep(0.1)
        tkinter.messagebox.showinfo(title='信息提示！', message='即将弹出UAC，程序将关闭，请耐心等待······')
        os.popen('start setup.exe')

        sys.exit()
    else:

        upvirscan()


def wriniexe():
    os.popen('start ini.exe')


def litter():
    tk.messagebox.showinfo('开始清理······', '开始清理······')
    os.popen('start litter.exe')


class AntiVirus_Set:
    def __init__(self):
        self.heur_oy = None
        conf = ConfigParser()  # 需要实例化一个ConfigParser对象
        conf.read('1.ini')  # 需要添加上config.ini的路径，不需要open打开，直接给文件路径就读取，也可以指定encoding='utf-8'
        self.heur_oo = conf['scan']['tz']  # 读取user段的name变量的值，字符串格式

    def set(self):
        set_window = tk.Tk()
        set_text1 = tk.Label(
            set_window,
            text='特征码：'
        )
        set_text1.pack()

        tk.Button(set_window, text='开启', command=self.set_a).pack()  # 传入参数
        tk.Button(set_window, text='关闭', command=self.set_b).pack()

    def set_a(self):
        config = ConfigParser()
        config.read('1.ini')
        config.set("scan", "tz", "Y")
        config.write(open('1.ini', "r+"))
        self.heur_oy = '是否开启:是'

    def set_b(self):
        config = ConfigParser()
        config.read('1.ini')
        config.set("scan", "tz", "N")
        config.write(open('1.ini', "r+"))
        self.heur_oy = '是否开启:不是'


def gui():
    set_win = AntiVirus_Set()
    # text_print.config(state=tk.DISABLED)
    root.withdraw()
    global svm

    with open('bd/ver.dll', 'r') as f:
        ve = f.read()

    with open('bd/ve.dll', 'r') as f:
        vee = f.read()
    global rt2
    rt2 = tk.Tk()
    rt2.geometry('720x720')
    rt2.iconbitmap('logo.ico')
    rt_m1 = tk.Menu(rt2)
    rt_m2 = tk.Menu(rt_m1, tearoff=False)
    tk.Button(rt2, text="自定义扫描", command=filescan, height=2).pack()
    tk.Button(rt2, text="快速扫描（需要ring3）", command=fastscan, height=2).pack()
    tk.Button(rt2, text="在线更新", command=upexe, height=2).pack()
    tk.Button(rt2, text="浏览官网（欢迎注册）", command=web_jj, height=2).pack()
    tk.Button(rt2, text="退出", command=sys.exit, height=2).pack()
    rt_m2.add_command(label='垃圾清理', command=litter)
    rt_m2.add_command(label='云鉴定（若没有结果，请自行到virustotal上传）', command=yunjianding)
    rt_m2.add_command(label='河众特征码（慎用，扫描极慢，除非你能等待）', command=wriniexe)
    rt_m2.add_command(label='隐藏扫描窗口', command=root.withdraw)
    rt_m2.add_command(label='显示扫描窗口', command=root.deiconify)
    rt_m2.add_command(label='设置', command=set_win.set)
    svm = tk.Label(rt2, text='病毒库版本：{}，程序版本：{}'.format(ve, vee), bg='blue', fg='red')
    svm.pack()
    frame2 = th3.HtmlFrame(rt2, messages_enabled=False)
    frame2.pack(expand=True, side='bottom')

    url = 'https://bbs.flexible-world.com/1/'
    frame2.load_website(url)
    rt2.configure(bg='blue')
    rt_m1.add_cascade(label='高级操作', menu=rt_m2)
    rt2.config(menu=rt_m1)


def yunjianding():
    fls = askopenfilename()
    dm5 = GetMD5FromLocalFile(fls)
    os.popen('jian.exe {}'.format(dm5))


def web_jj():
    global tem
    if tem is None:
        tem = True
        webget.deiconify()
        webget.geometry('1280x800')
        menu1 = tk.Menu(webget, tearoff=0)
        menu1.add_command(label="隐藏", command=webget.withdraw)
        menu1.add_separator()
        mebubar = tk.Menu(webget)
        mebubar.add_cascade(label="选项", menu=menu1)
        webget.config(menu=mebubar)
        try:
            frame1 = tk.Frame(webget, height=1080, width=1920)
            frame1.pack(expand=True, fill='both')

            url = 'https://bbs.flexible-world.com/'
            rect = [0, 0, 1920, 1080]
            threadp = threading.Thread(target=embed_browser_thread, args=(frame1, rect), name='w1')
            threadp.start()
            webget.mainloop()
        except Exception:
            pass
    else:
        webget.deiconify()
        webget.geometry('1280x800')
        menu1 = tk.Menu(webget, tearoff=0)
        menu1.add_command(label="隐藏", command=webget.withdraw)
        menu1.add_separator()
        mebubar = tk.Menu(webget)
        mebubar.add_cascade(label="选项", menu=menu1)
        webget.config(menu=mebubar)


if __name__ == '__main__':
    gui()
    rt2.mainloop()
