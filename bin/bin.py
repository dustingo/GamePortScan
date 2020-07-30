#! -*- coding:utf-8 -*-
#__author__:zack
import nmap
import sys
import os
import json
import time
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from ui.mainUI import *
from pyportscanner import  pyscanner

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(QMainWindow,self).__init__()
        self.setupUi(self)
        self.portscan = PortScan()
        self.pushButton.clicked.connect(self.__start_scan__)
        self.pushButton_2.clicked.connect(self.__upload_file__)

        self.gameport = GamePort()
        self.pushButton_3.clicked.connect(self.__upload_file__)
        self.pushButton_4.clicked.connect(self.__start_telnet__)

    #信息板
    def __show_info__(self,str):
        self.textBrowser.append(str)

    #上传IP列表
    def __upload_file__(self):
        self.ipfile = QFileDialog.getOpenFileName(self, 'open file', '/')[0]
        self.textBrowser.append(f'[info] Open IP File {self.ipfile}')
        if not self.ipfile:
            self.textBrowser.append('[error] No file opened')

    #开始端口扫描
    def __start_scan__(self):
        self.portscan.ipfile = self.ipfile
        if not self.ipfile:
            self.textBrowser.append('[error] No file found')
        else:
            self.textBrowser.append('[info]开始扫描端口')
            self.portscan.start()
            self.portscan.port_signal.connect(self.__show_info__)

    #端口连通性检查
    def __start_telnet__(self):
        self.gameport.ports = self.lineEdit.text().split(',')
        self.gameport.ipaddr = open(self.ipfile,'r').readlines()
        if not self.ipfile:
            self.textBrowser.append('[error] 未上传IP列表')
        else:
            self.textBrowser.append('[info] 开始检查端口')
            self.gameport.start()
            self.gameport.game_signal.connect(self.__show_info__)



class PortScan(QThread):
    port_signal = pyqtSignal(str)
    def __init__(self):
        super(QThread,self).__init__()
        self.ipfile = ''

    def run(self):
        scanner = pyscanner.PortScanner(target_ports=500,verbose=True)
        ip_list = open(self.ipfile,'r').readlines() # every ip has character '\n'
        for ip in ip_list:
            scanner.scan(ip)
            self.port_signal.emit('[info] IP:{} done'.format(ip.strip('\n')))
        self.port_signal.emit('扫描结束，请查看 ./result/port.log')


class GamePort(QThread):
    game_signal = pyqtSignal(str)
    def __init__(self):
        super(QThread,self).__init__()
        self.ports = ''
        self.ipaddr = ''

    def run(self):
        time_now = time.strftime('%Y%m%d%H%M')
        f = open('../result/check%s.log' % time_now,'a')
        nm = nmap.PortScanner(nmap_search_path=('nmap', '../Nmap/nmap.exe'))
        for ip in self.ipaddr:
            self.game_signal.emit('Target IP: {}'.format(ip))
            f.write('Target IP: {} \n'.format(ip.strip('\n')))
            for port in self.ports:
                result = nm.scan(ip.strip('\n'), port, arguments='-sUT')
                state = result['scan']
                self.game_signal.emit('PORT: {}/tcp  {}'.format(port, state[ip.strip('\n')]['tcp'][int(port)]['state']))
                f.write('PORT: {}/tcp  {} \n'.format(port, state[ip.strip('\n')]['tcp'][int(port)]['state']))
                self.game_signal.emit('PORT: {}/udp  {}'.format(port, state[ip.strip('\n')]['udp'][int(port)]['state']))
                f.write('PORT: {}/udp  {} \n'.format(port, state[ip.strip('\n')]['udp'][int(port)]['state']))
        f.close()
        self.game_signal.emit('端口检查结束,结果保存于check.log')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ntools = MainWindow()
    ntools.show()
    sys.exit(app.exec_())