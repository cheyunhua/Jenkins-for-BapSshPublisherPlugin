# -*- coding: utf-8 -*-
import json
import os
import socket
import threading
import time

import pandas as pd
import paramiko
import requests
import base64 as b64
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt, QRectF, QDir
from PyQt5.QtGui import QIcon, QPainter, QPainterPath, QBrush, QColor, QCursor
from PyQt5.QtWidgets import QWidget, QApplication, QMessageBox, QFileDialog
import sys
from bs4 import BeautifulSoup

if os.path.isfile('init.ini'):
    with open("./init.ini", "r") as file:
        initinfo = json.load(file)
    jenkins_url = initinfo['url']
else:
    jenkins_url = "http://192.168.196.128:8080"


def exitapp():
    sys.exit(0)


button_style = ''' 
                QPushButton
                {text-align : center;
                background-color : white;
                font: bold;
                border-color: gray;
                border-width: 1px;
                border-radius: 3px;
                padding: 2px;
                height : 14px;
                border-style: outset;
                font : 12px;}
                QPushButton:hover
                {text-align : center;
                background-color : cyan;
                font: bold;
                border-color: gray;
                border-width: 1px;
                border-radius: 5px;
                padding: 1px;
                height : 14px;
                border-style: outset;
                font : 12px;}
                QPushButton:pressed
                {text-align : center;
                background-color : cyan;
                font: bold;
                border-color: gray;
                border-width: 1px;
                border-radius: 5px;
                padding: 1px;
                height : 14px;
                border-style: outset;
                font : 12px;}                                                    
                '''


class RoundShadow(QWidget):
    """圆角边框类"""

    def __init__(self, parent=None):

        super(RoundShadow, self).__init__(parent)
        self.border_width = 8
        # 设置 窗口无边框和背景透明 *必须
        self.setWindowOpacity(0.9)  # 设置窗口透明度
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)

    def paintEvent(self, event):
        # 阴影
        path = QPainterPath()
        path.setFillRule(Qt.WindingFill)

        pat = QPainter(self)
        pat.setRenderHint(pat.Antialiasing)
        pat.fillPath(path, QBrush(Qt.white))

        color = QColor(192, 192, 192, 50)

        for i in range(10):
            i_path = QPainterPath()
            i_path.setFillRule(Qt.WindingFill)
            ref = QRectF(10 - i, 10 - i, self.width() - (10 - i) * 2, self.height() - (10 - i) * 2)
            # i_path.addRect(ref)
            i_path.addRoundedRect(ref, self.border_width, self.border_width)
            color.setAlpha(int(150 - i ** 0.5 * 50))
            pat.setPen(color)
            pat.drawPath(i_path)

        # 圆角
        pat2 = QPainter(self)
        pat2.setRenderHint(pat2.Antialiasing)  # 抗锯齿
        pat2.setBrush(Qt.cyan)
        pat2.setPen(Qt.transparent)

        rect = self.rect()
        rect.setLeft(-1)
        rect.setTop(-1)
        rect.setWidth(rect.width() - 1)
        rect.setHeight(rect.height() - 1)
        pat2.drawRoundedRect(rect, 8, 8)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.m_flag = True
            self.m_Position = event.globalPos() - self.pos()  # 获取鼠标相对窗口的位置
            event.accept()
            self.setCursor(QCursor(Qt.OpenHandCursor))  # 更改鼠标图标

    def mouseMoveEvent(self, QMouseEvent):
        try:
            if Qt.LeftButton and self.m_flag:
                self.move(QMouseEvent.globalPos() - self.m_Position)  # 更改窗口位置
                QMouseEvent.accept()
        except:
            pass

    def mouseReleaseEvent(self, QMouseEvent):
        self.m_flag = False
        self.setCursor(QCursor(Qt.ArrowCursor))


class jenkins_credentials:
    host = 'http://192.168.196.128:8080/'

    def createEOSCredentials(self, userName, passworld, id, des, jenkinsUserName, jenkinsPassworld):
        url = "http://192.168.196.128:8080/credentials/store/system/domain/_/createCredentials"
        json = {"": "0", "credentials": {"scope": "GLOBAL", "username": userName, "password": passworld,
                                         "$redact": "password", "id": id,
                                         "description": des,
                                         "stapler-class": "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl",
                                         "$class": "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl"}}
        data = {}
        data["json"] = str(json)
        result = requests.post(url, data=data, auth=(jenkinsUserName, jenkinsPassworld))
        if result.status_code != 200:
            exit(1)
        print(result.text)

        # 传入值请使用双引号

    def deleteEOSCredentials(self, id, jenkinsUserName, jenkinsPassworld):
        url = "http://192.168.196.128:8080/credentials/store/system/domain/_/credential/" + id + "/doDelete"
        requests.post(url, auth=(jenkinsUserName, jenkinsPassworld))

        # 传入值请使用双引号

    def updateEOSCredentials(self, userName, passworld, id, des, jenkinsUserName, jenkinsPassworld):
        url = "http://192.168.196.128:8080/credentials/store/system/domain/_/credential/" + id + "/updateSubmit"
        json = {"stapler-class": "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl",
                "scope": "GLOBAL", "username": userName, "password": passworld, "$redact": "password",
                "id": id, "description": des}
        data = {}
        data["json"] = str(json)
        result = requests.post(url, data=data, auth=(jenkinsUserName, jenkinsPassworld))
        print(result.text)

    def searchEOSCredentials(self, host, domin, id, jenkinsUserName, jenkinsPassworld):
        url = "http://192.168.196.128:8080/credentials/store/system/domain/_/credential/" + id + "/"
        result = requests.post(url, auth=(jenkinsUserName, jenkinsPassworld))
        # error_top = "The requested resource is not available."
        # if error_top in result.text:
        #     return False
        # else:
        #     return True
        if result.status_code == 200:
            return True
        else:
            return False



class SshHostConfiguration:

    def __init__(self):
        with open("init.ini", "r") as file:
            initinfo = json.load(file)
        self.url = initinfo['url']
        self.jenkinsUserName = initinfo['username']
        self.jenkinsPassword = Ui_jenkinslogin.xor_decrypt(self, initinfo['password'], key='superzyj')
        self.url = jenkins_url
        self.script_url = 'http://192.168.196.128:8080' + '/script'
        self.headers = {
            'Host': self.url,
            'Cache-Control': 'max-age=0',
            'Origin': self.url,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': self.script_url,
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }

    def addHostConfiguration(self, Name, Hostname, Username, Remotedirectory, Password):
        Hostname = Hostname.strip()
        Username = Username.strip()
        addhost_script_commands = '''
import jenkins.model.Jenkins;
import jenkins.plugins.publish_over_ssh.BapSshHostConfiguration
def publish_over_ssh = Jenkins.instance.getDescriptor("jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin")
// This is to make this re-entrant, so we don't create multiple entries
// if we somehow get run multiple times, like with a stored jenkins_home
publish_over_ssh.removeHostConfiguration("''' + Name + '''")
def configuration = new BapSshHostConfiguration()
configuration.name = "''' + Name + '''"
configuration.hostname = "''' + Hostname + '''"
configuration.username = "''' + Username + '''"
configuration.encryptedPassword = "''' + Password + '''"
configuration.proxyPassword = "''' + Password + '''"
configuration.remoteRootDir = "''' + Remotedirectory + '''"

configuration.port = configuration.DEFAULT_PORT

try {
	def f = new File("/run/secrets/PUBLISH_OVER_SSH_KEY")
	configuration.setKey(f.text)
	//configuration.setKeyPath("/run/secrets/PUBLISH_OVER_SSH_KEY")
	/*
	ERROR: Exception when publishing, exception message [Failed to read file - filename [/run/secrets/PUBLISH_OVER_SSH_KEY] (relative to JENKINS_HOME if not absolute). Message: [java.lang.SecurityException: agent may not read /run/secrets/PUBLISH_OVER_SSH_KEY
	See https://jenkins.io/redirect/security-144 for more details]]

	Either we open that in agent access, or we just set it in jenkins.
	*/
	configuration.setOverrideKey(true)
	println("PUBLISH_OVER_SSH_KEY configured")
} catch(e) {
	println("Failed to run setKey(/run/secrets/PUBLISH_OVER_SSH_KEY)")
	println(e)
}
publish_over_ssh.addHostConfiguration(configuration)
publish_over_ssh.save()'''
        data = {
            "script": addhost_script_commands
        }

        response = requests.post(self.script_url, auth=(self.jenkinsUserName, self.jenkinsPassword), data=data,
                                 verify=False)
        return response.text

    def removeHostConfiguration(self, Name):

        removehost_script_commands = '''
                import jenkins.model.*
                import jenkins.plugins.publish_over_ssh.BapSshHostConfiguration
                def inst = Jenkins.getInstance()
                def publish_ssh = inst.getDescriptor("jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin")
                publish_ssh.removeHostConfiguration("''' + Name + '''")
                publish_ssh.save()
                '''

        data = {
            "script": removehost_script_commands
        }

        try:
            requests.post(self.script_url, headers=self.headers, auth=(self.jenkinsUserName, self.jenkinsPassword),
                          data=data, verify=False)
        except:
            Ui_ImportCreds.messageBox(self, "INFO", "Connection timeout!")

    def getHostConfigurations(self):

        gethost_script_commands = '''import jenkins.model.*
                import jenkins.plugins.publish_over_ssh.BapSshHostConfiguration
                def inst = Jenkins.getInstance()
                def publish_ssh = inst.getDescriptor("jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin")
                publish_ssh.getHostConfigurations()'''

        data = {
            "script": gethost_script_commands
        }

        response = requests.post(self.script_url,
                                 auth=(self.jenkinsUserName, self.jenkinsPassword), data=data, verify=False)
        return response.text






class Ui_jenkinslogin(RoundShadow, QWidget):
    def __init__(self):
        super(Ui_jenkinslogin, self).__init__()
        self.setupUi()

    def setupUi(self):
        self.setObjectName("jenkinslogin")
        # self.setWindowIcon(QIcon('resources/jenkinslogin.ico'))
        self.setWindowModality(QtCore.Qt.WindowModal)
        self.setFixedSize(240, 150)
        self.label = QtWidgets.QLabel(self)
        self.label.setGeometry(QtCore.QRect(35, 31, 80, 16))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(9)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self)
        self.label_2.setGeometry(QtCore.QRect(35, 71, 80, 16))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(9)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.lineEdit = QtWidgets.QLineEdit(self)
        self.lineEdit.setGeometry(QtCore.QRect(71, 31, 133, 20))
        self.lineEdit.setObjectName("lineEdit")
        self.lineEdit_2 = QtWidgets.QLineEdit(self)
        self.lineEdit_2.setGeometry(QtCore.QRect(71, 71, 133, 20))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.lineEdit_2.setEchoMode(QtWidgets.QLineEdit.Password)

        self.pushButton = QtWidgets.QPushButton(self)
        self.pushButton.setGeometry(QtCore.QRect(31, 111, 75, 23))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        font.setBold(False)
        font.setWeight(50)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.pushButton.setStyleSheet(button_style)
        self.pushButton_2 = QtWidgets.QPushButton(self)
        self.pushButton_2.setGeometry(QtCore.QRect(125, 111, 75, 23))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(10)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_2.setStyleSheet(button_style)

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)
        self.url = jenkins_url
        if os.path.isfile("./init.ini"):
            with open("./init.ini", "r") as file:
                self.initinfo = json.load(file)
            self.url = self.initinfo['url']
            username = self.initinfo['username']
            password = self.xor_decrypt(self.initinfo['password'], "superzyj")
            self.lineEdit.setText(username)
            self.lineEdit_2.setText(password)

    def retranslateUi(self, Ui_jenkinslogin):
        _translate = QtCore.QCoreApplication.translate
        Ui_jenkinslogin.setWindowTitle(_translate("jenkinslogin", "登录"))
        Ui_jenkinslogin.label.setText(_translate("jenkinslogin", "用户："))
        Ui_jenkinslogin.label_2.setText(_translate("jenkinslogin", "口令："))
        Ui_jenkinslogin.pushButton.setText(_translate("jenkinslogin", "登录"))
        Ui_jenkinslogin.pushButton_2.setText(_translate("jenkinslogin", "退出"))

        self.pushButton.clicked.connect(self.check_login)
        self.pushButton_2.clicked.connect(exitapp)

    def xor_encrypt(self, tips, key):
        self.tips = tips
        self.key = key
        ltips = len(tips)
        lkey = len(key)
        secret = []
        num = 0
        for each in tips:
            if num >= lkey:
                num = num % lkey
            secret.append(chr(ord(each) ^ ord(key[num])))
            num += 1

        return b64.b64encode("".join(secret).encode()).decode()

    def xor_decrypt(self, secret, key):
        tips = b64.b64decode(secret.encode()).decode()
        self.secret = secret
        self.key = key
        ltips = len(tips)
        lkey = len(key)
        secret = []
        num = 0
        for each in tips:
            if num >= lkey:
                num = num % lkey

            secret.append(chr(ord(each) ^ ord(key[num])))
            num += 1

        return "".join(secret)

    def secwindow(self):
        self.hide()  # 隐藏此窗口
        self.f = Ui_ImportCreds()  # 将第一个窗口换个名字
        self.f.show()  # 将第一个窗口显示出来

    def messageBox(self, title, text):
        messagebox = QMessageBox()
        messagebox.setWindowIcon(QIcon('resources/jenkins.ico'))
        messagebox.setWindowTitle(title)
        messagebox.setStyleSheet(button_style)
        messagebox.setText(text)
        messagebox.addButton(QtWidgets.QPushButton('确定'), QMessageBox.YesRole)
        messagebox.exec_()

    def check_login(self):

        jenkinsUserName = self.lineEdit.text()
        jenkinsPassword = self.lineEdit_2.text()

        if jenkinsUserName == "" or jenkinsPassword == "":
            self.messageBox("INFO", "Username and password cannot be empty!")
        else:
            try:
                response = requests.post(self.url, auth=(jenkinsUserName, jenkinsPassword), timeout=3)
                result = response.status_code
                # print(result)
                if result == 200:
                    initinfo = {"url": self.url, "username": jenkinsUserName,
                                "password": self.xor_encrypt(jenkinsPassword, "superzyj")}
                    with open("./init.ini", "w") as file:
                        file.write(json.dumps(initinfo))

                    self.secwindow()
                else:
                    self.messageBox("INFO", "Login failed,username or password is incorrect!")
            except:
                Ui_jenkinslogin.messageBox(self, "INFO", "Connect timeout!")


class Ui_ImportCreds(RoundShadow, QWidget):

    def __init__(self):
        super(Ui_ImportCreds, self).__init__()
        self.setupUi()
        with open("./init.ini", "r") as file:
            initinfo = json.load(file)
        self.url = initinfo['url']
        self.jenkinsUserName = initinfo['username']
        self.jenkinsPassword = Ui_jenkinslogin.xor_decrypt(self, initinfo['password'], "superzyj")
        self.domain_name = '远程服务器凭据'
        # self.lineEdit.setPlainText("拖动华为云密码表到此处即可导入！")
        self.textBrowser.setText("使用说明：\n1.选择导入按钮或者拖动文件到输入框即可导入文件路径.\n" +
                                 "2.勾选复选框可以导入凭据的同时配置SSH授权。\n" +
                                 "3.配置文件init.ini中包含登录的url地址及用户名、密码，可以自己定义。\n")

    def setupUi(self):
        self.setObjectName("ImportCreds")
        self.resize(648, 327)
        self.toolButton = QtWidgets.QToolButton(self)
        self.toolButton.setGeometry(QtCore.QRect(10, 40, 41, 21))
        self.toolButton.setObjectName("toolButton")
        self.toolButton.setStyleSheet(''' 
                        QToolButton
                        {text-align : center;
                        background-color : white;
                        font: bold;
                        border-color: gray;
                        border-width: 1px;
                        border-radius: 3px;
                        padding: 2px;
                        height : 14px;
                        border-style: outset;
                        font : 12px;}
                        QToolButton:hover
                        {text-align : center;
                        background-color : cyan;
                        font: bold;
                        border-color: gray;
                        border-width: 1px;
                        border-radius: 5px;
                        padding: 1px;
                        height : 14px;
                        border-style: outset;
                        font : 12px;}
                        QToolButton:pressed
                        {text-align : center;
                        background-color : cyan;
                        font: bold;
                        border-color: gray;
                        border-width: 1px;
                        border-radius: 5px;
                        padding: 1px;
                        height : 14px;
                        border-style: outset;
                        font : 12px;}                                                    
                        '''
                                      )
        self.textBrowser = QtWidgets.QTextBrowser(self)
        self.textBrowser.setGeometry(QtCore.QRect(10, 70, 631, 251))
        self.textBrowser.setObjectName("textBrowser")
        self.lineEdit = QtWidgets.QTextEdit(self)
        self.lineEdit.setGeometry(QtCore.QRect(60, 40, 491, 20))
        self.lineEdit.setObjectName("lineEdit")

        self.CheckBox = QtWidgets.QCheckBox(self)
        self.CheckBox.setGeometry(QtCore.QRect(560, 40, 21, 21))
        self.CheckBox.setObjectName("CheckBox")
        self.CheckBox.setCheckState(True)

        self.pushButton = QtWidgets.QPushButton(self)
        self.pushButton.setGeometry(QtCore.QRect(600, 40, 41, 21))
        self.pushButton.setObjectName("pushButton")
        self.pushButton.setStyleSheet(button_style)

        self.pushButton_2 = QtWidgets.QPushButton(self)
        self.pushButton_2.setGeometry(QtCore.QRect(626, 1, 20, 20))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_2.setStyleSheet(button_style)

        self.label = QtWidgets.QLabel(self)
        self.label.setGeometry(QtCore.QRect(180, 10, 251, 16))
        font = QtGui.QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setToolTipDuration(1)
        self.label.setObjectName("label")

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)
        self.pushButton_2.clicked.connect(exitapp)
        self.lineEdit.textChanged.connect(self.choosepath)
        self.toolButton.clicked.connect(self.button_click)
        self.pushButton.clicked.connect(self.exec)

    def retranslateUi(self, ImportCreds):
        _translate = QtCore.QCoreApplication.translate
        ImportCreds.setWindowTitle(_translate("ImportCreds", "ImportCreds"))
        self.toolButton.setText(_translate("ImportCreds", "导入"))
        self.pushButton.setText(_translate("ImportCreds", "执行"))
        self.pushButton_2.setText(_translate("ImportCreds", "X"))
        self.label.setText(_translate("ImportCreds", "jenkins批量凭据及SSH授权配置工具"))

    def checkIP(self, IP):
        try:
            strIP = str(IP)
            socket.inet_aton(strIP)
            return True
        except socket.error:
            return False

    def checkSSH(self, ip, port, user, passwd):
        ssh = paramiko.SSHClient()
        port = int(port)
        ip = str(ip)
        passwd = str(passwd)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print(ip + str(port) + user + passwd)
        try:
            ssh.connect(ip, port, user, passwd, timeout=0.5)
            return True
        except Exception as e:
            return False

    def choosepath(self):
        if 0 == self.lineEdit.toPlainText().find('file:///'):
            self.lineEdit.setText(self.lineEdit.toPlainText().replace('file:///', ''))

    def button_click(self):
        # os.chdir(os.getenv('USERPROFILE') + "\\Desktop")
        # absolute_path is a QString object
        absolute_path = QFileDialog.getOpenFileName(self, "Open file",
                                                    os.getenv('USERPROFILE') + "\\Desktop", "Excel files (*.xlsx)")
        self.lineEdit.setText(absolute_path[0])

    def messageBox(self, title, text):
        messagebox = QMessageBox()
        messagebox.setWindowIcon(QIcon('resources/jenkins.ico'))
        messagebox.setWindowTitle(title)
        messagebox.setStyleSheet(button_style)
        messagebox.setText(text)
        messagebox.addButton(QtWidgets.QPushButton('确定'), QMessageBox.YesRole)
        messagebox.exec_()

    def exec(self):
        self.textBrowser.clear()
        self.textBrowser.append("开始执行.....................")
        filename = self.lineEdit.toPlainText()
        df = pd.read_excel(filename)

        def exec_():
            for i in range(0, len(df)):
                name = str(df.iloc[i][0]).strip()
                ip = str(df.iloc[i][1]).strip()
                username = str(df.iloc[i][2]).strip()
                password = str(df.iloc[i][3]).strip()
                # if self.checkIP(ip) == False:
                #     ip = str(df.iloc[i - 1][1])
                #     port = int(df.iloc[i - 1][5])
                # else:
                # port = int(df.iloc[i][5])
                id = des = ip

                if self.checkIP(ip) == True:
                    #
                    # if self.checkSSH(ip, port, username, password) == True:
                    if jenkins_credentials.searchEOSCredentials(self, self.url, self.domain_name, id,
                                                                self.jenkinsUserName, self.jenkinsPassword):
                        jenkins_credentials.updateEOSCredentials(self,  username, password, id, des,
                                                                 self.jenkinsUserName, self.jenkinsPassword)
                        self.textBrowser.append("ip = {0};username={1},password={2}".format(ip, username, password))
                        self.textBrowser.append('{0}的凭据已经存在，执行更新密码操作。'.format(ip))
                        self.textBrowser.moveCursor(self.textBrowser.textCursor().End)
                    else:
                        jenkins_credentials.createEOSCredentials(self, username, password, id, des, self.jenkinsUserName,
                                                                 self.jenkinsPassword)
                        self.textBrowser.append("ip = {0};username={1},password={2}".format(ip, username, password))
                        self.textBrowser.append('完成{0}的凭据的添加操作。'.format(ip))
                        self.textBrowser.moveCursor(self.textBrowser.textCursor().End)

                    if name in SshHostConfiguration().getHostConfigurations():
                        SshHostConfiguration().removeHostConfiguration(name)
                        SshHostConfiguration().addHostConfiguration(name, ip,
                                                                    username, '/usr/local/server',
                                                                    password)

                        self.textBrowser.append('{0}的SSH授权配置已经存在，执行更新配置操作。'.format(name))
                    else:
                        SshHostConfiguration().addHostConfiguration(name, ip,
                                                                    username, '/usr/local/server',
                                                                    password)
                        self.textBrowser.append('完成{0}的SSH授权的添加操作。'.format(name))

                    # else:
                    #     self.textBrowser.append(
                    #         "<font color='green'>SSH登录失败，请检查{0}的口令或者用户名是否正确</font>".format(ip))
                    #     self.textBrowser.moveCursor(self.textBrowser.textCursor().End)

                else:
                    self.textBrowser.append("{0}不是一个有效的ip地址，请检查导出结果.".format(ip))
                    self.textBrowser.moveCursor(self.textBrowser.textCursor().End)
            self.textBrowser.append("执行完毕.....................")

        threading.Thread(target=exec_, daemon=True).start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    form = QWidget()
    w = Ui_jenkinslogin()
    w.show()
    sys.exit(app.exec_())
