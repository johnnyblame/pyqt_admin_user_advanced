import json
import string
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QPixmap, QIcon
import sys
from PyQt5.QtWidgets import QMainWindow, QDialog, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QApplication,\
    QWidget
import os
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD2
ha = MD2.new()
from padding import pad, unpad
iv = os.urandom(16)

users_template = {
    "admin": ""
}
with open('users.json', 'w') as file:
    json.dump(users_template, file)
with open('users.json', 'r') as f:
    users = json.load(f)
current = []
blocked = []
pw_check_enabled = []
secrets = []


class Window(QMainWindow):
    switch_window = pyqtSignal()

    def __init__(self):
        super(Window, self).__init__()
        if current[-1] == 'admin':
            self.setWindowTitle('Welcome Admin')
            self.changepw_textbox = QLineEdit(self)
            self.changepw_textbox.setReadOnly(True)
            self.changepw_textbox.setPlaceholderText('Change Password: ')
            self.old_pw = QLineEdit(self)
            self.old_pw.setPlaceholderText('Old Password')
            self.old_pw.setEchoMode(QLineEdit.Password)
            self.new_pw = QLineEdit(self)
            self.new_pw.setPlaceholderText('New Password')
            self.new_pw.setEchoMode(QLineEdit.Password)
            self.changepw = QPushButton('Change Password', self)
            self.changepw.clicked.connect(self.change_password)
            self.show_users = QPushButton('Show Users', self)
            self.show_users.clicked.connect(self.on_show)
            self.add_username = QLineEdit(self)
            self.add_username.setPlaceholderText('Set New Username')
            self.add_user = QPushButton('Add User', self)
            self.add_user.clicked.connect(self.add)
            self.exit = QPushButton('Back to Login', self)
            self.exit.clicked.connect(self.switch)
            self.block_user = QLineEdit(self)
            self.block_user.setPlaceholderText('Username to Block')
            self.blockButton = QPushButton('Block', self)
            self.blockButton.clicked.connect(self.block)
            self.pw_checker = QLineEdit(self)
            self.pw_checker.setPlaceholderText('User for whom enable/disable password check')
            self.pwButton_e = QPushButton('Enable', self)
            self.pwButton_e.clicked.connect(self.enable)
            self.pwButton_d = QPushButton('Disable', self)
            self.pwButton_d.clicked.connect(self.disable)
            self.pw_confirm = QLineEdit(self)
            self.pw_confirm.setPlaceholderText('Confirm password')
            self.pw_confirm.setEchoMode(QLineEdit.Password)
            self.layout = QVBoxLayout(self)
            self.layout.addWidget(self.changepw_textbox)
            self.layout.addWidget(self.old_pw)
            self.layout.addWidget(self.new_pw)
            self.layout.addWidget(self.pw_confirm)
            self.layout.addWidget(self.changepw)
            self.layout.addWidget(self.show_users)
            self.layout.addWidget(self.add_username)
            self.layout.addWidget(self.add_user)
            self.layout.addWidget(self.block_user)
            self.layout.addWidget(self.blockButton)
            self.layout.addWidget(self.pw_checker)
            self.layout.addWidget(self.pwButton_e)
            self.layout.addWidget(self.pwButton_d)
            self.layout.addWidget(self.exit)
            self.widget = QWidget()
            self.widget.setLayout(self.layout)
            self.setLayout(self.layout)
            self.setCentralWidget(self.widget)
        else:
            self.setWindowTitle('Welcome {}'.format(next(iter(current))))
            self.changepw_textbox = QLineEdit(self)
            self.changepw_textbox.setReadOnly(True)
            self.changepw_textbox.setPlaceholderText('Change Password: ')
            self.old_pw = QLineEdit(self)
            self.old_pw.setPlaceholderText('Old Password')
            self.old_pw.setEchoMode(QLineEdit.Password)
            self.new_pw = QLineEdit(self)
            self.new_pw.setPlaceholderText('New Password')
            self.new_pw.setEchoMode(QLineEdit.Password)
            self.changepw = QPushButton('Change Password', self)
            self.changepw.clicked.connect(self.change_password)
            self.exit = QPushButton('Back to Login', self)
            self.exit.clicked.connect(self.switch)
            self.pw_confirm = QLineEdit(self)
            self.pw_confirm.setPlaceholderText('Confirm password')
            self.pw_confirm.setEchoMode(QLineEdit.Password)
            self.layout = QVBoxLayout(self)
            self.layout.addWidget(self.changepw_textbox)
            self.layout.addWidget(self.old_pw)
            self.layout.addWidget(self.new_pw)
            self.layout.addWidget(self.pw_confirm)
            self.layout.addWidget(self.changepw)
            self.layout.addWidget(self.exit)
            self.widget = QWidget()
            self.widget.setLayout(self.layout)
            self.setLayout(self.layout)
            self.setCentralWidget(self.widget)

    def switch(self):
        self.switch_window.emit()

    def change_password(self):
        pw_check = True
        curr = current[-1]
        print(curr)
        if self.old_pw.text() in users.values():
            if curr in pw_check_enabled:
                pw_check = self.password_control()
                print(pw_check)
            if pw_check is False:
                QMessageBox.warning(self, 'Error', 'Password must contain digits, letters and punctuations')
            else:
                if self.pw_confirm.text() == self.new_pw.text():
                    users[curr] = self.new_pw.text()
                    with open('users.json', 'w') as j:
                        json.dump(users, j, indent=4)
                    QMessageBox.information(self, 'Success', 'Password Changed')
                else:
                    QMessageBox.warning(self, 'Warning', 'Failed confirmation, please try again.')
        else:
            QMessageBox.warning(self, 'Error', 'Invalid Password')

    def on_show(self):
        s = ""
        for k in users:
            if k in blocked:
                if k in pw_check_enabled:
                    s += k + ' blocked ' + 'Password check enabled' + '\n'
                else:
                    s += k + ' blocked ' + 'Password check disabled' + '\n'
            else:
                if k in pw_check_enabled:
                    s += k + ' Password check enabled' + '\n'
                else:
                    s += k + ' Password check disabled' + '\n'
        QMessageBox.information(self, 'Users', s)

    def add(self):
        users[self.add_username.text()] = ''
        with open('users.json', 'w') as jso:
            json.dump(users, jso, indent=4)
        QMessageBox.information(self, 'Success', 'User added')

    def block(self):
        blocked.append(self.block_user.text())
        users['status_for_{}'.format(self.block_user.text())] = 'blocked'
        with open('users.json', 'w') as something:
            json.dump(users, something, indent=4)
        QMessageBox.information(self, 'User Blocked', '{} has been blocked'.format(self.block_user.text()))

    def password_control(self):
        check = 0
        check_1 = 0
        check_2 = 0
        check_3 = 0
        for i in self.new_pw.text():
            if i in string.punctuation:
                check_1 = 1
            else:
                check += 0
            if i in string.digits:
                check_2 = 1
            else:
                check += 0
            if i in string.ascii_letters:
                check_3 = 1
            else:
                check += 0
        check = check_1 + check_2 + check_3
        if check == 3:
            return True
        else:
            return False

    def enable(self):
        pw_check_enabled.append(self.pw_checker.text())
        users['pw_control_status_for_{}'.format(self.pw_checker.text())] = 'has password control enabled'
        with open('users.json', 'w') as something:
            json.dump(users, something, indent=4)

    def disable(self):
        pw_check_enabled.remove(self.pw_checker.text())
        users.pop(['pw_control_status_for_{}'.format(self.pw_checker.text())])
        with open('users.json', 'w') as something:
            json.dump(users, something, indent=4)


    def ecnryption(self, text):
        data = bytes(text, 'utf-8')
        ciphertext = secrets[1].encrypt(pad(data, AES.block_size))
        ct = b64encode(ciphertext).decode('utf-8')

        return str(ct)

    def decryption(self, entext):
        pt = unpad(secrets[1].decrypt(entext), AES.block_size)
        return pt

    def closeEvent(self, QCloseEvent):
        li = []
        li1 = []
        uss = {}
        for ke in users.keys():
            li.append(ke)
        for v in users.values():
            li1.append(v)
        for i in range(0, len(li)):
            uss[self.ecnryption(li[i])] = self.ecnryption(li1[i])
        with open('users_e.json', 'w') as enced:
            json.dump(uss, enced, indent=4)
        os.remove('users.json')


class Login(QDialog):
    switch_window = pyqtSignal()

    def __init__(self):
        super(Login, self).__init__()
        self.invalid_pw_count = 0
        self.setWindowTitle('Login')
        self.username = QLineEdit(self)
        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.Password)
        if len(current) == 0:
            self.session_key = QLineEdit(self)
            self.session_key.setPlaceholderText('Admin, set key')
        self.buttonLogin = QPushButton('Login', self)
        self.buttonLogin.clicked.connect(self.usercontrol)
        self.infoButton = QPushButton(self)
        self.infoButton.clicked.connect(self.showinfo)
        icon = QPixmap('unnamed.png')
        self.infoButton.setIcon(QIcon(icon))
        layout = QVBoxLayout(self)
        layout.addWidget(self.infoButton)
        layout.addWidget(self.username)
        layout.addWidget(self.password)
        if len(current) == 0:
            layout.addWidget(self.session_key)
        layout.addWidget(self.buttonLogin)

    def showinfo(self):
        QMessageBox.information(self, 'Info', 'Author: Victoria Gres \nIndividual task #5')

    def usercontrol(self):
        if self.username.text() in blocked:
            QMessageBox.warning(self, 'User is blocked', '{} was permanently blocked by admin.'
                                                         ' Exiting now. Sorry :)'.format(self.username.text()))
            QApplication.quit()
        if self.invalid_pw_count == 2:
            QApplication.quit()
        if self.username.text() == 'admin' and self.password.text() == users['admin']:
            current.append(self.username.text())
            self.keymaker()
            self.accept()
            self.switch_window.emit()

        elif self.username.text() in users.keys() and self.password.text() in users.values():
            current.append(self.username.text())
            self.accept()
            self.switch_window.emit()

        else:
            self.invalid_pw_count += 1
            QMessageBox.warning(self, 'Error', 'Enter again.')

    def keymaker(self):
        try:
            key = bytes(self.session_key.text(), 'utf-8') * 16
            ha.update(key)
            true_key = ha.hexdigest()
            cipher = AES.new(true_key, AES.MODE_CFB, iv)
        except ValueError:
            key = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CFB, iv)
        secrets.append(key)
        secrets.append(cipher)
        return key, cipher


class Controller:
    def __init__(self):
        pass

    def show_login(self):
        self.login = Login()
        self.login.switch_window.connect(self.show_main)
        self.login.show()

    def show_main(self):
        self.window = Window()
        self.window.switch_window.connect(self.show_login)
        self.login.close()
        self.window.show()


def main():
    app = QApplication(sys.argv)
    controller = Controller()
    controller.show_login()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()

