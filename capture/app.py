import sys
from PySide2.QtWidgets import (QDialog, QLineEdit, QPushButton, QApplication,
    QVBoxLayout, QHBoxLayout, QMainWindow, QLabel, QComboBox, QWidget)
import socket
import requests
import signal
import os
import ifaddr
from subprocess import Popen, PIPE
from zipfile import ZipFile
import pickle
import json


WORKINGDIR = os.path.dirname(os.path.realpath(__file__))

sniff_resources = {
    "SSLKEYLOGFILE" : os.path.join(WORKINGDIR, "eavesdrop.keylog"),
    "CAPTUREFILE"  : os.path.join(WORKINGDIR,"capture.pcap") ,
    "METADATA" : os.path.join(WORKINGDIR,".eavesdrop")
}


class RegisterForm(QDialog):
    def __init__(self, parent=None):
        super(RegisterForm, self).__init__(parent)
        self.setWindowTitle("Register")
        self.parent = parent
        self.req = {}
        layout = QVBoxLayout()
        username_layout = QHBoxLayout()
        description_layout = QHBoxLayout()
        button_layout = QHBoxLayout()

        info_label = QLabel("Config file missing please register or reopen app in appropriate directory")

        username_label = QLabel("Username")
        description_label = QLabel("Desciption")
        self.username_edit = QLineEdit("")
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_edit)
        self.description_edit = QLineEdit("")
        description_layout.addWidget(description_label)
        description_layout.addWidget(self.description_edit)
        self.submit_button = QPushButton("Submit")
        self.cancel_button = QPushButton("Cancel")
        button_layout.addWidget(self.submit_button)
        button_layout.addWidget(self.cancel_button)

        layout.addWidget(info_label)
        layout.addLayout(username_layout)
        layout.addLayout(description_layout)
        layout.addLayout(button_layout)
        self.setLayout(layout)
        self.submit_button.clicked.connect(self.submit)

    def submit(self):
        self.req["machine_name"] = socket.gethostname()
        self.req["username"] = self.username_edit.text()
        self.req["description"] = self.description_edit.text()
        res = requests.post("https://worriedwolf.com/api/register", data =self.req)
        if res != 200:
            print("error while trying to resgister")
            print(res)
            print(self.req)
            return
        self.req["uid"] = res.text
        with open(sniff_resources["METADATA"], 'wb') as fp:
            pickle.dump(self.req, fp, protocol=pickle.HIGHEST_PROTOCOL)
        self.parent.req = self.req
        self.close()

        

class SniffForm(QWidget):
    def __init__(self, parent=None):
        super(SniffForm, self).__init__(parent)
        self.setWindowTitle("Sniff Form")
        self.websites = requests.get('https://worriedwolf.com/api/websites').json()
        self.actions = requests.get('https://worriedwolf.com/api/actions').json()
        self.sniff_process = None
        os.environ["SSLKEYLOGFILE"] = sniff_resources["SSLKEYLOGFILE"]
        self.archive = False
        self.req = {}
        if parent:
            self.req["machine_id_str"] = parent.req["uid"]

        layout = QVBoxLayout()
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Sniff")
        self.end_button = QPushButton("End Sniff")
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.end_button)
        self.start_button.clicked.connect(self.start_sniff)
        self.end_button.clicked.connect(self.stop_sniff)

        self.submit_widget = QWidget()
        self.form_layout = QVBoxLayout()
        website_layout = QHBoxLayout()
        website_label = QLabel("Website")
        self.website_edit = QComboBox()
        for website in self.websites:
            self.website_edit.addItem(website["name"])
        website_layout.addWidget(website_label)
        website_layout.addWidget(self.website_edit)

        self.status_label = QLabel("Ready")

        action_layout = QHBoxLayout()
        action_label = QLabel("Action")
        self.action_edit = QComboBox()
        for action in self.actions:
            self.action_edit.addItem(action["action_type"])
        action_layout.addWidget(action_label)
        action_layout.addWidget(self.action_edit)

        self.submit_layout = QHBoxLayout()
        submit_button = QPushButton("Submit")
        discard_button = QPushButton("Discard")
        self.submit_layout.addWidget(submit_button)
        self.submit_layout.addWidget(discard_button)

        submit_button.clicked.connect(self.send_sniff)
        discard_button.clicked.connect(self.clean_up)
        
        
        self.submit_widget.setLayout(self.submit_layout)
        self.submit_widget.setVisible(False)
        layout.addLayout(website_layout)
        layout.addLayout(action_layout)
        layout.addLayout(button_layout)
        layout.addWidget(self.status_label)
        layout.addWidget(self.submit_widget)
        self.setLayout(layout)


    def get_ip_addresses(self):
        adapters = ifaddr.get_adapters()
        addresses = ""
        for adapter in adapters:
            for addr in adapter.ips:
                if addr.is_IPv4:
                    addresses +=  "%s," % (addr.ip)
        return addresses

    def start_sniff(self):
        start_sniff_cmd = "exec tshark poetry run python -w {0}".format(sniff_resources["CAPTUREFILE"]).encode()
        open_browser_cmd = b"google-chrome  " + self.websites[self.website_edit.currentIndex()]["domain"].encode()
        print(open_browser_cmd)
        self.sniff_process =  Popen(start_sniff_cmd, shell=True)
        Popen(open_browser_cmd, shell=True)
        self.status_label.setText("Sniffing")

    def stop_sniff(self): 
        if self.sniff_process:
            self.sniff_process.kill()
        self.submit_widget.setVisible(True)
        self.status_label.setText("Stopped and staged")

    def send_sniff(self):
        self.req["website_id"] = self.find_website_id()
        self.req["action"] = self.action_edit.currentText()
        self.req["external_ipv4"] =requests.get('https://checkip.amazonaws.com').text.strip()
        self.req["keylog"] = open(sniff_resources["SSLKEYLOGFILE"], "rb")
        self.req["capture"] = open( sniff_resources["CAPTUREFILE"], "rb")
        self.req["internal_ipv4s_str"] = self.get_ip_addresses()
        res = requests.post("https://worriedwolf.com/api/report", data=self.req)
        if res.status_code != 200:
            print("error sending report")
            print(res)
        self.clean_up()
        

    def find_website_id(self):
        for website in self.websites:
            if website["name"] == self.website_edit.currentIndex():
                return website["id"]

    def clean_up(self):
        if self.archive:
            with ZipFile('sample2.zip', 'w') as archive:
                archive.write(sniff_resources["SSLKEYLOGFILE"])
                archive.write(sniff_resources["CAPTUREFILE"])
        os.remove(sniff_resources["SSLKEYLOGFILE"])
        os.remove(sniff_resources["CAPTUREFILE"])
        self.submit_widget.setVisible(False)
        self.status_label.setText("ready")



class CaptureWindow(QWidget):
    def __init__(self):
        super(CaptureWindow, self).__init__()
        layout = QVBoxLayout()
        self.req = {}
        self.setup()
        uid_label = QLabel(self.req["uid"])
        username_label = QLabel(self.req["username"])
        self.sniff_widget = SniffForm(self)
        layout.addWidget(uid_label)
        layout.addWidget(username_label)
        layout.addWidget(self.sniff_widget)
        self.setLayout(layout)

    def setup(self):
        if os.path.exists(sniff_resources["METADATA"]):
            with open(sniff_resources["METADATA"], "rb") as config:
                self.req = pickle.load(config)
        else:
            register = RegisterForm(self)
            register.show()
        
    def destroy_sniff(self):
        self.sniff_widget.close()
        self.sniff_widget = SniffForm(self)

            

if __name__ == '__main__':
    app = QApplication(sys.argv)
    form = CaptureWindow()
    form.show()
    sys.exit(app.exec_())