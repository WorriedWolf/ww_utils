import sys
from PySide2.QtWidgets import (QLineEdit, QPushButton, QApplication,
    QVBoxLayout, QHBoxLayout, QDialog, QLabel, QComboBox, QWidget)
import socket
import requests
import signal
import os
import ifaddr
from subprocess import Popen, PIPE
from zipfile import ZipFile
import pickle


sniff_resources = {
    "SSLKEYLOGFILE" : "eavesdrop.keylog",
    "CAPTUREFILE"  : "capture.pcap" ,
    "METADATA" : ".eavesdrop"
}


class RegisterForm(QWidget):
    def __init__(self, parent=None):
        super(RegisterForm, self).__init__(parent)
        self.setWindowTitle("Register")
        layout = QVBoxLayout()
        username_layout = QHBoxLayout()
        description_layout = QHBoxLayout()
        button_layout = QHBoxLayout()
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
        layout.addLayout(username_layout)
        layout.addLayout(description_layout)
        layout.addLayout(button_layout)
        self.setLayout(layout)
        self.submit_button.clicked.connect(self.submit)

    def submit(self):
        req = {}
        req["machine_name"] = socket.gethostname()
        req["username"] = self.username_edit.text()
        req["description"] = self.description_edit.text()
        res = requests.post("https://worriedwolf.com/api/register", data = req)
        if res != 200:
            print("error while trying to resgister")
            print(req)
            return

        req["uid"] = res.text
        with open('.eavesdrop', 'wb') as fp:
            pickle.dump(req, fp, protocol=pickle.HIGHEST_PROTOCOL)

        

class SniffForm(QWidget):
    def __init__(self, parent=None):
        super(SniffForm, self).__init__(parent)
        self.setWindowTitle("Sniff Form")
        self.websites = requests.get('https://worriedwolf.com/api/websites').json()
        self.actions = requests.get('https://worriedwolf.com/api/actions').json()
        self.sniff_process = None
        os.environ["SSLKEYLOGFILE"] = "eavesdrop.keylog"
        archive = False
        self.req = {}
        if parent:
            self.req["machine_id_str"] = parent.uid

        layout = QVBoxLayout()
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Sniff")
        self.end_button = QPushButton("End Sniff")
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.end_button)
        self.start_button.clicked.connect(self.start_sniff)
        self.end_button.clicked.connect(self.stop_sniff)

        self.form_widget = QWidget()
        self.form_layout = QVBoxLayout()
        website_layout = QHBoxLayout()
        website_label = QLabel("Website")
        self.website_edit = QComboBox()
        for website in self.websites:
            self.website_edit.addItem(website["name"])
        website_layout.addWidget(website_label)
        website_layout.addWidget(self.website_edit)


        action_layout = QHBoxLayout()
        action_label = QLabel("Action")
        self.action_edit = QComboBox()
        for action in self.actions:
            self.action_edit.addItem(action["action_type"])
        action_layout.addWidget(action_label)
        action_layout.addWidget(self.action_edit)

        submit_layout = QHBoxLayout()
        submit_button = QPushButton("Submit")
        discard_button = QPushButton("Discard")
        submit_layout.addWidget(submit_button)
        submit_layout.addWidget(discard_button)

        submit_button.clicked.connect(self.send_sniff)
        discard_button.clicked.connect(self.clean_up)
        
        self.form_layout.addLayout(website_layout)
        self.form_layout.addLayout(action_layout)
        self.form_layout.addLayout(submit_layout)
        self.form_widget.setLayout(self.form_layout)
        

        layout.addLayout(button_layout)
        layout.addWidget(self.form_widget)
        self.form_widget.setVisible(False)
        self.setLayout(layout)


    def get_ip_addresses(self):
        adapters = ifaddr.get_adapters()
        addresses = ""
        for adapter in adapters:
            addresses +=  "   %s/%s" % (adapter.ips[1].ip)

    def start_sniff(self):
        start_sniff_cmd = "tshark -w {0}".format(sniff_resources["CAPTUREFILE"]).encode()
        open_browser_cmd = b"google-chrome &"
        self.sniff_process =  Popen(start_sniff_cmd, shell=True)
        Popen(open_browser_cmd, shell=True)

    def stop_sniff(self): 
        if self.sniff_process:
            self.sniff_process.terminate()
        self.form_widget.setVisible(True)

    def send_sniff(self):
        self.req["website_id"] = self.find_website_id()
        self.req["action"] = self.action_edit.currentText()
        self.req["external_ipv4"] =requests.get('https://checkip.amazonaws.com').text.strip()
        self.req["keylog"] = open(sniff_resources["SSLKEYLOGFILE"], "rb")
        self.req["capture"] = open( sniff_resources["CAPTUREFILE"], "rb")
        self.req["internal_ipv4s_str"] = "hello_world"
        res = requests.post("https://worriedwolf.com/api/report", data=self.req)
        if res.status_code != 200:
            print(res)

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


            

if __name__ == '__main__':
    app = QApplication(sys.argv)
    # form = SniffForm()
    form = RegisterForm()
    form.show()
    sys.exit(app.exec_())