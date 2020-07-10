from PyQt5 import QtCore, QtGui, QtWidgets
from scapy.all import *
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import pickle
import psutil
import time
import ipaddress
from threading import Thread

# global variables
load_layer('tls')
headers = ['ip', 'udp', 'tcp', 'tls', 'ntp', 'dns', 'mdns', 'dhcp', 'srcport',\
       'dstport', 'frame.len']
ip_cams = ['Dlink', 'Foscam', 'Xiaomi', 'Tplink']
PACKET_NUM = 100
ip_count = 0
white_dict = {}
black_list = {}
init_black_list = []
mac_list = []
LAN_IP_mask = None
LAN_IP = None
model = None
BPF_FILTER = None
adapte_thread = None


class Ui_MainWindow(object):
    

    def setupUi(self, MainWindow):
        global output_string, Main 
        
        MainWindow.setObjectName("MainWindow")
        MainWindow.setFixedSize(1200, 900)
        Main = MainWindow
        # MainWindow.setStyleSheet("background: gray")

        self.button_start = QtWidgets.QPushButton(MainWindow)
        self.button_start.setGeometry(QtCore.QRect(100, 10, 300, 100))
        self.button_start.setText('Start')
        self.button_start.setVisible(True)
        self.button_start.clicked.connect(self.button_start_clicked)
        # self.button_start.setIcon(QtGui.QIcon('picture/button.png'))
        # self.button_start.setIconSize(self.button_start.size())

        self.button_reset = QtWidgets.QPushButton(MainWindow)
        self.button_reset.setGeometry(QtCore.QRect(800, 10, 300, 100))
        self.button_reset.setText('Reset')
        self.button_reset.setVisible(False)
        self.button_reset.clicked.connect(self.button_reset_clicked)
        
        self.output = QtWidgets.QTextBrowser(MainWindow)
        self.output.setGeometry(QtCore.QRect(100, 150, 1000, 700))
        self.output.setStyleSheet("background: white; color: darkCyan; font-size: 48px; font-weight: bold")

        output_string = ''

        

    def button_start_clicked(self): # for starting
        print('start!!!')
        self.output.setText('Please wait for a minute to adapt the environment!\n')
        self.button_start.setVisible(False)

        thread = Thread(target = self.start)
        thread.setDaemon(True)
        thread.start()
        
        
    
    def button_reset_clicked(self): # for Resetting
        global ip_count, white_dict, black_list, init_black_list
        self.output.setText('Finish resetting!\n')
        white_dict, black_list = self.init_dict(init_black_list)
        ip_count = 0
        print("IP black list after Resetting")
        for index, ip_addr in enumerate(init_black_list):
            print("{0}. {1}".format(index+1, ip_addr))


    def display_output(self, text):
        self.output.append(text)
   
    # For debugging
    def print_dict(self):
        for key in white_dict.keys():
            print("IP is {0}, with length {1}".format(key, len(white_dict[key])))
        print("Below IP addresses are in black list.")
        for ip_addr in black_list:
            print(ip_addr)

    # For debugging
    def print_prob(self, ip_addr, prob_list):
        for index, prob in enumerate(prob_list):
            self.plot_prob_pie(ip_addr, index+1, prob)

    # Extract all network adapter informations
    def get_interface_info(self):
        # Dictionary to store the information of each network interface
        interface_info = dict()
        dic = psutil.net_if_addrs()
        for adapter in dic:
            snic_list = dic[adapter]
            mac = list()
            ipv4 = list()
            ipv6 = list()
            netmask = list()
            for snic in snic_list:
                if snic.family.name in {'AF_LINK', 'AF_PACKET'}:
                    mac.append(snic.address)
                elif snic.family.name == 'AF_INET':
                    ipv4.append(snic.address)
                    netmask.append(snic.netmask)
                elif snic.family.name == 'AF_INET6':
                    ipv6.append(snic.address)
                    
            interface_info[adapter] = (mac, ipv4, ipv6, netmask)
        return interface_info

    # Initialize the data structure
    def init_dict(self, init_black_list=[]):
        # Will continuously collecting packets and append on corresponding IP address
        white_dict = dict()
        # Stop collect the packets in the black list
        black_list = list(init_black_list)
        if '255.255.255.255' not in black_list:
            black_list.append('255.255.255.255')
        return white_dict, black_list

    # Load model
    def load_model(self, filepath):
        # Filepath of model must end with .sav, otherwise Exception will occur
        if filepath.endswith(".sav"):
            try:
                l_model = pickle.load(open(filepath,'rb'))
                return l_model
            except FileNotFoundError:
                pass
            raise Exception("File path: {0} is invalid.".format(filepath))
        raise Exception("File extension is not correct: {0}.".format(filepath.split("/")[-1]))

    # Output the prediction by given probabilities list
    def predict_brand(self, ip_addr, prob_list, packet_list):
        print("Prediction for IP address {0}".format(ip_addr))
        self.display_output("Prediction for IP address {0}".format(ip_addr))
        # threading.main_thread()

        # Calculate the prediction count of each brand(including unknown)
        total_cate = ip_cams + ['unknown']
        predict_count = {total_cate[i]: 0 for i in range(len(total_cate))} 
        min_threshold = 0.5
        # max_threshold = 1.1
        for prob in prob_list:
            if np.max(prob) >= min_threshold: #and np.min(prob) <= max_threshold:
                pred_brand = total_cate[np.argmax(prob)]
                predict_count[pred_brand] += 1
            else:
                predict_count['unknown'] += 1
        for key in predict_count:
            print("{0} : {1}".format(key, predict_count[key]))
            # self.display_output("{0} : {1}".format(key, predict_count[key]))
        if(max(predict_count, key=predict_count.get) == 'Dlink'):
            if(self.match_type(packet_list)):
                self.display_output("Model type: DCS-8000LHV2")          
        self.display_output("Detecting the new device: {0}\n".format(max(predict_count, key=predict_count.get)))

    # Match the model type
    def match_type(self, packet_list):
        model_type = "DCS-8000LHV2"
        for p in packet_list:
            if DNS in p:
                if p.qd:
                    if model_type in p.qd.qname.decode("utf-8"):
                        return True
        return False

    def packet2feature(self, packet_list):
         # Initialize the feature map
        feature_list = np.zeros((PACKET_NUM, len(headers))).astype('U')
        for index, p in enumerate(packet_list):
            # IP prtocol
            if IP in p:
                feature_list[index][headers.index('ip')] = 1
            # UDP protocol
            if UDP in p:
                feature_list[index][headers.index('udp')] = 1

            # TCP protocol
            if TCP in p:
                feature_list[index][headers.index('tcp')] = 1

            # TLS protocol
            if TLS in p:
                feature_list[index][headers.index('tls')] = 1

            # NTP protocol
            if NTPHeader in p:
                feature_list[index][headers.index('ntp')] = 1
                
            # MDNS protocol
            if DNS in p and p[DNS].qd == None:
                feature_list[index][headers.index('mdns')] = 1

            # DHCP protocol
            if p.haslayer('DHCP options'):
                feature_list[index][headers.index('dhcp')] = 1

            # Extract frame length 
            frame_len = len(p)
            feature_list[index][headers.index('frame.len')] = frame_len
            
            # Extract source port and destination port
            if TCP in p or UDP in p:
                src_port = p.sport
                dst_port = p.dport
                feature_list[index][headers.index('srcport')] = src_port
                feature_list[index][headers.index('dstport')] = dst_port
        df = pd.DataFrame(data=feature_list, columns=headers)
        return df
    def packet_callback_adapt(self, packet):
        global init_black_list
        ip_dst = None
        ip_src = None
        # Case for IPv4 
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst 
        # Otherwise
        else:
            pass

        # Add to init_black_list
        if ip_src not in init_black_list and ip_src:
            init_black_list.append(ip_src)
        if ip_dst not in init_black_list and ip_dst:
            init_black_list.append(ip_dst)

    def packet_callback(self, packet):
        global ip_count, white_dict, black_list, LAN_IP, LAN_IP_mask
        # print(ip_count)
        ip_dst = None
        ip_src = None  
        # Case for IPv4 
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst       
            ip_count += 1
        # Otherwise
        else:
            pass
        
        # Filter ip_src is not in black_list and ip_src has value
        if ip_src not in black_list and ip_src:
            # ip_dst is new for white_dict
            if ip_dst not in white_dict.keys():
                white_dict[ip_dst] = list()
                white_dict[ip_dst].append(packet)
            # ip_src exists in white_dict
            if ip_src in white_dict.keys():
                # Check if the packet is sufficient for predicting
                if len(white_dict[ip_src]) == PACKET_NUM and self.get_LAN_IP(ip_src, LAN_IP_mask) == LAN_IP:
                    # packet to feature list
                    df = self.packet2feature(white_dict[ip_src])
                    probabilities = model.predict_proba(df)
                    self.predict_brand(ip_src, probabilities, white_dict[ip_src])
                    # After prediction, delete the element and add to black_list
                    del white_dict[ip_src]
                    black_list.append(ip_src)
                else:    
                    white_dict[ip_src].append(packet)

        # Filter ip_dst is not in black_list and ip_dst has value
        if ip_dst not in black_list and ip_dst:
            # ip_src is new for white_dict
            if ip_src not in white_dict.keys():
                white_dict[ip_src] = list()
                white_dict[ip_src].append(packet)
            # ip_dst exists in white_dict
            if ip_dst in white_dict.keys():
                # Check if the packet is sufficient for predicting
                if len(white_dict[ip_dst]) == PACKET_NUM and self.get_LAN_IP(ip_dst, LAN_IP_mask) == LAN_IP:
                    # packet to feature list
                    df = self.packet2feature(white_dict[ip_dst])
                    probabilities = model.predict_proba(df)
                    self.predict_brand(ip_dst, probabilities, white_dict[ip_dst])
                    # After prediction, delete the element and add to black_list
                    del white_dict[ip_dst]
                    black_list.append(ip_dst)
                else:
                    white_dict[ip_dst].append(packet)
        if ip_count % 100 == 0:
            # self.display_output('Processing every {0} packets at {1}'.format(ip_count, time.ctime()))
            print("Processing every {0} packets at {1}".format(ip_count, time.ctime()))
            
    # Function to process ip to integer
    def ip2int(self, addr):
        return int(ipaddress.ip_address(addr))

    # Function to process integer to ip
    def int2ip(self, ip_int):
        return str(ipaddress.IPv4Address(ip_int))

    # Get Local Area Network IP address by subnet mask
    def get_LAN_IP(self, ip_addr, netmask):
        return self.int2ip(self.ip2int(ip_addr) & self.ip2int(netmask))

    def start(self):
        global adapte_thread
        adapte_thread = Thread(target = self.init)
        adapte_thread.setDaemon(True)
        adapte_thread.start()
        adapte_thread.join()

        self.button_reset.setVisible(True)
        self.display_output("Start detecting!\n")
        sniff(iface='乙太網路', prn=self.packet_callback, filter=BPF_FILTER)
        self.print_dict()
        print(ip_count)
        # print(pc_info)

    def init(self):
        global model, white_dict, black_list, ip_count, init_black_list, LAN_IP_mask, LAN_IP
        pc_info = self.get_interface_info()
        # Store the ipv4 and ipv6 addresses of this pc network adapter
        init_black_list = []
        # Store the BPF format of filter string
        mac_list = []
        # Ultimately BPF filter string
        BPF_FILTER = ""
        ip_count = 0

        LAN_IP_mask = pc_info['乙太網路'][3][0]
        LAN_IP = self.get_LAN_IP(pc_info['乙太網路'][1][0], LAN_IP_mask)

        for key in pc_info:
            if pc_info[key][0]:
                for mac in pc_info[key][0]:
                    mac = mac.replace("-", ":").lower()
                    mac = "(not ether src " + mac + ") and (not ether dst " + mac + ")"
                    mac_list.append(mac)
            if pc_info[key][1]:
                init_black_list += pc_info[key][1]

        BPF_FILTER = " and ".join(mac_list)
        BPF_FILTER += " and (not ether dst ff:ff:ff:ff:ff:ff) and (not ip6) and (not arp)"

        print(BPF_FILTER)
        print("IP black list before adaption : ")
        for index, ip_addr in enumerate(init_black_list):
            print("{0}. {1}".format(index+1, ip_addr))

        sniff(iface='乙太網路', prn=self.packet_callback_adapt, filter=BPF_FILTER, timeout=60)
        print("\nIP black list after adaption : ")
        for index, ip_addr in enumerate(init_black_list):
            print("{0}. {1}".format(index+1, ip_addr))

        white_dict, black_list = self.init_dict(init_black_list)
        model = self.load_model('./model/RFmodel2.sav')  