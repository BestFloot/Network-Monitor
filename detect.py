from scapy.all import sniff, IP
import joblib
import numpy as np
import pandas as pd
import colorama
import os
import socket
import logging
import time
import json
from collections import defaultdict
from datetime import datetime
from colorama import Fore, init
init(autoreset=True)

def cls():
    os.system("cls" if os.name == "nt" else "clear")

cls()

datestring = datetime.now().strftime("%Y%m%d_%H%M%S")
logging.basicConfig(filename=f'ids_log_{datestring}.txt', level=logging.INFO, format='&(asctime)s - %(levelname)s - %(message)s')
model = joblib.load('ids_model.pkl')
packet_counts = defaultdict(lambda: {'count':0, 'protocol':None, 'timestamp':time.time()})
ip_sources = defaultdict(lambda: 0)

with open('config.json') as config_file:
    config = json.load(config_file)

CAPTURE_DURATION = int(input("Capture Duration (in seconds):"))
ANOMALYS = 0
PACKETS_SNIFFED = 0
OKAY_PACKETS = 0

DDOS_THRESHOLD = config['ddos_packet_size_threshold']
DOS_THRESHOLD = config['dos_packet_size_threshold']
SMALL_ATTACK_THRESHOLD = config['small_attack_packet_size_threshold']
MEDIUM_ATTACK_THRESHOLD = config['medium_attack_packet_size_threshold']
LARGE_ATTACK_THRESHOLD = config['large_attack_packet_size_threshold']

def log(src_ip, dst_ip, protocol, packet_length, anomaly_type):
    logging.info(f"Anomaly Detected: type={anomaly_type}, src_ip={src_ip}, dst_ip={dst_ip}, protocol={protocol}, packet_length={packet_length}")

def classify(packet_length, src_ip, dst_ip, protocol):
    if packet_length>1500:
        return "Oversized Packet"
    elif is_ddos_attack(src_ip, protocol):
        return "Potential DDoS Attack"
    elif is_dos_attack(src_ip, protocol):
        return "Potential DDoS Attack"
    return "General Anomaly"

def is_ddos_attack(src_ip, protocol):
    global packet_counts
    current_time = time.time()

    if current_time - packet_counts[src_ip]['timestamp'] > 60:
        packet_counts[src_ip] = {'count':0, 'protocol':protocol, 'timestamp':current_time}
        ip_sources.clear()

    packet_counts[src_ip]['count'] += 1

    count = packet_counts[src_ip]['count']
    attack_type = None

    if count > LARGE_ATTACK_THRESHOLD:
        attack_type = "Large DDoS Attack"
    elif count > MEDIUM_ATTACK_THRESHOLD:
        attack_type = "Medium DDoS Attack"
    elif count > SMALL_ATTACK_THRESHOLD:
        attack_type = "Small DDoS Attack"

    if attack_type:
        log(src_ip, "", protocol, count, attack_type)
        return True

def is_dos_attack(src_ip, protocol):
    global packet_counts, ip_sources
    current_time = time.time()
    if current_time - packet_counts[src_ip]['timestamp'] > 60:
        packet_counts[src_ip] = {'count':0, 'protocol':protocol, 'timestamp':current_time}
        ip_sources.clear()
    
    packet_counts[src_ip]['count'] += 1

    if packet_counts[src_ip]['count'] > 100:
        ip_sources[src_ip] += 1

    if len(ip_sources) == 1 and packet_counts[src_ip]['count'] > DOS_THRESHOLD:
        log(src_ip, "", protocol, packet_counts[src_ip]['count'],"Potential DoS Attack")
        return True
    
    return False

def detect_anomaly(packet):
    global ANOMALYS
    global PACKETS_SNIFFED
    global OKAY_PACKETS
    if packet.haslayer(IP):
        data = {
            'src_ip': [packet[IP].src],
            'dst_ip': [packet[IP].dst],
            'protocol': [packet[IP].proto],
            'packet_length': [len(packet)],
        }
        df = pd.DataFrame(data)

        df['src_ip_numeric'] = df['src_ip'].apply(lambda x: int.from_bytes(socket.inet_aton(x), 'big'))
        df['dst_ip_numeric'] = df['dst_ip'].apply(lambda x: int.from_bytes(socket.inet_aton(x), 'big'))
        df_numeric = df[['src_ip_numeric', 'dst_ip_numeric', 'protocol', 'packet_length']]

        PACKETS_SNIFFED += 1
        if not df_numeric.empty:
            prediction = model.predict(df_numeric)
            if prediction[0] == -1:
                anomaly_type = classify(df['packet_length'][0], df['src_ip'][0], df['dst_ip'][0], df['protocol'][0])
                print(f"{Fore.MAGENTA}({Fore.RED}-{Fore.MAGENTA}){Fore.RESET} Anomaly Detected at {datetime.now()}! Type - {anomaly_type}")
                ANOMALYS += 1
                print(df)
                log(df['src_ip'][0], df['dst_ip'][0], df['protocol'][0], df['packet_length'][0], anomaly_type)
            else:
                print(f"{Fore.MAGENTA}({Fore.GREEN}+{Fore.MAGENTA}){Fore.RESET} Normal Packet at {datetime.now()}")
                OKAY_PACKETS += 1
        os.system(f"title Anomalys Detected [{ANOMALYS}] - Packets Sniffed [{PACKETS_SNIFFED}] - Normal Packets [{OKAY_PACKETS}]")

sniff(timeout=CAPTURE_DURATION, prn=detect_anomaly)