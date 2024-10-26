import pandas as pd
import numpy as np
import colorama
import os
import joblib
import socket
from scapy.all import sniff, IP
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from colorama import Fore, init
init(autoreset=True)

def cls():
    os.system("cls" if os.name == "nt" else "clear")

cls()

CAPTURE_DURATION = int(input("Capture Duration (in seconds):"))

if not os.path.exists('network_data.csv'):
    pd.DataFrame(columns=['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_length']).to_csv('network_data.csv', index=False)

def packet_callback(packet):
    if packet.haslayer(IP):
        data = {
            'timestamp': [datetime.now()],
            'src_ip': [packet[IP].src],
            'dst_ip': [packet[IP].dst],
            'protocol': [packet[IP].proto],
            'packet_length': [len(packet)],
        }
        df = pd.DataFrame(data)
        df.to_csv('network_data.csv', mode='a', header=False, index=False)

sniff(timeout=CAPTURE_DURATION, prn=packet_callback)
print(f"{Fore.MAGENTA}({Fore.CYAN}!{Fore.MAGENTA}){Fore.RESET} Network Analysis Ran for {CAPTURE_DURATION} seconds")

data = pd.read_csv('network_data.csv')
data['src_ip_numeric'] = data['src_ip'].apply(lambda x: int.from_bytes(socket.inet_aton(x), 'big'))
data['dst_ip_numeric'] = data['dst_ip'].apply(lambda x: int.from_bytes(socket.inet_aton(x), 'big'))
data = data.dropna()

x = data[['src_ip_numeric', 'dst_ip_numeric', 'protocol', 'packet_length']]
y = np.ones(x.shape[0])

x_train, x_test = train_test_split(x, test_size=0.2, random_state=42)
model = IsolationForest(n_estimators=100,contamination=0.1)
model.fit(x_train)

joblib.dump(model, 'ids_model.pkl')
print(f"{Fore.MAGENTA}({Fore.CYAN}!{Fore.MAGENTA}){Fore.RESET} Model Training Ran & Completed")