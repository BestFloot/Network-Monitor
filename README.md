# Please Star The Repo & Feel Free To Contribute!

## Overview
This project implements an Intrusion Detection System (IDS) capable of detecting network anomalies, including potential Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks. By analyzing packet data in real-time, this system identifies unusual patterns that may indicate malicious activity and logs relevant information for further analysis.

## Features
 - Anomaly Detection: Uses a trained machine learning model to classify packets as normal or anomalous.
 - DDoS and DoS Detection: Distinguishes between DoS and DDoS attacks based on packet characteristics and source IP behavior.
 - Logging: Records detected anomalies with detailed information such as source and destination IP addresses, protocol, and packet length.
 - Real-time Monitoring: Continuously sniffs packets and updates statistics in real time.

## Requirements
To run IDS, You will need:
 - Python 3.9+
 - Libraries:
  ```
  scapy scikit-learn joblib pandas colorama
  ```

# Usage
Clone the Repo
```
git clone https://github.com/BestFloot/Network-Monitor.git
cd Network-Monitor
```
Install Requirements
```
pip install scapy scikit-learn joblib pandas colorama
```
Train the AI Model
```
python model.py
```
This Will run a Packet Sniffer for the Chosen Time and Train a Model Based On The Traffic It Captures, The Longer it Trains, the Better.

Once the Model is Trained, run the Network Monitor
```
python detect.py
```
This Will now Capture all Packets on the Network and Analyse Them Using The Trained AI Model
