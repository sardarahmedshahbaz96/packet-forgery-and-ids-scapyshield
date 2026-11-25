# ==============================================================================
# sniffer.py - Network Packet Capture Engine for ScapyShield
# ==============================================================================

import os
import sys

# 🛡️ SYSTEM ISOLATION BYPASS: Force Scapy to use a local cache directory
# This natively prevents Windows User Profile PermissionErrors [WinError 5]
os.environ["SCAPY_HOME"] = os.path.dirname(os.path.abspath(__file__))

import logging
import argparse
import traceback
from scapy.all import sniff, IP, TCP, Ether
from detector import Detector, PacketInfo

logging.basicConfig(level=logging.INFO, format='%(message)s')

detector_engine = Detector()  # Global reference for UI routing
ui_logger = None              # Shared callback handler for live logging


def packet_callback(packet):
    """
    Analyzes every captured raw TCP packet in real-time, filters for suspicious
    stealth SYN scanning profiles, and dispatches data to the parsing engine.
    """
    try:
        # 1. Structural layer verification
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        # Convert flags to string to prevent Scapy object type mismatches
        tcp_flags = str(packet[TCP].flags)
        
        # 🛑 ROBUST LOOP BREAK: Must contain SYN ("S") and MUST NOT contain ACK ("A")
        # This catches all Nmap scan variants while perfectly ignoring our own replies!
        if "S" not in tcp_flags or "A" in tcp_flags:
            return

        # 2. Log incoming scan event anomalies
        msg = f"[!] SCAN DETECTED: Host {packet[IP].src} is probing Port {packet[TCP].dport}"
        logging.warning(msg)
        if ui_logger:
            ui_logger(msg, tag="warning")
            
        # 3. Secure hardware layer addresses safely
        src_mac = packet[Ether].src if packet.haslayer(Ether) else "00:00:00:00:00:00"
        dst_mac = packet[Ether].dst if packet.haslayer(Ether) else "00:00:00:00:00:00"
        
        # 4. Extract binding system network device info
        current_iface = getattr(packet, 'sniffed_on', "None")
            
        # 5. Pack captured packet telemetry structurally
        scanned_packet_data = PacketInfo(
            source_ip=packet[IP].src,
            source_port=packet[TCP].sport,
            destination_ip=packet[IP].dst,
            destination_port=packet[TCP].dport,
            sequence_number=packet[TCP].seq,
            src_mac=src_mac,
            dst_mac=dst_mac,
            iface=str(current_iface)
        )
        
        # 6. Pass data payload to detector analysis pipeline
        detector_engine.process_packet(scanned_packet_data, ui_callback=ui_logger)

    except Exception as e:
        # 🚨 DIAGNOSTIC CATCHER: Print the exact crash reason directly to your UI console!
        error_msg = f"[-] Sniffer Thread Crash: {e}\n{traceback.format_exc()}"
        print(error_msg)
        if ui_logger:
            ui_logger(f"[-] CRITICAL ERROR: {e}", tag="error")


def start_sniffer(interface_name, ui_callback=None):
    """
    Initializes and boots Scapy's raw kernel wire interception loop on 
    an unblocked background thread channel.
    """
    global ui_logger
    ui_logger = ui_callback
    
    logging.info(f"[*] Starting ScapyShield sniffer on interface: {interface_name if interface_name else 'Default'}")
    
    sniff(
        iface=interface_name,
        filter="tcp",
        prn=packet_callback,
        store=0
    )