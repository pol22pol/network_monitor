#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Monitor - Backend Application
=====================================
Aplikacja do monitorowania sieci lokalnej.
"""

import os
import sys
import time
import json
import logging
import socket
import sqlite3
import threading
import subprocess
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union, Any

# Próba importu scapy, z obsługą przypadku gdy nie jest dostępne
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Flask dla API i interfejsu web
from flask import Flask, request, jsonify, render_template, abort
from flask_cors import CORS

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('network_monitor.log')
    ]
)
logger = logging.getLogger('network_monitor')

# Konfiguracja aplikacji
CONFIG = {
    'DATABASE_PATH': 'network_monitor.db',
    'NETWORK_SCAN_RANGE': '192.168.1.0/24',  # Zakres skanowania sieci
    'NETWORK_SCAN_INTERVAL_SECONDS': 300,    # 5 minut
    'PING_INTERVAL_SECONDS': 60,             # 1 minuta
    'PORT_SCAN_TIMEOUT': 5,                  # Timeout skanowania portów
    'API_PORT': 5000,                        # Port API Flask
    'API_HOST': '0.0.0.0',                   # Nasłuchuj na wszystkich interfejsach
    'DEBUG': True                            # Tryb debug
}

# Inicjalizacja Flask
app = Flask(__name__)
CORS(app)  # Włączenie Cross-Origin Resource Sharing

# Blokada dla synchronizacji dostępu do bazy danych
db_lock = threading.Lock()

# ===================================================
# Moduł inicjalizacji i konfiguracji bazy danych
# ===================================================

def init_database() -> None:
    """Inicjalizacja bazy danych SQLite."""
    with db_lock, sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
        cursor = conn.cursor()
        
        # Tabela device_info - informacje o urządzeniach
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_info (
            ip TEXT PRIMARY KEY,
            hostname TEXT,
            custom_name TEXT,
            ports TEXT,  -- JSON
            os TEXT,
            mac TEXT,
            vendor TEXT,
            monitoring INTEGER DEFAULT 1,
            last_updated TEXT
        )
        ''')
        
        # Tabela availability - historia dostępności
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS availability (
            ip TEXT,
            timestamp TEXT,
            status INTEGER,
            PRIMARY KEY (ip, timestamp)
        )
        ''')
        
        # Indeks dla szybszego wyszukiwania historii
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_availability_ip_timestamp 
        ON availability (ip, timestamp)
        ''')
        
        conn.commit()
        logger.info("Baza danych zainicjowana pomyślnie")

# ===================================================
# Moduł zbierania i aktualizacji informacji o urządzeniach
# ===================================================

def scan_network() -> List[Dict[str, str]]:
    """
    Skanowanie sieci w poszukiwaniu urządzeń.
    Zwraca listę słowników z informacjami o urządzeniach.
    """
    logger.info(f"Rozpoczynam skanowanie sieci: {CONFIG['NETWORK_SCAN_RANGE']}")
    result = []
    
    try:
        # Najpierw próbujemy użyć scapy (ARP)
        if SCAPY_AVAILABLE:
            logger.info("Używam scapy do skanowania ARP")
            ip_range = CONFIG['NETWORK_SCAN_RANGE']
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            answered, _ = srp(packet, timeout=3, verbose=0)
            
            for sent, received in answered:
                result.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': None  # Vendor will be resolved later
                })
                
        # Jeśli scapy nie jest dostępne, używamy nmap
        else:
            logger.info("Używam nmap jako fallback")
            cmd = ["nmap", "-sn", CONFIG['NETWORK_SCAN_RANGE']]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Bardzo podstawowe parsowanie wyniku nmap
            for line in output.split('\n'):
                if "Nmap scan report for" in line:
                    parts = line.split()
                    ip = parts[-1].strip("()")
                    if ip.replace(".", "").isdigit():  # Proste sprawdzenie czy to IP
                        result.append({
                            'ip': ip,
                            'mac': None,  # MAC będzie uzupełniony później
                            'vendor': None
                        })
    
    except Exception as e:
        logger.error(f"Błąd podczas skanowania sieci: {e}")
    
    logger.info(f"Znaleziono {len(result)} urządzeń w sieci")
    return result

def resolve_hostname(ip: str) -> str:
    """Rozwiązywanie nazwy hosta dla danego IP."""
    try:
        hostname = socket.getfqdn(ip)
        if hostname == ip:  # Jeśli nie udało się rozwiązać
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror):
                hostname = ip
    except Exception as e:
        logger.warning(f"Nie udało się rozwiązać nazwy hosta dla {ip}: {e}")
        hostname = ip
    
    return hostname

def scan_ports(ip: str) -> Dict[str, Any]:
    """
    Skanowanie portów oraz detekcja OS dla danego IP przy użyciu nmap.
    Zwraca słownik z informacjami o portach i systemie operacyjnym.
    """
    logger.info(f"Skanuję porty dla {ip}")
    result = {
        "ports": {},
        "os": "Unknown",
        "vendor": None
    }
    
    try:
        # Skanowanie portów i detekcja OS
        cmd = ["nmap", "-O", "-sV", "--open", ip]
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate(timeout=CONFIG['PORT_SCAN_TIMEOUT'])
        
        # Parsowanie wyniku
        ports = {}
        current_port = None
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            # Wykrywanie portów
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0].split('/')
                    port = port_info[0]
                    protocol = port_info[1]
                    state = parts[1]
                    service = parts[2]
                    
                    ports[port] = {
                        'protocol': protocol,
                        'state': state,
                        'service': service
                    }
                    current_port = port
            
            # Wykrywanie OS
            elif "OS details:" in line:
                result["os"] = line.split("OS details:")[1].strip()
            
            # Wykrywanie vendora
            elif "MAC Address:" in line and "(" in line and ")" in line:
                vendor_info = line.split("(")[1].split(")")[0]
                result["vendor"] = vendor_info
    
    except Exception as e:
        logger.error(f"Błąd podczas skanowania portów dla {ip}: {e}")
    
    result["ports"] = ports
    return result

def update_device_info(devices: List[Dict[str, str]]) -> None:
    """
    Aktualizacja informacji o urządzeniach w bazie danych.
    Dla nowych urządzeń wykonuje skanowanie portów i detekcję OS.
    """
    with db_lock, sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        for device in devices:
            ip = device['ip']
            mac = device.get('mac')
            
            # Sprawdzenie czy urządzenie już istnieje w bazie
            cursor.execute("SELECT * FROM device_info WHERE ip = ?", (ip,))
            existing_device = cursor.fetchone()
            
            now = datetime.now().isoformat()
            
            if existing_device:
                # Aktualizacja istniejącego urządzenia
                updates = {}
                if mac and mac != existing_device['mac']:
                    updates['mac'] = mac
                
                if updates:
                    updates['last_updated'] = now
                    update_fields = ', '.join([f"{k} = ?" for k in updates.keys()])
                    query = f"UPDATE device_info SET {update_fields} WHERE ip = ?"
                    cursor.execute(query, list(updates.values()) + [ip])
                    logger.info(f"Zaktualizowano informacje dla {ip}")
            else:
                # Nowe urządzenie - zbieramy dodatkowe informacje
                hostname = resolve_hostname(ip)
                
                # Skanowanie portów i OS
                port_info = scan_ports(ip)
                
                cursor.execute("""
                INSERT INTO device_info 
                (ip, hostname, ports, os, mac, vendor, monitoring, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """, (
                    ip, 
                    hostname, 
                    json.dumps(port_info.get('ports', {})), 
                    port_info.get('os', 'Unknown'),
                    mac,
                    port_info.get('vendor'),
                    now
                ))
                logger.info(f"Dodano nowe urządzenie: {ip}")
        
        conn.commit()

def network_scanner_thread() -> None:
    """Wątek regularnie skanujący sieć."""
    while True:
        try:
            devices = scan_network()
            if devices:
                update_device_info(devices)
        except Exception as e:
            logger.error(f"Błąd w wątku skanowania sieci: {e}")
        
        # Czekaj określony czas przed następnym skanowaniem
        time.sleep(CONFIG['NETWORK_SCAN_INTERVAL_SECONDS'])

# ===================================================
# Moduł monitorowania dostępności (Pingowanie)
# ===================================================

def ping_device(ip: str) -> bool:
    """
    Pingowanie urządzenia. Zwraca True jeśli urządzenie odpowiada.
    Kompatybilne z Windows i Unix.
    """
    param = '-n' if sys.platform.lower() == 'win32' else '-c'
    command = ['ping', param, '1', ip]
    
    try:
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception as e:
        logger.warning(f"Błąd podczas pingowania {ip}: {e}")
        return False

def record_device_availability(ip: str, status: bool) -> None:
    """Zapisuje status dostępności urządzenia do bazy."""
    try:
        with db_lock, sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
            cursor = conn.cursor()
            
            # Najpierw sprawdzamy, czy urządzenie istnieje
            cursor.execute("SELECT 1 FROM device_info WHERE ip = ?", (ip,))
            if cursor.fetchone() is None:
                logger.warning(f"Próba zapisania dostępności dla niezarejestrowanego urządzenia: {ip}")
                return
            
            now = datetime.now().isoformat()
            cursor.execute(
                "INSERT INTO availability (ip, timestamp, status) VALUES (?, ?, ?)",
                (ip, now, 1 if status else 0)
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Błąd podczas zapisywania statusu dla {ip}: {e}")

def pinger_thread() -> None:
    """Wątek regularnie sprawdzający dostępność urządzeń."""
    while True:
        try:
            with db_lock, sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                # Pobieramy tylko urządzenia z włączonym monitorowaniem
                cursor.execute("SELECT ip FROM device_info WHERE monitoring = 1")
                devices = [row['ip'] for row in cursor.fetchall()]
            
            # Pingujemy każde urządzenie i zapisujemy wynik
            for ip in devices:
                status = ping_device(ip)
                record_device_availability(ip, status)
        
        except Exception as e:
            logger.error(f"Błąd w wątku pingera: {e}")
        
        # Czekaj określony czas przed następnym cyklem pingowania
        time.sleep(CONFIG['PING_INTERVAL_SECONDS'])

# ===================================================
# Moduł agregacji i prezentacji danych
# ===================================================

def get_latest_device_status_with_info() -> List[Dict[str, Any]]:
    """
    Pobiera aktualny status wszystkich urządzeń wraz z dodatkowymi informacjami.
    """
    with db_lock, sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Pobieramy dane urządzeń i najnowsze statusy dostępności
        cursor.execute("""
        SELECT d.*, 
               a.status AS current_status,
               a.timestamp AS status_timestamp
        FROM device_info d
        LEFT JOIN (
            SELECT ip, status, timestamp
            FROM availability
            WHERE (ip, timestamp) IN (
                SELECT ip, MAX(timestamp)
                FROM availability
                GROUP BY ip
            )
        ) a ON d.ip = a.ip
        """)
        
        devices = []
        for row in cursor.fetchall():
            device = dict(row)
            device['ports'] = json.loads(device['ports']) if device['ports'] else {}
            
            # Pobieranie dodatkowych danych historycznych
            ip = device['ip']
            
            # Data pierwszego pojawienia się urządzenia
            cursor.execute("SELECT MIN(timestamp) FROM availability WHERE ip = ?", (ip,))
            first_seen = cursor.fetchone()[0]
            device['first_seen'] = first_seen
            
            # Data ostatniej dostępności
            cursor.execute("""
            SELECT MAX(timestamp) FROM availability 
            WHERE ip = ? AND status = 1
            """, (ip,))
            last_online = cursor.fetchone()[0]
            device['last_online'] = last_online
            
            # Liczba okresów niedostępności w ciągu ostatnich 24h
            one_day_ago = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute("""
            SELECT COUNT(*) FROM (
                SELECT status, timestamp
                FROM availability
                WHERE ip = ? AND timestamp >= ?
                ORDER BY timestamp
            ) WHERE status = 0
            """, (ip, one_day_ago))
            downtime_count = cursor.fetchone()[0]
            device['downtime_count_24h'] = downtime_count
            
            # Formatowanie danych dla interfejsu
            device['status_color'] = 'green' if device.get('current_status', 0) == 1 else 'red'
            
            # Dodanie warunkowych linków HTTP/HTTPS w zależności od dostępności portów
            http_links = []
            if '80' in device['ports']:
                http_links.append(f"http://{ip}")
            if '443' in device['ports']:
                http_links.append(f"https://{ip}")
            device['http_links'] = http_links
            
            devices.append(device)
        
        return devices

def get_device_availability_history(ip: str, time_range: str = None) -> List[Dict[str, Any]]:
    """
    Pobiera historię dostępności dla danego urządzenia.
    
    Args:
        ip: Adres IP urządzenia
        time_range: Opcjonalny zakres czasowy (np. '24h', '7d', '-1d')
    
    Returns:
        Lista słowników z historią dostępności
    """
    with db_lock, sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Ustalanie zakresu czasowego
        time_filter = ""
        params = [ip]
        
        if time_range:
            now = datetime.now()
            
            if time_range.endswith('h'):
                hours = int(time_range[:-1])
                start_time = (now - timedelta(hours=hours)).isoformat()
            elif time_range.endswith('d'):
                days = int(time_range[:-1])
                start_time = (now - timedelta(days=days)).isoformat()
            else:
                # Domyślnie 24 godziny
                start_time = (now - timedelta(hours=24)).isoformat()
            
            time_filter = "AND timestamp >= ?"
            params.append(start_time)
        
        query = f"""
        SELECT timestamp, status
        FROM availability
        WHERE ip = ? {time_filter}
        ORDER BY timestamp
        """
        
        cursor.execute(query, params)
        history = [dict(row) for row in cursor.fetchall()]
        
        return history

# ===================================================
# Moduł API i interfejs webowy
# ===================================================

@app.route('/')
def index():
    """Strona główna (dashboard)."""
    return render_template('index.html')

@app.route('/api/devices')
def api_devices():
    """API - pobieranie listy urządzeń z najnowszymi statusami."""
    devices = get_latest_device_status_with_info()
    return jsonify(devices)

@app.route('/api/device/<ip>')
def api_device_info(ip):
    """API - pobieranie szczegółowych informacji o urządzeniu."""
    with db_lock, sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM device_info WHERE ip = ?", (ip,))
        device = cursor.fetchone()
        
        if device:
            result = dict(device)
            result['ports'] = json.loads(result['ports']) if result['ports'] else {}
            return jsonify(result)
        else:
            return jsonify({"error": "Device not found"}), 404

@app.route('/api/device/<ip>/availability')
def api_device_availability(ip):
    """API - pobieranie historii dostępności urządzenia."""
    time_range = request.args.get('range')
    history = get_device_availability_history(ip, time_range)
    return jsonify(history)

@app.route('/api/device/<ip>/set_name', methods=['POST'])
def api_set_device_name(ip):
    """API - ustawianie własnej nazwy urządzenia."""
    data = request.json
    new_name = data.get('name')
    
    if not new_name:
        return jsonify({"error": "Missing name parameter"}), 400
    
    with db_lock, sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
        cursor = conn.cursor()
        
        cursor.execute("UPDATE device_info SET custom_name = ? WHERE ip = ?", (new_name, ip))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({"error": "Device not found"}), 404
        
        return jsonify({"success": True, "message": "Device name updated"})

@app.route('/api/device/<ip>/toggle_monitoring', methods=['POST'])
def api_toggle_monitoring(ip):
    """API - przełączanie statusu monitorowania urządzenia."""
    with db_lock, sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
        cursor = conn.cursor()
        
        # Najpierw sprawdzamy aktualny status
        cursor.execute("SELECT monitoring FROM device_info WHERE ip = ?", (ip,))
        result = cursor.fetchone()
        
        if not result:
            return jsonify({"error": "Device not found"}), 404
        
        current_status = result[0]
        new_status = 0 if current_status == 1 else 1
        
        cursor.execute("UPDATE device_info SET monitoring = ? WHERE ip = ?", (new_status, ip))
        conn.commit()
        
        return jsonify({
            "success": True, 
            "message": f"Monitoring {'enabled' if new_status == 1 else 'disabled'}"
        })

@app.route('/api/device/<ip>/rescan_ports', methods=['POST'])
def api_rescan_ports(ip):
    """API - ponowne skanowanie portów, systemu operacyjnego oraz producenta urządzenia."""
    try:
        port_info = scan_ports(ip)
        
        with db_lock, sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
            UPDATE device_info 
            SET ports = ?, os = ?, vendor = ?, last_updated = ?
            WHERE ip = ?
            """, (
                json.dumps(port_info['ports']),
                port_info['os'],
                port_info['vendor'],
                datetime.now().isoformat(),
                ip
            ))
            conn.commit()
            
            if cursor.rowcount == 0:
                return jsonify({"error": "Device not found"}), 404
            
            return jsonify({
                "success": True, 
                "message": "Ports and OS information updated",
                "data": port_info
            })
    
    except Exception as e:
        logger.error(f"Błąd podczas ponownego skanowania portów dla {ip}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/device/<ip>', methods=['DELETE'])
def api_delete_device(ip):
    """API - usuwanie urządzenia z bazy danych."""
    with db_lock, sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
        cursor = conn.cursor()
        
        # Usuwanie z tabeli device_info
        cursor.execute("DELETE FROM device_info WHERE ip = ?", (ip,))
        device_deleted = cursor.rowcount > 0
        
        # Usuwanie z tabeli availability
        cursor.execute("DELETE FROM availability WHERE ip = ?", (ip,))
        
        conn.commit()
        
        if device_deleted:
            return jsonify({"success": True, "message": "Device deleted"})
        else:
            return jsonify({"error": "Device not found"}), 404

# ===================================================
# Funkcja główna
# ===================================================

def main():
    """Funkcja główna aplikacji."""
    # Inicjalizacja bazy danych
    init_database()
    
    # Uruchomienie wątków w tle
    threading.Thread(target=network_scanner_thread, daemon=True).start()
    threading.Thread(target=pinger_thread, daemon=True).start()
    
    # Uruchomienie serwera Flask
    logger.info(f"Uruchamiam serwer API na {CONFIG['API_HOST']}:{CONFIG['API_PORT']}")
    app.run(
        host=CONFIG['API_HOST'],
        port=CONFIG['API_PORT'],
        debug=CONFIG['DEBUG'],
        use_reloader=False  # Wyłączamy reloader, aby nie uruchamiać podwójnych wątków w trybie debug
    )

if __name__ == "__main__":
    main()
