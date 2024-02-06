import time
import re
import subprocess
import socket
import threading
import os
import logging

class Tusk:
    def __init__(self, ip: str):
        self.ip = ip
        self.open_ports = {}
        self.print_lock = threading.Lock() # this is a print lock to ensure synchronized printing across threads being used
        
    
    def ip_range(self):
        ip_arr = [] # Empty array to store strings of ip addresses
        rev_ip = self.ip[::-1] 
        # ^ gets the reverse of the contructor ip to obtain the last octet: an octet are the values separated by periods.
        per = "." # string of period to find it later on
        max = int(input("Highest octet number: "))

        for dot in rev_ip:
            if per == dot:
                pos = rev_ip.index(dot)
                last_octet = rev_ip[:pos]
                break

        current_octet = 0
        while True:
            if current_octet == max:
                break
            current_octet += 1
            num = str(current_octet)
            rev_num = num[::-1]
            # ^ gets the reverse of the num, because we will reverse it again when storing in the array
            modified_ip = rev_ip.replace(last_octet, rev_num, 1) # replaces the last octet with every number until max
            ip_arr.append(modified_ip[::-1])
        return ip_arr
    
    def mac(self, ip):
        try:
            arp = subprocess.Popen(["arp", "-a", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = arp.communicate()
            decoded_stdout = stdout.decode('utf-8')

            mac_address_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", decoded_stdout)
            if mac_address_match:
                return mac_address_match.group()
            else:
                return "MAC address not found"
        except subprocess.CalledProcessError as e:
            logging.warning(f"Error while retrieving MAC address for {ip}: {e}")
            return "Error"
    
    def tusk_scan(self):
        ip_addresses = self.ip_range()
        print("Sniffing...")
        for ip in ip_addresses:
            try:
                output = subprocess.Popen(["ping", "-n", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = output.communicate()
                stdout_str = stdout.decode('utf-8')

                search = re.search(f"Reply from {ip}: bytes=", stdout_str)
                mac_addresses = self.mac(ip)
                
                # Check if the port scan for this IP has already been performed for every successfully pinged ip
                if search:
                    # if IP is up, perform port scan
                    if ip not in self.open_ports:
                        ports = self.port_scan(ip, 1, 500)
                        self.open_ports[ip] = ports
                    else:
                        ports = self.open_ports[ip]
                        if len(ports) < 1:
                            ports = "No open ports"
                    logging.info(f"IP: {ip}. MAC: {mac_addresses}. Open-Ports: {ports}")
                else:
                    logging.info(f"{ip} is down")
                
            except subprocess.CalledProcessError:
                logging.warning(f"{ip} is down.")
            except subprocess.TimeoutExpired:
                logging.warning(f"{ip} is down (timeout).")


    def connect(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((ip, port))
            with self.print_lock:
                self.open_ports[ip].append(port)
        except Exception as e:
            pass
        finally:
            sock.close()

    def port_scan(self, ip, start_port, end_port):
        self.open_ports[ip] = []  # Initialize the list for this IP
        threads = []
        threads.clear()

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.connect, args=(ip, port,))
            thread.daemon = True
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        return self.open_ports[ip]
