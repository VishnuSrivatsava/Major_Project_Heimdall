# cve_server.py
import socket
import json
from django.utils import timezone
from Remote_User.models import CapturedThreat  # Ensure this import is correct

class CVEServer:
    def __init__(self, host='localhost', port=9999):
        self.host = host
        self.port = port
        self.running = False
        
    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        print(f"Server listening on {self.host}:{self.port}")
        
        while self.running:
            try:
                conn, addr = self.sock.accept()
                print(f"Connection from {addr}")
                self.handle_client(conn, addr)
            except Exception as e:
                print(f"Error accepting connection: {e}")
                
    def handle_client(self, conn, addr):
        try:
            data = conn.recv(4096).decode()
            cve_data = json.loads(data)
            
            # Save to database
            CapturedThreat.objects.create(
                cve_id=cve_data['cve_id'],
                vendor_project=cve_data['vendor_project'],
                product=cve_data['product'],
                threat_name=cve_data['threat_name'],
                date_added=cve_data['date_added'],
                short_description=cve_data['short_description'],
                required_action=cve_data['required_action'],
                due_date=cve_data['due_date'],
                pub_date=cve_data['pub_date'],
                cvss=float(cve_data['cvss']),
                cwe=cve_data['cwe'],
                type=cve_data['type'],
                complexity=cve_data['complexity'],
                capture_time=timezone.now()
            )
            
            conn.sendall("Data received and saved successfully".encode())
            
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
            conn.sendall(f"Error: {str(e)}".encode())
        finally:
            conn.close()