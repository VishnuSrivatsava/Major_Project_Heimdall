# cve_sender.py
import tkinter as tk
from tkinter import ttk, messagebox
import socket
import json

class CVESender(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CVE Data Sender")
        self.geometry("500x700")
        
        # Create main frame with padding
        self.frame = ttk.Frame(self, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Sample data
        self.sample_data = {
            'cve_id': 'CVE-2023-1234',
            'vendor_project': 'Apache',
            'product': 'Struts',
            'threat_name': 'SQL Injection',
            'date_added': '2023-12-01',
            'short_description': 'SQL Injection vulnerability in login form',
            'required_action': 'Update to latest version',
            'due_date': '2023-12-15',
            'pub_date': '2023-12-01',
            'cvss': '7.5',
            'cwe': 'CWE-89',
            'type': 'Injection',
            'complexity': 'Medium'
        }
        
        # Create entry fields
        self.entries = {}
        row = 0
        for key, value in self.sample_data.items():
            ttk.Label(self.frame, text=key.replace('_', ' ').title()).grid(row=row, column=0, sticky=tk.W)
            entry = ttk.Entry(self.frame, width=40)
            entry.insert(0, value)  # Pre-fill with sample data
            entry.grid(row=row, column=1, padx=5, pady=2)
            self.entries[key] = entry
            row += 1
        
        # Add send button
        ttk.Button(self.frame, text="Send Data", command=self.send_data).grid(row=row, column=0, columnspan=2, pady=20)
        
        # Status label
        self.status = ttk.Label(self.frame, text="")
        self.status.grid(row=row+1, column=0, columnspan=2)

    def send_data(self):
        try:
            # Collect data from entries
            data = {key: entry.get() for key, entry in self.entries.items()}
            
            # Connect to localhost
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(('localhost', 9999))
                
                # Send data
                message = json.dumps(data)
                sock.sendall(message.encode())
                
                # Get response
                response = sock.recv(1024).decode()
                
                self.status.config(text=f"Success: {response}", foreground="green")
                messagebox.showinfo("Success", "Data sent successfully!")
                
        except Exception as e:
            self.status.config(text=f"Error: {str(e)}", foreground="red")
            messagebox.showerror("Error", f"Failed to send data: {str(e)}")

if __name__ == "__main__":
    app = CVESender()
    app.mainloop()