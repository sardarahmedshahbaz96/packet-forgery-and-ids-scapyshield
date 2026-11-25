# ==============================================================================
# app.py - Main GUI Cyber Security Control Dashboard Application
# ==============================================================================

import os
import sys
import os.path

# 🛡️ SYSTEM BYPASS MONKEYPATCH
# Forces Scapy to use your project directory for data and caching profiles.
# This prevents Windows User Profile PermissionErrors (WinError 5) natively.
def bypass_expanduser(path="~"):
    return os.path.dirname(os.path.abspath(__file__))

os.path.expanduser = bypass_expanduser
os.environ["SCAPY_HOME"] = os.path.dirname(os.path.abspath(__file__))

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time

# Central Matrix Imports
import config

# Import teammate panels
from rules_panel import DetectionRulesPanel
from analytics_panel import AnalyticsPanel

# Import teammate backend engines & execution entry point
from sniffer import start_sniffer   


class ScapyShieldApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ScapyShield // Cyber Security Dashboard")
        self.root.geometry("1100x650")
        self.root.configure(bg=config.BG_MAIN)
        
        # Configure Styles for standard ttk widgets using central configurations
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.style.configure('.', background=config.BG_SURFACE, foreground=config.TEXT_PRIMARY)

        # Track navigation elements and state
        self.nav_buttons = {}
        self.current_view = "console"
        
        # Build layout architecture
        self.setup_layout()

        # --- START BACKGROUND LIVE SNIFFER WORKER ---
        self.start_monitoring()

    def setup_layout(self):
        # 1. SIDEBAR NAVIGATION PANELS
        sidebar = tk.Frame(self.root, bg=config.BG_SURFACE, width=240, padx=15, pady=20)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Logo Area
        logo_label = tk.Label(
            sidebar, 
            text="🛡️ SCAPYSHIELD", 
            font=(config.FONT_FAMILY, 14, "bold"), 
            fg=config.NEON_CYAN, 
            bg=config.BG_SURFACE
        )
        logo_label.pack(anchor="w", pady=(0, 25))

        # Nav Links Mapping to Panel Methods
        nav_items = [
            ("📺 Console", "console"), 
            ("🧠 Detector Rules", "rules"), 
            ("📊 Analytics", "analytics")
        ]
        
        for item_text, target_view in nav_items:
            is_initial_active = (target_view == "console")
            fg_color = config.TEXT_PRIMARY if is_initial_active else config.TEXT_MUTED
            bg_color = config.BG_CONSOLE if is_initial_active else config.BG_SURFACE
            border_color = config.NEON_CYAN if is_initial_active else config.BORDER_COLOR
            
            # High-tactility solid outline button style instead of flat label
            btn = tk.Button(
                sidebar, 
                text=item_text, 
                font=(config.FONT_FAMILY, 10, "bold"), 
                fg=fg_color, 
                bg=bg_color,
                activebackground=config.BG_CONSOLE,
                activeforeground=config.NEON_CYAN,
                bd=1, 
                relief="solid",
                highlightthickness=0,
                highlightbackground=border_color,
                anchor="w",
                padx=15,
                pady=4,
                cursor="hand2"
            )
            btn.pack(fill="x", pady=8, ipady=4)
            
            # Bind dynamic hover animation behavior
            btn.bind("<Enter>", lambda event, b=btn, v=target_view: self.on_nav_hover(b, v))
            btn.bind("<Leave>", lambda event, b=btn, v=target_view: self.on_nav_leave(b, v))
            btn.bind("<Button-1>", lambda event, view=target_view: self.switch_view(view))
            
            self.nav_buttons[target_view] = btn

        # System Status Footer
        status_frame = tk.Frame(sidebar, bg=config.BG_SURFACE)
        status_frame.pack(side="bottom", anchor="w", pady=10)
        self.status_dot = tk.Label(status_frame, text="●", fg=config.NEON_GREEN, bg=config.BG_SURFACE, font=("Arial", 12))
        self.status_dot.pack(side="left")
        self.status_txt = tk.Label(
            status_frame, 
            text=" SYSTEM ACTIVE", 
            fg=config.NEON_GREEN, 
            bg=config.BG_SURFACE, 
            font=(config.FONT_FAMILY, 9, "bold")
        )
        self.status_txt.pack(side="left")

        # 2. MAIN CONTAINER ARCHITECTURE
        self.main_content = tk.Frame(self.root, bg=config.BG_MAIN, padx=20, pady=20)
        self.main_content.pack(side="right", fill="both", expand=True)

        # Header Ribbon
        header_frame = tk.Frame(self.main_content, bg=config.BG_MAIN)
        header_frame.pack(fill="x", pady=(0, 15))
        
        title_lbl = tk.Label(
            header_frame, 
            text="SECURITY CONTROL CENTER", 
            font=(config.FONT_FAMILY, 12, "bold"), 
            fg=config.TEXT_PRIMARY, 
            bg=config.BG_MAIN
        )
        title_lbl.pack(side="left")
        
        iface_lbl = tk.Label(
            header_frame, 
            text="IFACE: Default", 
            font=(config.FONT_FAMILY, 9, "bold"), 
            fg=config.NEON_CYAN, 
            bg=config.BG_MAIN, 
            bd=1, 
            relief="solid", 
            padx=8, 
            pady=2
        )
        iface_lbl.pack(side="right")

        # 3. METRICS UPPER DISPLAY ROW (Glowing Borders)
        metrics_frame = tk.Frame(self.main_content, bg=config.BG_MAIN)
        metrics_frame.pack(fill="x", pady=(0, 20))
        metrics_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="equal")

        self.create_metric_card(metrics_frame, 0, "Packets Sniffed", "142,839", config.NEON_CYAN)
        self.create_metric_card(metrics_frame, 1, "SYN Scans Detected", "42", config.NEON_YELLOW)
        self.create_metric_card(metrics_frame, 2, "Spoofed Responses", "42", config.NEON_MAGENTA)

        # 4. VIEWPORT CONTEXT FRAME (Dynamic Display Area)
        self.viewport_frame = tk.Frame(self.main_content, bg=config.BG_MAIN)
        self.viewport_frame.pack(fill="both", expand=True)

        # Default View initialization
        self.load_console_panel()

    def on_nav_hover(self, btn, view_name):
        """Highlights the navbar item under the mouse cursor"""
        if self.current_view != view_name:
            btn.config(fg=config.NEON_CYAN, bg=config.BG_CONSOLE)

    def on_nav_leave(self, btn, view_name):
        """Reverts styling when the mouse leaves the navigation element"""
        if self.current_view != view_name:
            btn.config(fg=config.TEXT_MUTED, bg=config.BG_SURFACE)

    def clear_viewport(self):
        """Wipes the dynamic content window before switching views"""
        for widget in self.viewport_frame.winfo_children():
            widget.destroy()

    def switch_view(self, view_name):
        """Handles changing button layouts and swapping panel views"""
        self.current_view = view_name
        
        # Update styling profiles for active vs inactive tabs
        for name, btn in self.nav_buttons.items():
            if name == view_name:
                btn.config(fg=config.TEXT_PRIMARY, bg=config.BG_CONSOLE, highlightbackground=config.NEON_CYAN)
            else:
                btn.config(fg=config.TEXT_MUTED, bg=config.BG_SURFACE, highlightbackground=config.BORDER_COLOR)

        self.clear_viewport()
        
        if view_name == "console":
            self.load_console_panel()
        elif view_name == "rules":
            self.current_panel = DetectionRulesPanel(self.viewport_frame)
            self.current_panel.pack(fill="both", expand=True)
        elif view_name == "analytics":
            self.current_panel = AnalyticsPanel(self.viewport_frame)
            self.current_panel.pack(fill="both", expand=True)

    def load_console_panel(self):
        """Builds your default main live console view layout"""
        self.viewport_frame.grid_columnconfigure(0, weight=2)
        self.viewport_frame.grid_columnconfigure(1, weight=1)
        self.viewport_frame.grid_rowconfigure(0, weight=1)

        # Live Terminal Panel Console Frame
        console_panel = tk.Frame(self.viewport_frame, bg=config.BG_SURFACE, bd=1, relief="solid", highlightbackground=config.TEXT_MUTED)
        console_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        console_hdr = tk.Frame(console_panel, bg=config.BG_SURFACE, padx=10, pady=8)
        console_hdr.pack(fill="x")
        
        tk.Label(
            console_hdr, 
            text="💻 Live Sniffer Console", 
            font=(config.FONT_FAMILY, 10, "bold"), 
            fg=config.NEON_CYAN, 
            bg=config.BG_SURFACE
        ).pack(side="left")
        
        self.sniff_status_lbl = tk.Label(
            console_hdr, 
            text="● Sniffing...", 
            font=(config.FONT_FAMILY, 9, "bold"), 
            fg=config.NEON_GREEN, 
            bg=config.BG_SURFACE
        )
        self.sniff_status_lbl.pack(side="right")

        self.console_text = scrolledtext.ScrolledText(
            console_panel, 
            bg=config.BG_CONSOLE, 
            fg=config.TEXT_MUTED, 
            insertbackground=config.NEON_CYAN, 
            selectbackground=config.BG_SURFACE,
            selectforeground=config.TEXT_PRIMARY,
            font=(config.FONT_FAMILY, config.FONT_SIZE_CONSOLE), 
            bd=0, 
            padx=10, 
            pady=10
        )
        self.console_text.pack(fill="both", expand=True)
        
        # Color logging definitions connected directly to global accents Matrix
        self.console_text.tag_config('warning', foreground=config.NEON_YELLOW)
        self.console_text.tag_config('success', foreground=config.NEON_GREEN)
        self.console_text.tag_config('forger', foreground=config.NEON_CYAN)
        self.console_text.tag_config('error', foreground=config.NEON_MAGENTA)

        self.console_text.configure(state="normal")
        self.console_text.insert(tk.END, "[*] GUI Console Thread Attached Successfully.\n")
        self.console_text.configure(state="disabled")

        # Module Architecture Sidebar Box
        arch_panel = tk.Frame(self.viewport_frame, bg=config.BG_SURFACE, bd=1, relief="solid", highlightbackground=config.BORDER_COLOR)
        arch_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        arch_hdr = tk.Frame(arch_panel, bg=config.BG_SURFACE, padx=10, pady=8)
        arch_hdr.pack(fill="x")
        tk.Label(
            arch_hdr, 
            text="⚙️ Module Architecture", 
            font=(config.FONT_FAMILY, 10, "bold"), 
            fg=config.NEON_MAGENTA, 
            bg=config.BG_SURFACE
        ).pack(side="left")

        # Status displays
        self.create_component_item(arch_panel, "sniffer.py", "Captures raw TCP packets", "RUNNING", config.NEON_CYAN)
        self.create_component_item(arch_panel, "detector.py", "Parses raw packet data", "ACTIVE", config.NEON_YELLOW)
        self.create_component_item(arch_panel, "forger.py", "Assembles & injects packets", "STANDBY", config.NEON_MAGENTA)

    # --- MULTI-THREADING BACKGROUND ENGINE ---
    def start_monitoring(self):
        """Spins up the network engine capture loop on an unblocked background thread"""
        sniffer_worker = threading.Thread(target=self.run_sniffer_loop, daemon=True)
        sniffer_worker.start()

    def run_sniffer_loop(self):
        """Launches your teammate's actual scapy sniffer loop using our safe UI logging channel"""
        try:
            start_sniffer(interface_name=None, ui_callback=self.log_packet_safe)
        except Exception as e:
            self.log_packet_safe(f"[-] Critical Sniffer Thread Error: {str(e)}", tag="warning")

    def log_packet_safe(self, message, tag=None):
        """Thread-safe interface function to drop strings directly into console window"""
        if hasattr(self, 'console_text') and self.console_text.winfo_exists():
            self.console_text.config(state="normal")
            if tag:
                self.console_text.insert(tk.END, f"{message}\n", tag)
            else:
                self.console_text.insert(tk.END, f"{message}\n")
            self.console_text.see(tk.END)
            self.console_text.config(state="disabled")

    # --- HELPER UI COMPONENT GENERATORS ---
    def create_metric_card(self, parent, col, title, value, color):
        # Increased highlightthickness to create a premium glowing neon border effect
        card = tk.Frame(parent, bg=config.BG_SURFACE, bd=0, highlightthickness=2, highlightbackground=color)
        card.grid(row=0, column=col, sticky="nsew", padx=12, pady=8)
        
        lbl_title = tk.Label(
            card, 
            text=title.upper(), 
            font=(config.FONT_FAMILY, 8, "bold"), 
            fg=config.TEXT_MUTED, 
            bg=config.BG_SURFACE
        )
        lbl_title.pack(anchor="w", padx=15, pady=(12, 2))
        
        lbl_val = tk.Label(
            card, 
            text=value, 
            font=(config.FONT_FAMILY, 20, "bold"), 
            fg=color, 
            bg=config.BG_SURFACE
        )
        lbl_val.pack(anchor="w", padx=15, pady=(0, 12))

    def create_component_item(self, parent, filename, desc, status, accent_color):
        item_frame = tk.Frame(parent, bg=config.BG_MAIN, bd=1, relief="flat", highlightthickness=1, highlightbackground=config.BORDER_COLOR)
        item_frame.pack(fill="x", padx=12, pady=8, ipady=4)

        text_container = tk.Frame(item_frame, bg=config.BG_MAIN)
        text_container.pack(side="left", padx=8)
        
        tk.Label(text_container, text=filename, font=(config.FONT_FAMILY, 9, "bold"), fg=config.TEXT_PRIMARY, bg=config.BG_MAIN).pack(anchor="w")
        tk.Label(text_container, text=desc, font=(config.FONT_FAMILY, 7), fg=config.TEXT_MUTED, bg=config.BG_MAIN).pack(anchor="w")

        badge = tk.Label(
            item_frame, 
            text=status, 
            font=(config.FONT_FAMILY, 7, "bold"), 
            fg=accent_color, 
            bg=config.BG_SURFACE, 
            bd=1, 
            relief="solid", 
            padx=4
        )
        badge.pack(side="right", padx=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = ScapyShieldApp(root)
    root.mainloop()