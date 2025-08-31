#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from pathlib import Path
import datetime


class ReorgApp:
    def __init__(self):
        self.root = tk.Tk()
        self.setup_window()
        self.setup_styles()
        self.create_widgets()
        
        self.target_folder = ""
        
    def setup_window(self):
        self.root.title("ReORG - File Organization Tool")
        self.root.geometry("650x550")
        self.root.resizable(True, True)
        self.root.configure(bg="#f8f9fa")
        
        # Center the window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (650 // 2)
        y = (self.root.winfo_screenheight() // 2) - (550 // 2)
        self.root.geometry(f"650x550+{x}+{y}")
        
    def setup_styles(self):
        style = ttk.Style()
        
        # Configure modern color scheme
        style.configure("Card.TFrame", 
                       background="#ffffff", 
                       relief="flat", 
                       borderwidth=1)
        
        style.configure("Title.TLabel", 
                       background="#ffffff",
                       foreground="#2c3e50",
                       font=("Segoe UI", 18, "bold"))
        
        style.configure("Heading.TLabel", 
                       background="#ffffff",
                       foreground="#34495e",
                       font=("Segoe UI", 10, "bold"))
        
        style.configure("Modern.TButton", 
                       padding=(12, 8),
                       font=("Segoe UI", 9))
        
        style.configure("Accent.TButton", 
                       padding=(16, 10),
                       font=("Segoe UI", 10, "bold"))
        
        style.configure("Modern.TCheckbutton",
                       background="#ffffff",
                       foreground="#2c3e50",
                       font=("Segoe UI", 9),
                       focuscolor="none")
        
        style.configure("Modern.TEntry",
                       padding=(8, 6),
                       font=("Segoe UI", 9))
        
        style.configure("Modern.Horizontal.TProgressbar",
                       background="#3498db",
                       troughcolor="#ecf0f1",
                       borderwidth=0,
                       lightcolor="#3498db",
                       darkcolor="#3498db")
        
    def create_widgets(self):
        # Main container with padding
        main_frame = tk.Frame(self.root, bg="#f8f9fa")
        main_frame.pack(fill="both", expand=True, padx=24, pady=24)
        
        # Header card
        header_card = ttk.Frame(main_frame, style="Card.TFrame", padding="24")
        header_card.pack(fill="x", pady=(0, 20))
        
        title_label = ttk.Label(header_card, text="ReORG File Organizer", 
                               style="Title.TLabel")
        title_label.pack()
        
        subtitle_label = ttk.Label(header_card, 
                                  text="Intelligent file organization powered by AI",
                                  background="#ffffff",
                                  foreground="#7f8c8d",
                                  font=("Segoe UI", 9))
        subtitle_label.pack(pady=(5, 0))
        
        # Folder selection card
        folder_card = ttk.Frame(main_frame, style="Card.TFrame", padding="20")
        folder_card.pack(fill="x", pady=(0, 16))
        
        folder_header = ttk.Label(folder_card, text="Target Folder", style="Heading.TLabel")
        folder_header.pack(anchor="w", pady=(0, 12))
        
        folder_input_frame = tk.Frame(folder_card, bg="#ffffff")
        folder_input_frame.pack(fill="x")
        
        self.folder_var = tk.StringVar()
        self.folder_entry = ttk.Entry(folder_input_frame, textvariable=self.folder_var, 
                                     style="Modern.TEntry", width=50)
        self.folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 12))
        
        browse_btn = ttk.Button(folder_input_frame, text="Browse Folder", 
                               command=self.browse_folder, style="Modern.TButton")
        browse_btn.pack(side="right")
        
        # Options card
        options_card = ttk.Frame(main_frame, style="Card.TFrame", padding="20")
        options_card.pack(fill="x", pady=(0, 16))
        
        options_header = ttk.Label(options_card, text="Options", style="Heading.TLabel")
        options_header.pack(anchor="w", pady=(0, 12))
        
        self.backup_enabled = tk.BooleanVar(value=True)
        backup_check = ttk.Checkbutton(options_card, 
                                      text="Create backup before organizing files", 
                                      variable=self.backup_enabled,
                                      style="Modern.TCheckbutton")
        backup_check.pack(anchor="w")
        
        # Action buttons card
        action_card = ttk.Frame(main_frame, style="Card.TFrame", padding="20")
        action_card.pack(fill="x", pady=(0, 16))
        
        button_container = tk.Frame(action_card, bg="#ffffff")
        button_container.pack()
        
        start_btn = ttk.Button(button_container, text="Start Organization", 
                              command=self.start_organization, 
                              style="Accent.TButton")
        start_btn.pack()
        
        # Progress bar (initially hidden)
        self.progress_frame = tk.Frame(action_card, bg="#ffffff")
        self.progress_frame.pack(fill="x", pady=(16, 0))
        
        progress_label = ttk.Label(self.progress_frame, text="Progress:", 
                                  background="#ffffff", foreground="#34495e",
                                  font=("Segoe UI", 9))
        progress_label.pack(anchor="w")
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, 
                                           variable=self.progress_var,
                                           maximum=100, 
                                           style="Modern.Horizontal.TProgressbar")
        self.progress_bar.pack(fill="x", pady=(8, 0))
        
        self.progress_text = ttk.Label(self.progress_frame, text="",
                                      background="#ffffff", foreground="#7f8c8d",
                                      font=("Segoe UI", 8))
        self.progress_text.pack(anchor="w", pady=(4, 0))
        
        # Hide progress initially
        self.progress_frame.pack_forget()
        
        # Status/log card
        log_card = ttk.Frame(main_frame, style="Card.TFrame", padding="20")
        log_card.pack(fill="both", expand=True)
        
        log_header = ttk.Label(log_card, text="Status & Activity", style="Heading.TLabel")
        log_header.pack(anchor="w", pady=(0, 12))
        
        log_container = tk.Frame(log_card, bg="#ffffff")
        log_container.pack(fill="both", expand=True)
        
        self.log_text = tk.Text(log_container, height=10, wrap=tk.WORD, 
                               font=("Consolas", 9), state="disabled",
                               bg="#fafbfc", fg="#2c3e50",
                               relief="flat", borderwidth=0,
                               selectbackground="#3498db",
                               selectforeground="#ffffff")
        self.log_text.pack(side="left", fill="both", expand=True)
        
        log_scroll = ttk.Scrollbar(log_container, orient="vertical", command=self.log_text.yview)
        log_scroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=log_scroll.set)
        
        self.log_message("Ready to organize files. Select a target folder to begin.")
        
    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select folder to organize")
        if folder:
            self.folder_var.set(folder)
            self.target_folder = folder
            
            # Show folder info for better user feedback
            try:
                folder_path = Path(folder)
                file_count = len(list(folder_path.rglob('*')))
                self.log_message(f"Selected: {folder}")
                self.log_message(f"Found {file_count} items to analyze", "info")
            except Exception as e:
                self.log_message(f"Selected: {folder}")
                self.log_message("Could not analyze folder contents", "error")
            
    def start_organization(self):
        if not self.validate_inputs():
            return
            
        result = messagebox.askyesno("Confirm Organization", 
                                   f"This will organize files in:\n{self.target_folder}\n\nContinue?",
                                   icon="question")
        if not result:
            self.log_message("Organization cancelled by user")
            return
                
        self.log_message("Organization started...", "success")
        if self.backup_enabled.get():
            self.log_message("Backup will be created before moving files")
        self.log_message("Backend integration pending - this is a preview version")
        
        # Show progress bar and simulate some work
        self.show_progress()
        
    def show_progress(self):
        """Show progress bar and simulate organization work"""
        self.progress_frame.pack(fill="x", pady=(16, 0))
        
        # Simulate organization steps
        steps = [
            ("Analyzing files...", 20),
            ("Creating backup...", 40),
            ("Organizing files...", 70),
            ("Updating references...", 90),
            ("Complete!", 100)
        ]
        
        def update_progress(step_index=0):
            if step_index < len(steps):
                step_text, progress = steps[step_index]
                self.progress_var.set(progress)
                self.progress_text.configure(text=step_text)
                self.log_message(step_text)
                
                # Schedule next update (simulate work)
                self.root.after(1500, lambda: update_progress(step_index + 1))
            else:
                # Hide progress bar when done
                self.root.after(2000, self.hide_progress)
                self.log_message("Organization completed successfully!", "success")
        
        update_progress()
        
    def hide_progress(self):
        """Hide the progress bar"""
        self.progress_frame.pack_forget()
        self.progress_var.set(0)
        self.progress_text.configure(text="")
        
    def validate_inputs(self):
        if not self.target_folder:
            messagebox.showerror("Missing Information", "Please select a target folder to organize")
            self.log_message("Validation failed: No folder selected", "error")
            return False
            
        if not os.path.exists(self.target_folder):
            messagebox.showerror("Invalid Folder", "The selected folder no longer exists")
            self.log_message("Validation failed: Folder doesn't exist", "error")
            return False
            
        return True
        
    def log_message(self, message, msg_type="info"):
        """Add a message to the log with optional styling"""
        self.log_text.configure(state="normal")
        
        # Add timestamp for a more professional look
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, formatted_message)
        
        # Simple color coding without being too flashy
        if msg_type == "error":
            # Subtle red tint for errors
            start_line = float(self.log_text.index(tk.END)) - 2
            self.log_text.tag_add("error", f"{start_line:.0f}.0", f"{start_line:.0f}.end")
            self.log_text.tag_config("error", foreground="#e74c3c")
        elif msg_type == "success":
            # Subtle green tint for success
            start_line = float(self.log_text.index(tk.END)) - 2
            self.log_text.tag_add("success", f"{start_line:.0f}.0", f"{start_line:.0f}.end")
            self.log_text.tag_config("success", foreground="#27ae60")
        
        self.log_text.configure(state="disabled")
        self.log_text.see(tk.END)
        
        # Force update to ensure message appears immediately
        self.root.update_idletasks()
        
    def run(self):
        self.root.mainloop()


def main():
    try:
        app = ReorgApp()
        app.run()
    except ImportError:
        print("Error: tkinter not available")
        print("Install with: sudo apt-get install python3-tk (on Ubuntu)")
        return 1
    except Exception as e:
        print(f"Error starting GUI: {e}")
        return 1
        
    return 0


if __name__ == "__main__":
    exit(main())
