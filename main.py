#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from pathlib import Path


class ReorgApp:
    def __init__(self):
        self.root = tk.Tk()
        self.setup_window()
        self.create_widgets()
        
        self.target_folder = ""
        self.model_path = ""
        
    def setup_window(self):
        self.root.title("ReORG - File Organization Tool")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.root.winfo_screenheight() // 2) - (500 // 2)
        self.root.geometry(f"600x500+{x}+{y}")
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(5, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        title_label = ttk.Label(main_frame, text="ReORG File Organizer", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        ttk.Label(main_frame, text="Target Folder:").grid(row=1, column=0, sticky="w", pady=5)
        self.folder_var = tk.StringVar()
        self.folder_entry = ttk.Entry(main_frame, textvariable=self.folder_var, width=40)
        self.folder_entry.grid(row=1, column=1, sticky="ew", padx=(10, 5))
        
        browse_btn = ttk.Button(main_frame, text="Browse", command=self.browse_folder)
        browse_btn.grid(row=1, column=2, padx=(5, 0))
        
        ttk.Label(main_frame, text="AI Model:").grid(row=2, column=0, sticky="w", pady=5)
        self.model_var = tk.StringVar()
        self.model_entry = ttk.Entry(main_frame, textvariable=self.model_var, width=40)
        self.model_entry.grid(row=2, column=1, sticky="ew", padx=(10, 5))
        
        model_btn = ttk.Button(main_frame, text="Browse", command=self.browse_model)
        model_btn.grid(row=2, column=2, padx=(5, 0))
        
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="10")
        options_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(20, 10))
        options_frame.grid_columnconfigure(0, weight=1)
        
        self.dry_run = tk.BooleanVar(value=True)
        dry_run_check = ttk.Checkbutton(options_frame, text="Dry run (preview only)", 
                                       variable=self.dry_run)
        dry_run_check.grid(row=0, column=0, sticky="w")
        
        self.backup_enabled = tk.BooleanVar(value=True)
        backup_check = ttk.Checkbutton(options_frame, text="Create backup before organizing", 
                                      variable=self.backup_enabled)
        backup_check.grid(row=1, column=0, sticky="w")
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=(20, 10))
        
        start_btn = ttk.Button(button_frame, text="Start Organization", 
                              command=self.start_organization, 
                              style="Accent.TButton")
        start_btn.pack(side="left", padx=(0, 10))
        
        preview_btn = ttk.Button(button_frame, text="Preview Changes", 
                                command=self.preview_changes)
        preview_btn.pack(side="left", padx=10)
        
        log_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        log_frame.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(10, 0))
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        
        self.log_text = tk.Text(log_frame, height=8, wrap=tk.WORD, 
                               font=("Consolas", 9), state="disabled",
                               bg="#f5f5f5")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)
        
        self.log_message("Ready to organize files. Select a target folder and AI model to begin.")
        
    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select folder to organize")
        if folder:
            self.folder_var.set(folder)
            self.target_folder = folder
            self.log_message(f"Selected target folder: {folder}")
            
    def browse_model(self):
        model_file = filedialog.askopenfilename(
            title="Select AI model file",
            filetypes=[
                ("GGUF models", "*.gguf"),
                ("Bin files", "*.bin"),
                ("All files", "*.*")
            ]
        )
        if model_file:
            self.model_var.set(model_file)
            self.model_path = model_file
            model_name = os.path.basename(model_file)
            self.log_message(f"Selected model: {model_name}")
            
    def start_organization(self):
        if not self.validate_inputs():
            return
            
        if self.dry_run.get():
            self.log_message("Starting dry run - no files will be moved")
        else:
            result = messagebox.askyesno("Confirm", 
                                       "This will actually move your files. Continue?",
                                       icon="warning")
            if not result:
                return
                
        self.log_message("Organization started...")
        self.log_message("(Backend integration pending)")
        
    def preview_changes(self):
        if not self.validate_inputs():
            return
            
        self.log_message("Generating preview...")
        self.log_message("(Preview functionality coming soon)")
        
    def validate_inputs(self):
        if not self.target_folder:
            messagebox.showerror("Error", "Please select a target folder")
            return False
            
        if not os.path.exists(self.target_folder):
            messagebox.showerror("Error", "Target folder doesn't exist")
            return False
            
        if not self.model_path:
            messagebox.showerror("Error", "Please select an AI model file")
            return False
            
        if not os.path.exists(self.model_path):
            messagebox.showerror("Error", "Model file doesn't exist")
            return False
            
        return True
        
    def log_message(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.configure(state="disabled")
        self.log_text.see(tk.END)
        
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
