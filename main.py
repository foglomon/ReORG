
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import datetime
from pathlib import Path

from sort import (
    FileSorter, FileInfo, SortCriteria, FileCategory, 
    format_size, create_test_files
)


class ReorgApp:
    
    def __init__(self):
        self.root = tk.Tk()
        self.intelligent_sorter = FileSorter()
        self.current_plan = {}
        
        self.setup_window()
        self.setup_styles()
        self.create_widgets()
        
    def setup_window(self):
        self.root.title("ReORG - Intelligent File Organization Tool")
        self.root.geometry("900x750")
        self.root.resizable(True, True)
        self.root.configure(bg="#f8f9fa")
        
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (450)
        y = (self.root.winfo_screenheight() // 2) - (375)
        self.root.geometry(f"900x750+{x}+{y}")
        
    def setup_styles(self):
        style = ttk.Style()
        
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
                       font=("Segoe UI", 12, "bold"))
        
    def create_widgets(self):
        # Create main intelligent interface directly without tabs
        self.create_intelligent_interface()
        
    def create_intelligent_interface(self):
        # Create main container frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        title_frame = ttk.Frame(main_frame, style="Card.TFrame")
        title_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        title_label = ttk.Label(title_frame, 
                               text="🧠 Intelligent File Sorter", 
                               style="Title.TLabel")
        title_label.pack(pady=20)
        
        source_frame = ttk.LabelFrame(main_frame, text="Source Folder", padding="10")
        source_frame.pack(fill="x", padx=20, pady=(0, 10))
        source_frame.columnconfigure(1, weight=1)
        
        ttk.Label(source_frame, text="Folder to organize:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.source_folder_var = tk.StringVar()
        self.source_entry = ttk.Entry(source_frame, textvariable=self.source_folder_var)
        self.source_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Button(source_frame, text="Browse", 
                  command=self.browse_source_folder).grid(row=0, column=2, padx=(0, 10))
        ttk.Button(source_frame, text="Create Test Files", 
                  command=self.create_test_files).grid(row=0, column=3, padx=(0, 10))
        ttk.Button(source_frame, text="Scan Folder", 
                  command=self.scan_folder).grid(row=0, column=4)
        
        analysis_frame = ttk.LabelFrame(main_frame, text="File Analysis", padding="10")
        analysis_frame.pack(fill="x", padx=20, pady=(0, 10))
        analysis_frame.columnconfigure(0, weight=1)
        
        self.stats_text = tk.Text(analysis_frame, height=4, wrap=tk.WORD)
        self.stats_text.pack(fill="x", pady=(0, 10))
        
        columns = ("File", "Type", "Size", "Modified", "Category")
        self.file_tree = ttk.Treeview(analysis_frame, columns=columns, show="headings", height=6)
        
        for col in columns:
            self.file_tree.heading(col, text=col)
            if col == "File":
                self.file_tree.column(col, width=200)
            elif col == "Size":
                self.file_tree.column(col, width=80)
            else:
                self.file_tree.column(col, width=100)
        
        file_scrollbar = ttk.Scrollbar(analysis_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=file_scrollbar.set)
        
        self.file_tree.pack(side="left", fill="both", expand=True)
        file_scrollbar.pack(side="right", fill="y")
        
        rec_frame = ttk.LabelFrame(main_frame, text="Smart Recommendations", padding="10")
        rec_frame.pack(fill="x", padx=20, pady=(0, 10))
        rec_frame.columnconfigure(0, weight=1)
        
        self.recommendations_text = tk.Text(rec_frame, height=3, wrap=tk.WORD)
        self.recommendations_text.pack(fill="x")
        
        org_frame = ttk.LabelFrame(main_frame, text="Organization Settings", padding="10")
        org_frame.pack(fill="x", padx=20, pady=(0, 10))
        org_frame.columnconfigure(1, weight=1)
        
        ttk.Label(org_frame, text="Sort by:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.sort_strategy_var = tk.StringVar()
        strategy_combo = ttk.Combobox(org_frame, textvariable=self.sort_strategy_var, 
                                    values=[
                                        "File Type", "Date (Year)", "Date (Month)", 
                                        "File Size", "Project/Topic", "File Extension", "Version Control"
                                    ], state="readonly")
        strategy_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Button(org_frame, text="Use Recommended", 
                  command=self.use_recommended_strategy).grid(row=0, column=2, padx=(0, 10))
        
        ttk.Label(org_frame, text="Target folder:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.target_folder_var = tk.StringVar()
        target_entry = ttk.Entry(org_frame, textvariable=self.target_folder_var)
        target_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(10, 0))
        
        ttk.Button(org_frame, text="Browse", 
                  command=self.browse_target_folder).grid(row=1, column=2, pady=(10, 0))
        
        options_subframe = ttk.Frame(org_frame)
        options_subframe.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.dry_run_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_subframe, text="Dry run (preview only)", 
                       variable=self.dry_run_var).pack(side=tk.LEFT, padx=(0, 20))
        
        self.create_folders_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_subframe, text="Create folder structure", 
                       variable=self.create_folders_var).pack(side=tk.LEFT)
        
        action_frame = ttk.Frame(org_frame)
        action_frame.grid(row=3, column=0, columnspan=3, pady=(15, 0))
        
        ttk.Button(action_frame, text="📋 Preview Organization", 
                  command=self.preview_organization).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(action_frame, text="🗂️ Organize Files", 
                  command=self.organize_files).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(action_frame, text="🧹 Clear All", 
                  command=self.clear_all).pack(side=tk.LEFT)
        
        results_frame = ttk.LabelFrame(main_frame, text="Organization Preview", padding="10")
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        self.results_text = tk.Text(results_frame, height=8, wrap=tk.WORD)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=results_scrollbar.set)
        results_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
    def browse_source_folder(self):
        folder = filedialog.askdirectory(title="Select folder to organize")
        if folder:
            self.source_folder_var.set(folder)
            
    def browse_target_folder(self):
        folder = filedialog.askdirectory(title="Select target folder for organized files")
        if folder:
            self.target_folder_var.set(folder)
    
    def create_test_files(self):
        folder = filedialog.askdirectory(title="Select folder for test files")
        if folder:
            try:
                create_test_files(folder)
                self.source_folder_var.set(folder)
                messagebox.showinfo("Success", f"Test files created in {folder}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create test files: {str(e)}")
    
    def scan_folder(self):
        source_folder = self.source_folder_var.get()
        if not source_folder:
            messagebox.showerror("Error", "Please select a source folder first")
            return
        
        if not os.path.exists(source_folder):
            messagebox.showerror("Error", "Selected folder does not exist")
            return
        
        try:
            self.log_output("🔍 Scanning folder...")
            self.root.update()
            
            files = self.intelligent_sorter.scan_folder(source_folder)
            
            for item in self.file_tree.get_children():
                self.file_tree.delete(item)
            
            # Populate file list (show first 20 files)
            for file_info in files[:20]:
                relative_path = file_info.path.relative_to(Path(source_folder))
                self.file_tree.insert("", "end", values=(
                    str(relative_path),
                    file_info.extension or "N/A",
                    format_size(file_info.size),
                    file_info.modified.strftime("%Y-%m-%d"),
                    file_info.category.value
                ))
            
            stats = self.intelligent_sorter.get_stats()
            stats_text = f"📊 Analysis Results:\n"
            stats_text += f"Total files: {stats['total_files']}\n"
            stats_text += f"Total size: {format_size(stats['total_size'])}\n"
            stats_text += f"Categories: {', '.join([f'{k}({v})' for k, v in stats['categories'].items()])}\n"
            
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, stats_text)
            
            recommendation = self.intelligent_sorter.recommend_strategy()
            rec_text = f"🎯 Smart Recommendation:\n"
            rec_text += f"Strategy: {recommendation['strategy'].value}\n"
            rec_text += f"Reason: {recommendation['reason']}\n"
            if 'confidence' in recommendation:
                rec_text += f"Confidence: {recommendation['confidence']}%"
            
            self.recommendations_text.delete(1.0, tk.END)
            self.recommendations_text.insert(1.0, rec_text)
            
            self.current_recommendation = recommendation
            
            self.log_output(f"✅ Scan complete! Found {len(files)} files")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan folder: {str(e)}")
            self.log_output(f"❌ Scan failed: {str(e)}")
    
    def use_recommended_strategy(self):
        if hasattr(self, 'current_recommendation'):
            strategy_map = {
                SortCriteria.TYPE: "File Type",
                SortCriteria.DATE: "Date (Year)",
                SortCriteria.MONTH: "Date (Month)",
                SortCriteria.SIZE: "File Size",
                SortCriteria.PROJECT: "Project/Topic",
                SortCriteria.EXTENSION: "File Extension",
                SortCriteria.VERSION: "Version Control"
            }
            
            recommended = strategy_map.get(self.current_recommendation['strategy'], "File Type")
            self.sort_strategy_var.set(recommended)
        else:
            messagebox.showwarning("Warning", "Please scan a folder first to get recommendations")
    
    def preview_organization(self):
        if not self.intelligent_sorter.files:
            messagebox.showerror("Error", "Please scan a folder first")
            return
        
        strategy = self._get_selected_strategy()
        if not strategy:
            messagebox.showerror("Error", "Please select a sorting strategy")
            return
        
        try:
            target_folder = self.target_folder_var.get() or "organized_files"
            plan = self.intelligent_sorter.organize_files(target_folder, strategy, dry_run=True)
            self.current_plan = plan
            
            summary = self.intelligent_sorter.get_summary(plan)
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, summary)
            
            self.log_output(f"📋 Preview generated for {sum(len(files) for files in plan.values())} files")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate preview: {str(e)}")
    
    def organize_files(self):
        if not self.current_plan:
            messagebox.showerror("Error", "Please generate a preview first")
            return
        
        target_folder = self.target_folder_var.get()
        if not target_folder:
            messagebox.showerror("Error", "Please select a target folder")
            return
        
        strategy = self._get_selected_strategy()
        if not strategy:
            messagebox.showerror("Error", "Please select a sorting strategy")
            return
        
        if not self.dry_run_var.get():
            total_files = sum(len(files) for files in self.current_plan.values())
            result = messagebox.askyesno(
                "Confirm Organization", 
                f"This will move {total_files} files to {target_folder}.\n\nAre you sure you want to proceed?"
            )
            if not result:
                return
        
        try:
            plan = self.intelligent_sorter.organize_files(
                target_folder, 
                strategy, 
                dry_run=self.dry_run_var.get()
            )
            
            if self.dry_run_var.get():
                self.log_output("✅ Dry run completed - no files were moved")
            else:
                total_files = sum(len(files) for files in plan.values())
                self.log_output(f"✅ Organization complete! Moved {total_files} files")
                messagebox.showinfo("Success", f"Successfully organized {total_files} files!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to organize files: {str(e)}")
            self.log_output(f"❌ Organization failed: {str(e)}")
    
    def _get_selected_strategy(self):
        strategy_map = {
            "File Type": SortCriteria.TYPE,
            "Date (Year)": SortCriteria.DATE,
            "Date (Month)": SortCriteria.DATE,
            "File Size": SortCriteria.SIZE,
            "Project/Topic": SortCriteria.PROJECT,
            "File Extension": SortCriteria.EXTENSION,
            "Version Control": SortCriteria.VERSION
        }
        
        selected = self.sort_strategy_var.get()
        return strategy_map.get(selected)
    
    def clear_all(self):
        self.intelligent_sorter = FileSorter()
        self.current_plan = {}
        if hasattr(self, 'current_recommendation'):
            delattr(self, 'current_recommendation')
        
        self.source_folder_var.set("")
        self.target_folder_var.set("")
        self.sort_strategy_var.set("")
        
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        self.stats_text.delete(1.0, tk.END)
        self.recommendations_text.delete(1.0, tk.END)
        self.results_text.delete(1.0, tk.END)
        
        self.log_output("🧹 All data cleared")
    
    def log_output(self, message):
        current = self.results_text.get(1.0, tk.END)
        if current.strip():
            self.results_text.insert(tk.END, f"\n{message}")
        else:
            self.results_text.insert(1.0, message)
        self.results_text.see(tk.END)
        self.root.update()
        
    def run(self):
        self.root.mainloop()


def main():
    try:
        app = ReorgApp()
        app.run()
    except ImportError as e:
        print(f"Error: Missing required module - {e}")
        print("Make sure all dependencies are installed")
        return 1
    except Exception as e:
        print(f"Error starting application: {e}")
        return 1
        
    return 0


if __name__ == "__main__":
    exit(main())
