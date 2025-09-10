
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import datetime
import logging
import sys
from datetime import datetime as dt, timedelta
from pathlib import Path
from typing import Optional

from sort import (
    FileSorter, FileInfo, SortCriteria, FileCategory, 
    format_size, CompressionFormat,
    TaskScheduler, ScheduleType, ScheduleStatus, logger
)


class ReorgApp:
    
    def __init__(self):
        self.root = tk.Tk()
        self.intelligent_sorter = FileSorter()
        self.scheduler = TaskScheduler()
        self.current_plan = {}
        
        self.setup_window()
        self.setup_styles()
        self.create_widgets()
        
        # Start the scheduler
        self.scheduler.start_scheduler()
        
    def setup_window(self):
        self.root.title("ReORG - Intelligent File Organization Tool")
        self.root.resizable(True, True)
        self.root.configure(bg="#f8f9fa")
        
        self.root.state('zoomed')
        
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
        ttk.Button(source_frame, text="Scan Folder", 
                  command=self.scan_folder).grid(row=0, column=3)
        
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
                                        "File Size", "Project/Topic", "File Extension"
                                    ], state="readonly")
        strategy_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Button(org_frame, text="Use Recommended", 
                  command=self.use_recommended_strategy).grid(row=0, column=2, padx=(0, 10))
        
        options_subframe = ttk.Frame(org_frame)
        options_subframe.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.dry_run_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_subframe, text="Dry run (preview only)", 
                       variable=self.dry_run_var).pack(side=tk.LEFT, padx=(0, 20))
        
        self.create_folders_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_subframe, text="Create folder structure", 
                       variable=self.create_folders_var).pack(side=tk.LEFT)
        
        # Compression options
        compression_subframe = ttk.Frame(org_frame)
        compression_subframe.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.compress_enabled_var = tk.BooleanVar(value=False)
        self.compress_checkbox = ttk.Checkbutton(compression_subframe, text="Compress organized files", 
                                                variable=self.compress_enabled_var,
                                                command=self.toggle_compression_options)
        self.compress_checkbox.pack(side=tk.LEFT, padx=(0, 20))
        
        # Compression format dropdown (initially hidden)
        self.compression_format_frame = ttk.Frame(compression_subframe)
        
        ttk.Label(self.compression_format_frame, text="Format:").pack(side=tk.LEFT, padx=(0, 5))
        self.compression_var = tk.StringVar(value="ZIP")
        self.compression_combo = ttk.Combobox(self.compression_format_frame, textvariable=self.compression_var,
                                             values=["ZIP", "RAR", "TAR.GZ"], state="readonly", width=8)
        self.compression_combo.pack(side=tk.LEFT)
        
        action_frame = ttk.Frame(org_frame)
        action_frame.grid(row=4, column=0, columnspan=3, pady=(15, 0))
        
        ttk.Button(action_frame, text="📋 Preview Organization", 
                  command=self.preview_organization).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(action_frame, text="🗂️ Organize Files", 
                  command=self.organize_files).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(action_frame, text="⏰ Schedule", 
                  command=self.open_scheduler).pack(side=tk.LEFT, padx=(0, 10))
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
        
    def toggle_compression_options(self):
        """Show or hide compression format options based on checkbox state"""
        if self.compress_enabled_var.get():
            self.compression_format_frame.pack(side=tk.LEFT, padx=(0, 10))
        else:
            self.compression_format_frame.pack_forget()
    
    def browse_source_folder(self):
        folder = filedialog.askdirectory(title="Select folder to organize")
        if folder:
            self.source_folder_var.set(folder)
            
    def scan_folder(self):
        source_folder = self.source_folder_var.get()
        if not source_folder:
            messagebox.showerror("Error", "Please select a source folder first")
            return
        
        if not os.path.exists(source_folder):
            logger.error(f"Source folder does not exist: {source_folder}")
            messagebox.showerror("Error", "Selected folder does not exist")
            return
        
        try:
            logger.info(f"Starting folder scan: {source_folder}")
            self.log_output("🔍 Scanning folder...")
            self.root.update()
            
            files = self.intelligent_sorter.scan(source_folder)
            
            for item in self.file_tree.get_children():
                self.file_tree.delete(item)
            
            # Populate file list (show first 20 files)
            for file_info in files[:20]:
                relative_path = file_info.path.relative_to(Path(source_folder))
                self.file_tree.insert("", "end", values=(
                    str(relative_path),
                    file_info.ext or "N/A",
                    format_size(file_info.size),
                    file_info.modified.strftime("%Y-%m-%d"),
                    file_info.cat.value
                ))
            
            stats = self.intelligent_sorter.get_stats()
            stats_text = f"📊 Analysis Results:\n"
            stats_text += f"Total files: {stats['total_files']}\n"
            stats_text += f"Total size: {format_size(stats['total_size'])}\n"
            stats_text += f"Categories: {', '.join([f'{k}({v})' for k, v in stats['categories'].items()])}\n"
            
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, stats_text)
            
            recommendation = self.intelligent_sorter.recommend()
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
            logger.error(f"Folder scan failed: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to scan folder: {str(e)}")
            self.log_output(f"❌ Scan failed: {str(e)}")
    
    def use_recommended_strategy(self):
        if hasattr(self, 'current_recommendation'):
            strategy_map = {
                SortCriteria.TYPE: "File Type",
                SortCriteria.DATE: "Date (Year)",
                SortCriteria.SIZE: "File Size",
                SortCriteria.PROJECT: "Project/Topic",
                SortCriteria.EXTENSION: "File Extension"
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
        
        compression = self._get_selected_compression()
        
        try:
            # Always dry run for preview
            plan = self.intelligent_sorter.organize_files(strategy, dry_run=True, compression=compression)
            self.current_plan = plan
            
            summary = self.intelligent_sorter.get_summary(plan)
            
            # Add compression info to preview
            if compression != CompressionFormat.NONE:
                total_files = sum(len(files) for files in plan.values())
                summary += f"\n📦 Compression Info:\n"
                summary += f"Format: {compression.value.upper()}\n"
                summary += f"Will create: organized_files_[timestamp].{compression.value}\n"
                summary += f"Total files to compress: {total_files}\n"
            
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, summary)
            
            self.log_output(f"📋 Preview generated for {sum(len(files) for files in plan.values())} files")
            
        except Exception as e:
            logger.error(f"Preview generation failed: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to generate preview: {str(e)}")
    
    def organize_files(self):
        if not self.current_plan:
            messagebox.showerror("Error", "Please generate a preview first")
            return
        
        strategy = self._get_selected_strategy()
        if not strategy:
            messagebox.showerror("Error", "Please select a sorting strategy")
            return
        
        compression = self._get_selected_compression()
        
        if not self.dry_run_var.get():
            total_files = sum(len(files) for files in self.current_plan.values())
            source_folder = self.source_folder_var.get()
            
            # Update confirmation message based on compression
            if compression != CompressionFormat.NONE:
                confirm_message = f"This will organize {total_files} files from {source_folder} into a {compression.value.upper()} archive.\n\nThe original files will remain in place and organized files will be compressed.\n\nAre you sure you want to proceed?"
            else:
                confirm_message = f"This will organize {total_files} files within {source_folder}.\n\nAre you sure you want to proceed?"
            
            result = messagebox.askyesno("Confirm Organization", confirm_message)
            if not result:
                return
        
        try:
            result = self.intelligent_sorter.organize_files(
                strategy, 
                dry_run=self.dry_run_var.get(),
                compression=compression
            )
            
            if self.dry_run_var.get():
                self.log_output("✅ Dry run completed - no files were moved")
            else:
                if compression != CompressionFormat.NONE:
                    # Result is the path to the compressed file
                    archive_path = result
                    self.log_output(f"✅ Organization and compression complete!")
                    self.log_output(f"📦 Created archive: {Path(archive_path).name}")
                    messagebox.showinfo("Success", f"Files organized and compressed!\n\nArchive created: {Path(archive_path).name}")
                else:
                    # Result is the organization plan
                    total_files = sum(len(files) for files in result.values())
                    self.log_output(f"✅ Organization complete! Moved {total_files} files")
                    messagebox.showinfo("Success", f"Successfully organized {total_files} files!")
            
        except Exception as e:
            logger.error(f"File organization failed: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to organize files: {str(e)}")
            self.log_output(f"❌ Organization failed: {str(e)}")
    
    def _get_selected_strategy(self):
        strategy_map = {
            "File Type": SortCriteria.TYPE,
            "Date (Year)": SortCriteria.DATE,
            "Date (Month)": SortCriteria.DATE,
            "File Size": SortCriteria.SIZE,
            "Project/Topic": SortCriteria.PROJECT,
            "File Extension": SortCriteria.EXTENSION
        }
        
        selected = self.sort_strategy_var.get()
        return strategy_map.get(selected)
    
    def _get_selected_compression(self):
        if not self.compress_enabled_var.get():
            return CompressionFormat.NONE
        
        compression_map = {
            "ZIP": CompressionFormat.ZIP,
            "RAR": CompressionFormat.RAR,
            "TAR.GZ": CompressionFormat.TAR_GZ
        }
        
        selected = self.compression_var.get()
        return compression_map.get(selected, CompressionFormat.ZIP)
    
    def clear_all(self):
        self.intelligent_sorter = FileSorter()
        self.current_plan = {}
        if hasattr(self, 'current_recommendation'):
            delattr(self, 'current_recommendation')
        
        self.source_folder_var.set("")
        self.sort_strategy_var.set("")
        self.compress_enabled_var.set(False)
        self.compression_var.set("ZIP")
        self.toggle_compression_options()  # Hide compression format options
        
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
    
    def open_scheduler(self):
        """Open the task scheduler window"""
        scheduler_window = tk.Toplevel(self.root)
        scheduler_window.title("Task Scheduler")
        scheduler_window.geometry("800x600")
        scheduler_window.transient(self.root)
        scheduler_window.grab_set()
        
        # Create notebook for tabs
        notebook = ttk.Notebook(scheduler_window)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create Schedule tab
        schedule_frame = ttk.Frame(notebook)
        notebook.add(schedule_frame, text="Create Schedule")
        self.create_schedule_tab(schedule_frame)
        
        # Create Manage tab
        manage_frame = ttk.Frame(notebook)
        notebook.add(manage_frame, text="Manage Tasks")
        self.create_manage_tab(manage_frame)
    
    def create_schedule_tab(self, parent):
        """Create the schedule creation tab"""
        # Task details
        details_frame = ttk.LabelFrame(parent, text="Task Details", padding="10")
        details_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(details_frame, text="Task Name:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.schedule_name_var = tk.StringVar()
        ttk.Entry(details_frame, textvariable=self.schedule_name_var, width=40).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Label(details_frame, text="Folder Path:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.schedule_folder_var = tk.StringVar()
        folder_frame = ttk.Frame(details_frame)
        folder_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(5, 0))
        ttk.Entry(folder_frame, textvariable=self.schedule_folder_var, width=30).pack(side=tk.LEFT, fill="x", expand=True)
        ttk.Button(folder_frame, text="Browse", command=self.browse_schedule_folder).pack(side=tk.RIGHT, padx=(5, 0))
        
        details_frame.columnconfigure(1, weight=1)
        
        # Organization settings
        org_frame = ttk.LabelFrame(parent, text="Organization Settings", padding="10")
        org_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(org_frame, text="Sort Strategy:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.schedule_strategy_var = tk.StringVar(value="File Type")
        strategy_combo = ttk.Combobox(org_frame, textvariable=self.schedule_strategy_var,
                                     values=["File Type", "Date (Year)", "Date (Month)", 
                                            "File Size", "Project/Topic", "File Extension"],
                                     state="readonly")
        strategy_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Label(org_frame, text="Compression:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.schedule_compression_var = tk.StringVar(value="None")
        compression_combo = ttk.Combobox(org_frame, textvariable=self.schedule_compression_var,
                                        values=["None", "ZIP", "RAR", "TAR.GZ"],
                                        state="readonly")
        compression_combo.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(5, 0))
        
        org_frame.columnconfigure(1, weight=1)
        
        # Schedule settings
        schedule_frame = ttk.LabelFrame(parent, text="Schedule Settings", padding="10")
        schedule_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(schedule_frame, text="Schedule Type:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.schedule_type_var = tk.StringVar(value="One Time")
        type_combo = ttk.Combobox(schedule_frame, textvariable=self.schedule_type_var,
                                 values=["One Time", "Daily", "Weekly", "Monthly"],
                                 state="readonly", command=self.on_schedule_type_change)
        type_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Date and time selection
        ttk.Label(schedule_frame, text="Date:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        date_frame = ttk.Frame(schedule_frame)
        date_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(5, 0))
        
        self.schedule_date_var = tk.StringVar(value=dt.now().strftime("%Y-%m-%d"))
        ttk.Entry(date_frame, textvariable=self.schedule_date_var, width=12).pack(side=tk.LEFT)
        ttk.Label(date_frame, text="Time:").pack(side=tk.LEFT, padx=(10, 5))
        
        self.schedule_time_var = tk.StringVar(value="12:00")
        ttk.Entry(date_frame, textvariable=self.schedule_time_var, width=8).pack(side=tk.LEFT)
        
        # Recurring options (initially hidden)
        self.recurring_frame = ttk.Frame(schedule_frame)
        
        ttk.Label(self.recurring_frame, text="Max Runs:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.max_runs_var = tk.StringVar()
        ttk.Entry(self.recurring_frame, textvariable=self.max_runs_var, width=10).grid(row=0, column=1, sticky=tk.W)
        ttk.Label(self.recurring_frame, text="(leave empty for unlimited)").grid(row=0, column=2, sticky=tk.W, padx=(5, 0))
        
        schedule_frame.columnconfigure(1, weight=1)
        
        # Action buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(button_frame, text="Create Task", command=self.create_scheduled_task).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=lambda: parent.master.master.destroy()).pack(side=tk.RIGHT)
    
    def create_manage_tab(self, parent):
        """Create the task management tab"""
        # Task list
        list_frame = ttk.LabelFrame(parent, text="Scheduled Tasks", padding="10")
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create treeview for tasks
        columns = ("Name", "Folder", "Schedule", "Status", "Next Run", "Last Run")
        self.task_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.task_tree.heading(col, text=col)
            if col == "Name":
                self.task_tree.column(col, width=150)
            elif col == "Folder":
                self.task_tree.column(col, width=200)
            else:
                self.task_tree.column(col, width=120)
        
        task_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.task_tree.yview)
        self.task_tree.configure(yscrollcommand=task_scrollbar.set)
        
        self.task_tree.pack(side="left", fill="both", expand=True)
        task_scrollbar.pack(side="right", fill="y")
        
        # Task control buttons
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="Refresh", command=self.refresh_task_list).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Enable", command=self.enable_selected_task).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Disable", command=self.disable_selected_task).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Cancel", command=self.cancel_selected_task).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Delete", command=self.delete_selected_task).pack(side=tk.LEFT, padx=(0, 5))
        
        # Refresh the task list
        self.refresh_task_list()
    
    def browse_schedule_folder(self):
        """Browse for folder to schedule"""
        folder = filedialog.askdirectory(title="Select folder to schedule organization")
        if folder:
            self.schedule_folder_var.set(folder)
    
    def on_schedule_type_change(self, event=None):
        """Handle schedule type changes"""
        schedule_type = self.schedule_type_var.get()
        if schedule_type == "One Time":
            self.recurring_frame.grid_forget()
        else:
            self.recurring_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
    
    def create_scheduled_task(self):
        """Create a new scheduled task"""
        # Validate inputs
        if not self.schedule_name_var.get().strip():
            messagebox.showerror("Error", "Please enter a task name")
            return
        
        if not self.schedule_folder_var.get().strip():
            messagebox.showerror("Error", "Please select a folder to organize")
            return
        
        try:
            # Parse date and time
            date_str = self.schedule_date_var.get()
            time_str = self.schedule_time_var.get()
            scheduled_datetime = dt.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
            
            if scheduled_datetime <= dt.now():
                messagebox.showerror("Error", "Scheduled time must be in the future")
                return
            
            # Get strategy
            strategy_map = {
                "File Type": SortCriteria.TYPE,
                "Date (Year)": SortCriteria.DATE,
                "Date (Month)": SortCriteria.DATE,
                "File Size": SortCriteria.SIZE,
                "Project/Topic": SortCriteria.PROJECT,
                "File Extension": SortCriteria.EXTENSION
            }
            strategy = strategy_map.get(self.schedule_strategy_var.get(), SortCriteria.TYPE)
            
            # Get compression
            compression_map = {
                "None": CompressionFormat.NONE,
                "ZIP": CompressionFormat.ZIP,
                "RAR": CompressionFormat.RAR,
                "TAR.GZ": CompressionFormat.TAR_GZ
            }
            compression = compression_map.get(self.schedule_compression_var.get(), CompressionFormat.NONE)
            
            # Get schedule type
            type_map = {
                "One Time": ScheduleType.ONE_TIME,
                "Daily": ScheduleType.DAILY,
                "Weekly": ScheduleType.WEEKLY,
                "Monthly": ScheduleType.MONTHLY
            }
            schedule_type = type_map.get(self.schedule_type_var.get(), ScheduleType.ONE_TIME)
            
            # Get max runs
            max_runs = None
            if self.max_runs_var.get().strip():
                try:
                    max_runs = int(self.max_runs_var.get())
                except ValueError:
                    messagebox.showerror("Error", "Max runs must be a number")
                    return
            
            # Create task
            task_id = self.scheduler.create_task(
                name=self.schedule_name_var.get().strip(),
                folder_path=self.schedule_folder_var.get(),
                strategy=strategy,
                compression=compression,
                schedule_type=schedule_type,
                scheduled_time=scheduled_datetime,
                max_runs=max_runs
            )
            
            messagebox.showinfo("Success", f"Task '{self.schedule_name_var.get()}' created successfully!")
            
            # Clear form
            self.schedule_name_var.set("")
            self.schedule_folder_var.set("")
            self.schedule_strategy_var.set("File Type")
            self.schedule_compression_var.set("None")
            self.schedule_type_var.set("One Time")
            self.max_runs_var.set("")
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid date/time format: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create task: {e}")
    
    def refresh_task_list(self):
        """Refresh the task list display"""
        # Clear existing items
        for item in self.task_tree.get_children():
            self.task_tree.delete(item)
        
        # Add current tasks
        for task in self.scheduler.get_all_tasks():
            schedule_desc = task.schedule_type.value.replace("_", " ").title()
            next_run = task.next_run.strftime("%Y-%m-%d %H:%M") if task.enabled else "Disabled"
            last_run = task.last_run.strftime("%Y-%m-%d %H:%M") if task.last_run else "Never"
            
            self.task_tree.insert("", "end", values=(
                task.name,
                task.folder_path,
                schedule_desc,
                task.status.value.title(),
                next_run,
                last_run
            ), tags=(task.id,))
    
    def get_selected_task_id(self) -> Optional[str]:
        """Get the ID of the selected task"""
        selection = self.task_tree.selection()
        if selection:
            item = selection[0]
            tags = self.task_tree.item(item, "tags")
            return tags[0] if tags else None
        return None
    
    def enable_selected_task(self):
        """Enable the selected task"""
        task_id = self.get_selected_task_id()
        if task_id:
            self.scheduler.enable_task(task_id, True)
            self.refresh_task_list()
        else:
            messagebox.showwarning("Warning", "Please select a task")
    
    def disable_selected_task(self):
        """Disable the selected task"""
        task_id = self.get_selected_task_id()
        if task_id:
            self.scheduler.enable_task(task_id, False)
            self.refresh_task_list()
        else:
            messagebox.showwarning("Warning", "Please select a task")
    
    def cancel_selected_task(self):
        """Cancel the selected task"""
        task_id = self.get_selected_task_id()
        if task_id:
            task = self.scheduler.get_task(task_id)
            if task:
                result = messagebox.askyesno("Confirm", f"Cancel task '{task.name}'?")
                if result:
                    self.scheduler.cancel_task(task_id)
                    self.refresh_task_list()
        else:
            messagebox.showwarning("Warning", "Please select a task")
    
    def delete_selected_task(self):
        """Delete the selected task"""
        task_id = self.get_selected_task_id()
        if task_id:
            task = self.scheduler.get_task(task_id)
            if task:
                result = messagebox.askyesno("Confirm", f"Delete task '{task.name}'?\n\nThis action cannot be undone.")
                if result:
                    self.scheduler.delete_task(task_id)
                    self.refresh_task_list()
        else:
            messagebox.showwarning("Warning", "Please select a task")
        
    def run(self):
        try:
            self.root.mainloop()
        finally:
            # Stop the scheduler when closing
            self.scheduler.stop_scheduler()


def main():
    try:
        logger.info("Starting ReORG application")
        app = ReorgApp()
        app.run()
        logger.info("ReORG application closed normally")
    except ImportError as e:
        error_msg = f"Missing required module: {e}\nMake sure all dependencies are installed"
        logger.error(f"Import error: {e}")
        import tkinter.messagebox as messagebox
        messagebox.showerror("Import Error", error_msg)
        return 1
    except Exception as e:
        error_msg = f"Error starting application: {e}"
        logger.error(f"Application startup error: {e}", exc_info=True)
        import tkinter.messagebox as messagebox
        messagebox.showerror("Application Error", error_msg)
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
