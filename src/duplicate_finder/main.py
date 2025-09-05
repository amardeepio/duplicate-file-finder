import sys
import multiprocessing
import os
import hashlib
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                            QProgressBar, QTreeWidget, QTreeWidgetItem, 
                            QCheckBox, QComboBox, QGroupBox, QLineEdit, 
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QSplitter, QMessageBox, QAction, QMenu, QSpinBox,
                            QDialog, QTabWidget, QAbstractItemView)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QIcon, QFont

# Import the other tools
from .analyzer import DiskSpaceAnalyzer
from .visualizer import DiskVisualizer

# Top-level worker function for multiprocessing
def _hash_file_worker(file_path, chunk_size=8192):
    """Worker function to hash a single file."""
    md5 = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                md5.update(chunk)
        return file_path, md5.hexdigest()
    except Exception:
        return file_path, None


class FileScanner(QThread):
    """Worker thread for scanning files to avoid UI freezing"""
    progress_update = pyqtSignal(int, str)
    scan_complete = pyqtSignal(dict)

    def __init__(self, root_path, file_extensions=None, min_size=1024, scan_method="content"):
        super().__init__()
        self.root_path = root_path
        self.file_extensions = file_extensions
        self.min_size = min_size
        self.scan_method = scan_method
        self.running = True

    def run(self):
        """Dispatcher for different scan methods."""
        try:
            if self.scan_method == "content":
                self._scan_by_content()
            else:
                self._scan_by_name_or_size()
        except Exception as e:
            print(f"Error during scan: {str(e)}")
            self.scan_complete.emit({})

    def _scan_by_content(self):
        """Scan for duplicates by file content (size -> hash), parallelized."""
        # Pass 1: Group by size
        sizes = {}
        processed_count = 0
        total_files = self._count_files_quickly()
        self.progress_update.emit(0, "Pass 1/2: Grouping by size...")

        for file_path, file_size in self._iter_files():
            if not self.running:
                return
            processed_count += 1
            if processed_count % 20 == 0 or processed_count == total_files:
                percentage = int((processed_count / total_files) * 50)  # Pass 1 is 50%
                self.progress_update.emit(percentage, f"Pass 1/2: Analyzing sizes... {self._truncate_path(file_path)}")

            if file_size in sizes:
                sizes[file_size].append(file_path)
            else:
                sizes[file_size] = [file_path]

        # Prepare for Pass 2: Hashing
        duplicates = {}
        potential_duplicates_paths = []
        for size, paths in sizes.items():
            if len(paths) > 1:
                potential_duplicates_paths.extend(paths)
        
        total_to_hash = len(potential_duplicates_paths)
        if total_to_hash == 0:
            self.progress_update.emit(100, "Scan complete. No duplicates found.")
            self.scan_complete.emit({})
            return

        # Pass 2: Hashing potential duplicates in parallel
        self.progress_update.emit(50, "Pass 2/2: Hashing potential duplicates...")
        
        num_processes = os.cpu_count() or 1
        pool = multiprocessing.Pool(processes=num_processes)
        
        hashed_count = 0
        try:
            results_iterator = pool.imap_unordered(_hash_file_worker, potential_duplicates_paths)
            
            for file_path, file_hash in results_iterator:
                if not self.running:
                    pool.terminate()
                    break
                
                hashed_count += 1
                percentage = 50 + int((hashed_count / total_to_hash) * 50) # Pass 2 is 50%
                self.progress_update.emit(percentage, f"Pass 2/2: Hashing... {self._truncate_path(file_path)}")

                if file_hash:
                    try:
                        file_size = os.path.getsize(file_path)
                        file_info = {'path': file_path, 'size': file_size, 'modified': os.path.getmtime(file_path)}
                        if file_hash in duplicates:
                            duplicates[file_hash].append(file_info)
                        else:
                            duplicates[file_hash] = [file_info]
                    except OSError:
                        continue
        finally:
            pool.close()
            pool.join()

        if not self.running:
            return

        result = {key: files for key, files in duplicates.items() if len(files) > 1}
        self.scan_complete.emit(result)

    def _scan_by_name_or_size(self):
        """Scan for duplicates by file name or size."""
        duplicates = {}
        processed_count = 0
        total_files = self._count_files_quickly()
        self.progress_update.emit(0, "Scanning...")

        for file_path, file_size in self._iter_files():
            if not self.running:
                break
            
            processed_count += 1
            if processed_count % 20 == 0 or processed_count == total_files:
                percentage = int((processed_count / total_files) * 100)
                self.progress_update.emit(percentage, f"Scanning... {self._truncate_path(file_path)}")

            try:
                if self.scan_method == "size":
                    signature = str(file_size)
                elif self.scan_method == "name":
                    signature = os.path.basename(file_path)
                else:
                    signature = None
                
                if signature:
                    file_info = {'path': file_path, 'size': file_size, 'modified': os.path.getmtime(file_path)}
                    if signature in duplicates:
                        duplicates[signature].append(file_info)
                    else:
                        duplicates[signature] = [file_info]
            except (OSError, FileNotFoundError):
                continue

        result = {key: files for key, files in duplicates.items() if len(files) > 1}
        self.scan_complete.emit(result)

    def _truncate_path(self, path, length=60):
        if len(path) > length:
            return "..." + path[-(length - 3):]
        return path

    def _count_files_quickly(self):
        """Quickly estimate the number of files to process."""
        total_files = 0
        try:
            for root, _, files in os.walk(self.root_path):
                if not self.running:
                    break
                total_files += len(files)
                if total_files > 20000:
                    break
        except Exception as e:
            print(f"Error estimating file count: {str(e)}")
            return 1000
        return max(total_files, 1)

    def _iter_files(self):
        """Generator that yields (file_path, file_size) tuples, with filtering."""
        try:
            for root, _, files in os.walk(self.root_path):
                for filename in files:
                    if not self.running:
                        return
                    file_path = os.path.join(root, filename)
                    if self.file_extensions and not any(file_path.lower().endswith(ext.lower()) for ext in self.file_extensions):
                        continue
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size >= self.min_size:
                            yield file_path, file_size
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
        except Exception as e:
            print(f"Error scanning directory: {str(e)}")

    def stop(self):
        self.running = False


class DuplicateFinderWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.scanner_thread = None
        self.duplicates = {}
        self.initUI()
        
    def initUI(self):
        main_layout = QVBoxLayout(self)
        
        # Create scan options group
        scan_options_group = QGroupBox("Scan Options")
        scan_options_layout = QVBoxLayout(scan_options_group)
        
        # Path selection
        path_layout = QVBoxLayout()
        path_layout.addWidget(QLabel("Enter the full path to scan:"))
        
        path_input_layout = QHBoxLayout()
        
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("e.g., /home/user/Documents")
        path_input_layout.addWidget(self.path_input, 3)
        
        home_button = QPushButton("Home")
        home_button.clicked.connect(lambda: self.path_input.setText(os.path.expanduser("~")))
        path_input_layout.addWidget(home_button, 1)
        
        documents_button = QPushButton("Documents")
        documents_button.clicked.connect(lambda: self.path_input.setText(os.path.join(os.path.expanduser("~"), "Documents")))
        path_input_layout.addWidget(documents_button, 1)
        
        downloads_button = QPushButton("Downloads")
        downloads_button.clicked.connect(lambda: self.path_input.setText(os.path.join(os.path.expanduser("~"), "Downloads")))
        path_input_layout.addWidget(downloads_button, 1)
        
        path_layout.addLayout(path_input_layout)
        
        path_validation_layout = QHBoxLayout()
        self.path_status_label = QLabel("")
        path_validation_layout.addWidget(self.path_status_label)
        
        check_path_button = QPushButton("Verify Path")
        check_path_button.clicked.connect(self.verify_path)
        path_validation_layout.addWidget(check_path_button)
        
        self.button_dict = {'verify_path': check_path_button}
        
        path_layout.addLayout(path_validation_layout)
        scan_options_layout.addLayout(path_layout)
        
        # Advanced options
        advanced_layout = QHBoxLayout()
        
        ext_layout = QHBoxLayout()
        ext_layout.addWidget(QLabel("File Extensions:"))
        self.extensions_input = QLineEdit()
        self.extensions_input.setPlaceholderText("e.g., .jpg,.png,.pdf (leave empty for all)")
        ext_layout.addWidget(self.extensions_input)
        advanced_layout.addLayout(ext_layout)
        
        size_layout = QHBoxLayout()
        size_layout.addWidget(QLabel("Min Size (KB):"))
        self.min_size_input = QSpinBox()
        self.min_size_input.setRange(0, 10000)
        self.min_size_input.setValue(1)
        size_layout.addWidget(self.min_size_input)
        advanced_layout.addLayout(size_layout)
        
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Scan Method:"))
        self.scan_method_combo = QComboBox()
        self.scan_method_combo.addItems(["Content Hash", "File Size", "Filename"])
        method_layout.addWidget(self.scan_method_combo)
        advanced_layout.addLayout(method_layout)
        
        scan_options_layout.addLayout(advanced_layout)
        
        # Scan control buttons
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        scan_options_layout.addLayout(button_layout)
        main_layout.addWidget(scan_options_group)
        
        # Progress section
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        progress_layout.addWidget(self.status_label)
        
        main_layout.addWidget(progress_group)
        
        # Results section
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Group", "Size", "Files", "Actions"])
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        results_layout.addWidget(self.results_table)
        
        # Action buttons for results
        action_layout = QHBoxLayout()
        
        self.delete_button = QPushButton("Delete Selected")
        self.delete_button.clicked.connect(self.delete_selected)
        self.delete_button.setEnabled(False)
        action_layout.addWidget(self.delete_button)
        
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        action_layout.addWidget(self.export_button)
        
        results_layout.addLayout(action_layout)
        main_layout.addWidget(results_group)
        
    def verify_path(self):
        """Verify that the entered path exists and is accessible"""
        path = self.path_input.text().strip()
        
        if not path:
            self.path_status_label.setText("Please enter a path")
            self.path_status_label.setStyleSheet("color: red")
            return
            
        if not os.path.exists(path):
            self.path_status_label.setText("Path does not exist!")
            self.path_status_label.setStyleSheet("color: red")
            return
            
        if not os.path.isdir(path):
            self.path_status_label.setText("Not a directory!")
            self.path_status_label.setStyleSheet("color: red")
            return
            
        if not os.access(path, os.R_OK):
            self.path_status_label.setText("Directory not readable!")
            self.path_status_label.setStyleSheet("color: red")
            return
            
        # Try to list contents as a test
        try:
            next(os.scandir(path))
            self.path_status_label.setText("Path is valid and accessible ✓")
            self.path_status_label.setStyleSheet("color: green")
        except (StopIteration, PermissionError, OSError) as e:
            self.path_status_label.setText(f"Warning: {str(e)}")
            self.path_status_label.setStyleSheet("color: orange")
    
    def start_scan(self):
        """Start the scanning process"""
        scan_path = self.path_input.text().strip()
        if not scan_path:
            QMessageBox.warning(self, "Invalid Path", "Please enter a directory path to scan.")
            return
            
        if not os.path.exists(scan_path) or not os.path.isdir(scan_path) or not os.access(scan_path, os.R_OK):
            QMessageBox.warning(self, "Invalid Path", "Please enter a valid and accessible directory.")
            return
            
        if self.scanner_thread and self.scanner_thread.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running.")
            return
            
        extensions_text = self.extensions_input.text().strip()
        file_extensions = [ext.strip() for ext in extensions_text.split(',')] if extensions_text else None
        min_size = self.min_size_input.value() * 1024
        
        scan_method_map = {"File Size": "size", "Filename": "name"}
        scan_method = scan_method_map.get(self.scan_method_combo.currentText(), "content")
            
        self.progress_bar.setValue(0)
        self.status_label.setText("Initializing scan...")
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.results_table.setRowCount(0)
        self.delete_button.setEnabled(False)
        self.export_button.setEnabled(False)
        
        self.scanner_thread = FileScanner(scan_path, file_extensions, min_size, scan_method)
        self.scanner_thread.progress_update.connect(self.update_progress)
        self.scanner_thread.scan_complete.connect(self.display_results)
        self.scanner_thread.start()
        
    def stop_scan(self):
        """Stop the scanning process"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.status_label.setText("Scan stopped by user.")
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
    
    def update_progress(self, percentage, message):
        """Update the progress bar and status label"""
        self.progress_bar.setValue(percentage)
        self.status_label.setText(message)
        
    def display_results(self, duplicates):
        """Display the scan results in the table"""
        self.duplicates = duplicates
        self.results_table.setRowCount(0)
        
        if not duplicates:
            self.status_label.setText("Scan complete. No duplicates found.")
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            return
            
        total_groups = len(duplicates)
        total_files = sum(len(files) - 1 for files in duplicates.values())
        total_wasted_space = sum((len(files) - 1) * files[0]['size'] for files in duplicates.values())
        
        self.status_label.setText(
            f"Scan complete. Found {total_files} duplicate files in {total_groups} groups. "
            f"Potential space savings: {self.format_size(total_wasted_space)}"
        )
        
        for row, (signature, files) in enumerate(duplicates.items()):
            if len(files) <= 1:
                continue
                
            self.results_table.insertRow(row)
            
            self.results_table.setItem(row, 0, QTableWidgetItem(f"Group {row + 1}"))
            self.results_table.setItem(row, 1, QTableWidgetItem(self.format_size(files[0]['size'])))
            
            file_paths = [f['path'] for f in files]
            files_item = QTableWidgetItem(", ".join(os.path.basename(p) for p in file_paths))
            files_item.setToolTip("\n".join(file_paths))
            self.results_table.setItem(row, 2, files_item)
            
            view_button = QPushButton("View")
            view_button.setProperty("group_id", row)
            view_button.clicked.connect(self.view_group_details)
            self.results_table.setCellWidget(row, 3, view_button)
            
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.delete_button.setEnabled(True)
        self.export_button.setEnabled(True)
        
    def view_group_details(self):
        """Show detailed view of duplicate group"""
        sender = self.sender()
        group_id = sender.property("group_id")
        
        signature = list(self.duplicates.keys())[group_id]
        files = self.duplicates[signature]
        
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Duplicate Group Details")
        
        message = f"<b>Group {group_id + 1}</b><br>"
        message += f"<b>File size:</b> {self.format_size(files[0]['size'])}<br>"
        message += f"<b>Hash/Signature:</b> {signature}<br><br>"
        message += "<b>Duplicate files:</b><br>"
        
        for i, file_info in enumerate(files):
            path = file_info['path']
            modified = datetime.fromtimestamp(file_info['modified']).strftime('%Y-%m-%d %H:%M:%S')
            message += f"{i+1}. {path}<br>   Last modified: {modified}<br>"
            
        dialog.setText(message)
        dialog.exec_()
        
    def delete_selected(self):
        """Delete selected duplicate files in batch."""
        selected_row_indices = {index.row() for index in self.results_table.selectedIndexes()}
        if not selected_row_indices:
            QMessageBox.warning(self, "No Selection", "Please select one or more duplicate groups from the results table.")
            return

        files_to_delete = []
        total_size = 0
        signatures_to_process = []
        
        all_signatures = list(self.duplicates.keys())

        for group_index in sorted(list(selected_row_indices), reverse=True):
            try:
                signature = all_signatures[group_index]
                signatures_to_process.append(signature)
                files = self.duplicates[signature]
                files_to_delete.extend([f['path'] for f in files[1:]])
                total_size += sum(f['size'] for f in files[1:])
            except (IndexError, KeyError):
                continue

        if not files_to_delete:
            QMessageBox.information(self, "No Files to Delete", "The selected groups do not have any files that can be deleted.")
            return

        msg = (
               f"You have selected {len(selected_row_indices)} groups.\n"
               f"This will delete {len(files_to_delete)} files, freeing up {self.format_size(total_size)}.\n\n"
               f"The first file in each group will be kept. This action cannot be undone.\n"
               f"Are you sure you want to proceed?")
        
        confirm = QMessageBox.warning(self, "Confirm Batch Deletion", msg,
                                   QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if confirm == QMessageBox.Yes:
            deleted_count = 0
            failed_paths = []
            error_messages = []

            for file_path in files_to_delete:
                try:
                    os.remove(file_path)
                    deleted_count += 1
                except Exception as e:
                    failed_paths.append(file_path)
                    error_messages.append(f"{file_path}: {str(e)}")

            successfully_deleted_paths = set(files_to_delete) - set(failed_paths)

            for signature in signatures_to_process:
                if signature in self.duplicates:
                    updated_files = [f for f in self.duplicates[signature] if f['path'] not in successfully_deleted_paths]
                    
                    if len(updated_files) <= 1:
                        del self.duplicates[signature]
                    else:
                        self.duplicates[signature] = updated_files

            self.display_results(self.duplicates)

            if not error_messages:
                QMessageBox.information(self, "Deletion Complete", f"Successfully deleted {deleted_count} file(s).")
            else:
                error_msg = (
                           f"Deleted {deleted_count} file(s), but failed to delete {len(error_messages)} file(s):\n\n"
                           + "\n".join(error_messages))
                QMessageBox.warning(self, "Deletion Incomplete", error_msg)
        
    def export_results(self):
        """Export scan results to CSV"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Results", "", "CSV Files (*.csv)")
        if not file_path:
            return
            
        try:
            with open(file_path, 'w') as f:
                f.write("Group,File Size,File Path,Last Modified\n")
                
                for group_id, (signature, files) in enumerate(self.duplicates.items()):
                    for file_info in files:
                        path = file_info['path']
                        size = self.format_size(file_info['size'])
                        modified = datetime.fromtimestamp(file_info['modified']).strftime('%Y-%m-%d %H:%M:%S')
                        f.write(f"{group_id + 1},{size},\"{path}\",{modified}\n")
                        
            QMessageBox.information(self, "Export Complete", f"Results exported to {file_path}")
            
        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Failed to export results: {str(e)}")
            
    def format_size(self, size_bytes):
        """Format byte size to human-readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024 or unit == 'TB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024

class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Duplicate File Finder')
        self.setGeometry(100, 100, 1000, 800)
        self.initUI()

    def initUI(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Create tab widgets
        self.duplicate_finder_tab = DuplicateFinderWidget()
        self.disk_analyzer_tab = DiskSpaceAnalyzer()
        self.disk_visualizer_tab = DiskVisualizer()

        # Add tabs
        self.tabs.addTab(self.duplicate_finder_tab, "Duplicate Finder")
        self.tabs.addTab(self.disk_analyzer_tab, "Disk Space Analyzer")
        self.tabs.addTab(self.disk_visualizer_tab, "Disk Usage Visualizer")
        
        # Create menu bar
        menubar = self.menuBar()
        tools_menu = menubar.addMenu('Tools')
        
        # Add actions to switch tabs
        switch_to_analyzer_action = QAction('Disk Space Analyzer', self)
        switch_to_analyzer_action.triggered.connect(lambda: self.tabs.setCurrentWidget(self.disk_analyzer_tab))
        tools_menu.addAction(switch_to_analyzer_action)
        
        switch_to_visualizer_action = QAction('Disk Usage Visualizer', self)
        switch_to_visualizer_action.triggered.connect(lambda: self.tabs.setCurrentWidget(self.disk_visualizer_tab))
        tools_menu.addAction(switch_to_visualizer_action)

def main():
    # Set Qt platform-specific workarounds
    if 'linux' in sys.platform:
        os.environ["QT_QPA_PLATFORM"] = "xcb"
        os.environ["QT_FILESYSTEMMODEL_WATCH_FILES"] = "0"
        
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
