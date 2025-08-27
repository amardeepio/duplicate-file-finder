import sys
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
                            QDialog, QAbstractItemView)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QIcon, QFont

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
        """Scan for duplicates by file content (size -> hash)."""
        sizes = {}
        processed_count = 0
        total_files = self._count_files_quickly()
        self.progress_update.emit(0, "Pass 1/2: Grouping by size...")

        for file_path, file_size in self._iter_files():
            if not self.running:
                return
            processed_count += 1
            if processed_count % 20 == 0 or processed_count == total_files:
                percentage = int((processed_count / total_files) * 70)
                self.progress_update.emit(percentage, f"Pass 1/2: Analyzing sizes... {self._truncate_path(file_path)}")

            if file_size in sizes:
                sizes[file_size].append(file_path)
            else:
                sizes[file_size] = [file_path]

        duplicates = {}
        potential_duplicates = {size: paths for size, paths in sizes.items() if len(paths) > 1}
        
        total_to_hash = sum(len(paths) for paths in potential_duplicates.values())
        if total_to_hash == 0:
            self.progress_update.emit(100, "Scan complete. No duplicates found.")
            self.scan_complete.emit({})
            return

        hashed_count = 0
        self.progress_update.emit(70, "Pass 2/2: Hashing potential duplicates...")

        for size, paths in potential_duplicates.items():
            if not self.running:
                break
            for file_path in paths:
                if not self.running:
                    break
                
                hashed_count += 1
                percentage = 70 + int((hashed_count / total_to_hash) * 30)
                self.progress_update.emit(percentage, f"Pass 2/2: Hashing... {self._truncate_path(file_path)}")

                file_hash = self._get_file_hash(file_path)
                if file_hash:
                    try:
                        file_info = {'path': file_path, 'size': size, 'modified': os.path.getmtime(file_path)}
                        if file_hash in duplicates:
                            duplicates[file_hash].append(file_info)
                        else:
                            duplicates[file_hash] = [file_info]
                    except OSError:
                        continue
        
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

    def _get_file_hash(self, file_path, chunk_size=8192):
        """Calculate MD5 hash of a file."""
        md5 = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(chunk_size), b''):
                    if not self.running:
                        return None
                    md5.update(chunk)
            return md5.hexdigest()
        except Exception as e:
            print(f"Error hashing {file_path}: {str(e)}")
            return None

    def stop(self):
        self.running = False


class DuplicateFinderApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scanner_thread = None
        self.duplicates = {}
        self.initUI()
        
    def initUI(self):
        # Set window properties
        self.setWindowTitle('Duplicate File Finder')
        self.setGeometry(100, 100, 900, 600)
        
        # Create menu bar
        menubar = self.menuBar()
        tools_menu = menubar.addMenu('Tools')
        
        # Add disk analyzer action
        disk_analyzer_action = QAction('Disk Space Analyzer', self)
        disk_analyzer_action.triggered.connect(self.launch_disk_analyzer)
        tools_menu.addAction(disk_analyzer_action)
        
        # Add disk visualizer action
        visualizer_action = QAction('Disk Usage Visualizer', self)
        visualizer_action.triggered.connect(self.launch_disk_visualizer)
        tools_menu.addAction(visualizer_action)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create scan options group
        scan_options_group = QGroupBox("Scan Options")
        scan_options_layout = QVBoxLayout(scan_options_group)
        
        # Path selection - SIMPLIFIED to avoid freezing
        path_layout = QVBoxLayout()
        path_layout.addWidget(QLabel("Enter the full path to scan:"))
        
        # Create a horizontal layout for path input and examples
        path_input_layout = QHBoxLayout()
        
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("e.g., /home/user/Documents")
        path_input_layout.addWidget(self.path_input, 3)
        
        # Add some quick access buttons for common directories
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
        
        # Add path validation
        path_validation_layout = QHBoxLayout()
        self.path_status_label = QLabel("")
        path_validation_layout.addWidget(self.path_status_label)
        
        check_path_button = QPushButton("Verify Path")
        check_path_button.clicked.connect(self.verify_path)
        path_validation_layout.addWidget(check_path_button)
        
        # Dictionary to store references to buttons for easy access in tests
        self.button_dict = {
            'verify_path': check_path_button
        }
        
        path_layout.addLayout(path_validation_layout)
        scan_options_layout.addLayout(path_layout)
        
        # Advanced options
        advanced_layout = QHBoxLayout()
        
        # File extension filter
        ext_layout = QHBoxLayout()
        ext_layout.addWidget(QLabel("File Extensions:"))
        self.extensions_input = QLineEdit()
        self.extensions_input.setPlaceholderText("e.g., .jpg,.png,.pdf (leave empty for all)")
        ext_layout.addWidget(self.extensions_input)
        advanced_layout.addLayout(ext_layout)
        
        # Min file size
        size_layout = QHBoxLayout()
        size_layout.addWidget(QLabel("Min Size (KB):"))
        self.min_size_input = QSpinBox()
        self.min_size_input.setRange(0, 10000)
        self.min_size_input.setValue(1)
        size_layout.addWidget(self.min_size_input)
        advanced_layout.addLayout(size_layout)
        
        # Scan method
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
        
        # Add disk analyzer button
        disk_analyzer_button = QPushButton("Disk Space Analyzer")
        disk_analyzer_button.clicked.connect(self.launch_disk_analyzer)
        action_layout.addWidget(disk_analyzer_button)
        
        # Add disk visualizer button
        visualizer_button = QPushButton("Disk Visualizer")
        visualizer_button.clicked.connect(self.launch_disk_visualizer)
        action_layout.addWidget(visualizer_button)
        
        results_layout.addLayout(action_layout)
        main_layout.addWidget(results_group)
        
    def launch_disk_analyzer(self):
        """Launch the Disk Space Analyzer application"""
        try:
            # Get the path to the disk_space_analyzer.py file
            analyzer_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "disk_space_analyzer.py")
            
            # Launch the analyzer as a separate process
            subprocess.Popen(["python3", analyzer_path])
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not launch Disk Space Analyzer: {str(e)}")
    
    def launch_disk_visualizer(self):
        """Launch the Disk Usage Visualizer"""
        try:
            # Get the path to the disk_visualizer.py file
            visualizer_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "disk_visualizer.py")
            
            # Launch the visualizer as a separate process
            subprocess.Popen(["python3", visualizer_path])
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not launch Disk Visualizer: {str(e)}")
        
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
        # Get scan path
        scan_path = self.path_input.text().strip()
        if not scan_path:
            QMessageBox.warning(self, "Invalid Path", "Please enter a directory path to scan.")
            return
            
        # Verify path exists and is accessible
        if not os.path.exists(scan_path):
            QMessageBox.warning(self, "Invalid Path", "The specified directory does not exist.")
            return
            
        if not os.path.isdir(scan_path):
            QMessageBox.warning(self, "Invalid Path", "The specified path is not a directory.")
            return
            
        if not os.access(scan_path, os.R_OK):
            QMessageBox.warning(self, "Invalid Path", "Cannot read the specified directory. Check permissions.")
            return
            
        # Check if a scan is already running
        if self.scanner_thread and self.scanner_thread.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running. Please wait or stop it first.")
            return
            
        # Get scan options
        extensions_text = self.extensions_input.text().strip()
        file_extensions = None
        if extensions_text:
            file_extensions = [ext.strip() for ext in extensions_text.split(',')]
            
        min_size = self.min_size_input.value() * 1024  # Convert KB to bytes
        
        scan_method_text = self.scan_method_combo.currentText()
        scan_method = "content"
        if scan_method_text == "File Size":
            scan_method = "size"
        elif scan_method_text == "Filename":
            scan_method = "name"
            
        # Update UI
        self.progress_bar.setValue(0)
        self.status_label.setText("Initializing scan...")
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.results_table.setRowCount(0)
        self.delete_button.setEnabled(False)
        self.export_button.setEnabled(False)
        
        # Start scanner thread
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
            
        # Count total duplicates and space
        total_groups = len(duplicates)
        total_files = sum(len(files) - 1 for files in duplicates.values())
        total_wasted_space = sum((len(files) - 1) * files[0]['size'] for files in duplicates.values())
        
        # Update status
        self.status_label.setText(
            f"Scan complete. Found {total_files} duplicate files in {total_groups} groups. "
            f"Potential space savings: {self.format_size(total_wasted_space)}"
        )
        
        # Populate table
        row = 0
        for signature, files in duplicates.items():
            # Skip if not actual duplicates
            if len(files) <= 1:
                continue
                
            self.results_table.insertRow(row)
            
            # Group number
            group_item = QTableWidgetItem(f"Group {row + 1}")
            self.results_table.setItem(row, 0, group_item)
            
            # File size
            size_item = QTableWidgetItem(self.format_size(files[0]['size']))
            self.results_table.setItem(row, 1, size_item)
            
            # File list
            file_paths = [f['path'] for f in files]
            files_item = QTableWidgetItem(", ".join(os.path.basename(p) for p in file_paths))
            files_item.setToolTip("\n".join(file_paths))
            self.results_table.setItem(row, 2, files_item)
            
            # Actions
            view_button = QPushButton("View")
            view_button.setProperty("group_id", row)
            view_button.clicked.connect(self.view_group_details)
            self.results_table.setCellWidget(row, 3, view_button)
            
            row += 1
            
        # Enable action buttons
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.delete_button.setEnabled(True)
        self.export_button.setEnabled(True)
        
    def view_group_details(self):
        """Show detailed view of duplicate group"""
        sender = self.sender()
        group_id = sender.property("group_id")
        
        # Get the duplicate group
        signature = list(self.duplicates.keys())[group_id]
        files = self.duplicates[signature]
        
        # Create a dialog to display details
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Duplicate Group Details")
        
        # Create message with file details
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
                # Keep the first file, delete the rest
                files_to_delete.extend([f['path'] for f in files[1:]])
                total_size += sum(f['size'] for f in files[1:])
            except (IndexError, KeyError):
                continue

        if not files_to_delete:
            QMessageBox.information(self, "No Files to Delete", "The selected groups do not have any files that can be deleted (e.g., only one file in each group).")
            return

        msg = (f"You have selected {len(selected_row_indices)} groups.\n" 
               f"This will delete {len(files_to_delete)} files, freeing up {self.format_size(total_size)}.\n\n" 
               "A default of keeping the first file and deleting the rest will be applied.\n" 
               "This action cannot be undone. Are you sure you want to proceed?")
        
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

            # Update the data model
            successfully_deleted_paths = set(files_to_delete) - set(failed_paths)

            for signature in signatures_to_process:
                if signature in self.duplicates:
                    updated_files = [f for f in self.duplicates[signature] if f['path'] not in successfully_deleted_paths]
                    
                    if len(updated_files) <= 1:
                        del self.duplicates[signature]
                    else:
                        self.duplicates[signature] = updated_files

            # Refresh the results table
            self.display_results(self.duplicates)

            # Show results
            if not error_messages:
                QMessageBox.information(self, "Deletion Complete",
                                     f"Successfully deleted {deleted_count} file(s).")
            else:
                error_msg = (f"Deleted {deleted_count} file(s), but failed to delete {len(error_messages)} file(s):\n\n" 
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


def main():
    # Set Qt platform-specific workarounds
    if 'linux' in sys.platform:
        # Fix for Wayland issues
        os.environ["QT_QPA_PLATFORM"] = "xcb"
        
        # Fix for file dialog issues on Linux
        os.environ["QT_FILESYSTEMMODEL_WATCH_FILES"] = "0"
        
    app = QApplication(sys.argv)
    window = DuplicateFinderApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()