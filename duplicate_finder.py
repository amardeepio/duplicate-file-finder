import sys
import os
import hashlib
import shutil
from pathlib import Path
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                            QProgressBar, QTreeWidget, QTreeWidgetItem, 
                            QCheckBox, QComboBox, QGroupBox, QLineEdit, 
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QSplitter, QMessageBox, QAction, QMenu, QSpinBox,
                            QDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QIcon, QFont

class FileScanner(QThread):
    """Worker thread for scanning files to avoid UI freezing"""
    progress_update = pyqtSignal(int, int, str)
    scan_complete = pyqtSignal(dict)
    
    def __init__(self, root_path, file_extensions=None, min_size=1024, scan_method="content"):
        super().__init__()
        self.root_path = root_path
        self.file_extensions = file_extensions
        self.min_size = min_size  # Minimum file size in bytes
        self.scan_method = scan_method  # "content", "name", or "size"
        self.running = True
        
    def run(self):
        duplicates = {}
        file_count = 0
        processed_count = 0
        
        # Instead of collecting all files at once, process them in smaller batches
        try:
            # Estimate total file count first (lightweight operation)
            self.progress_update.emit(0, 0, "Counting files...")
            total_files = self._count_files_quickly()
            self.progress_update.emit(0, total_files, f"Found approximately {total_files} files to scan")
            
            # Now process files in a streaming fashion
            for file_path in self._iter_files():
                if not self.running:
                    break
                    
                processed_count += 1
                
                try:
                    # Skip if file doesn't exist or is not accessible
                    if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                        continue
                        
                    # Skip if doesn't match extension filter
                    if self.file_extensions:
                        if not any(file_path.lower().endswith(ext.lower()) for ext in self.file_extensions):
                            continue
                    
                    # Get file size and skip if below minimum size
                    file_size = os.path.getsize(file_path)
                    if file_size < self.min_size:
                        continue
                    
                    # Update progress
                    self.progress_update.emit(processed_count, total_files, file_path)
                    
                    # Generate file signature based on scan method
                    file_signature = None
                    
                    if self.scan_method == "size":
                        file_signature = str(file_size)
                    elif self.scan_method == "name":
                        file_signature = os.path.basename(file_path)
                    else:  # content-based hash
                        file_signature = self._get_file_hash(file_path)
                    
                    # Store file info
                    if file_signature:
                        file_info = {
                            'path': file_path,
                            'size': file_size,
                            'modified': os.path.getmtime(file_path)
                        }
                        
                        if file_signature in duplicates:
                            duplicates[file_signature].append(file_info)
                        else:
                            duplicates[file_signature] = [file_info]
                
                except Exception as e:
                    print(f"Error processing {file_path}: {str(e)}")
        except Exception as e:
            print(f"Error during scan: {str(e)}")
            
        # Filter out unique files
        result = {key: files for key, files in duplicates.items() if len(files) > 1}
        self.scan_complete.emit(result)
        
    def _count_files_quickly(self):
        """Quickly estimate the number of files to process"""
        count = 0
        max_sample = 5  # Only sample a few directories to estimate
        sampled = 0
        
        try:
            # First count immediate files in root
            with os.scandir(self.root_path) as it:
                for entry in it:
                    if entry.is_file():
                        count += 1
                    
            # Then sample some subdirectories
            for root, dirs, files in os.walk(self.root_path):
                count += len(files)
                sampled += 1
                if sampled >= max_sample:
                    # Extrapolate based on remaining directories
                    remaining_dirs = sum(1 for _ in os.walk(self.root_path)) - sampled
                    avg_files_per_dir = count / (sampled + 1)  # +1 for root
                    count += int(remaining_dirs * avg_files_per_dir)
                    break
                    
        except Exception as e:
            print(f"Error estimating file count: {str(e)}")
            # Return a default value
            return 1000
            
        return max(count, 1)  # Ensure at least 1
        
    def _iter_files(self):
        """Generator that yields files one at a time, with filtering"""
        try:
            for root, _, files in os.walk(self.root_path):
                for filename in files:
                    if not self.running:
                        return
                        
                    file_path = os.path.join(root, filename)
                    
                    # Apply extension filter
                    if self.file_extensions:
                        if not any(file_path.lower().endswith(ext.lower()) for ext in self.file_extensions):
                            continue
                            
                    try:
                        # Check minimum size
                        if os.path.getsize(file_path) < self.min_size:
                            continue
                            
                        yield file_path
                        
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
                        
        except Exception as e:
            print(f"Error scanning directory: {str(e)}")
            # Just stop iteration
            return
        
    def _get_file_hash(self, file_path, chunk_size=8192):
        """Calculate MD5 hash of a file"""
        md5 = hashlib.md5()
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files efficiently
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
    
    def update_progress(self, current, total, current_file):
        """Update the progress bar and status label"""
        if total > 0:
            percentage = int((current / total) * 100)
            self.progress_bar.setValue(percentage)
            
        # Truncate path if too long
        if len(current_file) > 60:
            display_path = "..." + current_file[-57:]
        else:
            display_path = current_file
            
        self.status_label.setText(f"Scanning: {current}/{total} - {display_path}")
        
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
        """Delete selected duplicate files"""
        # Get the current selected row in the results table
        selected_rows = self.results_table.selectedIndexes()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a duplicate group from the results table.")
            return
            
        # Get the group ID from the first selected cell's row
        group_id = selected_rows[0].row()
        
        # Get the duplicate group
        try:
            signature = list(self.duplicates.keys())[group_id]
            files = self.duplicates[signature]
        except (IndexError, KeyError):
            QMessageBox.warning(self, "Invalid Selection", "Could not find the selected duplicate group.")
            return
            
        # Create a dialog to let user select which files to delete
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Files to Delete")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(400)
        
        layout = QVBoxLayout(dialog)
        
        # Add instructions
        layout.addWidget(QLabel("Select the files you want to delete. Keep at least one file."))
        
        # Add file list with checkboxes
        file_list = QTreeWidget()
        file_list.setHeaderLabels(["Select", "File Path", "Size", "Last Modified"])
        file_list.setColumnWidth(0, 60)
        file_list.setColumnWidth(1, 300)
        
        # Track checkboxes for later access
        checkboxes = []
        
        # Add each file as an item with a checkbox
        for i, file_info in enumerate(files):
            item = QTreeWidgetItem(file_list)
            
            # Create a checkbox in the first column
            checkbox = QCheckBox()
            # Check all except the first file by default
            if i > 0:
                checkbox.setChecked(True)
            checkboxes.append(checkbox)
            file_list.setItemWidget(item, 0, checkbox)
            
            # File path, size, and date
            item.setText(1, file_info['path'])
            item.setText(2, self.format_size(file_info['size']))
            date = datetime.fromtimestamp(file_info['modified']).strftime('%Y-%m-%d %H:%M:%S')
            item.setText(3, date)
            
        layout.addWidget(file_list)
        
        # Add action buttons
        button_layout = QHBoxLayout()
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_button)
        
        delete_button = QPushButton("Delete Selected")
        delete_button.clicked.connect(dialog.accept)
        button_layout.addWidget(delete_button)
        
        layout.addLayout(button_layout)
        
        # Show the dialog and process the result
        if dialog.exec_() == QDialog.Accepted:
            files_to_delete = []
            all_checked = True
            
            # Check which files were selected for deletion
            for i, checkbox in enumerate(checkboxes):
                if checkbox.isChecked():
                    files_to_delete.append(files[i]['path'])
                else:
                    all_checked = False
            
            # Don't allow deleting all files
            if all_checked:
                QMessageBox.warning(self, "Invalid Selection", "You must keep at least one file.")
                return
                
            # Confirm deletion
            count = len(files_to_delete)
            if count == 0:
                QMessageBox.information(self, "No Files Selected", "No files were selected for deletion.")
                return
                
            msg = f"Are you sure you want to delete {count} file(s)?\n\nThis action cannot be undone!"
            confirm = QMessageBox.warning(self, "Confirm Deletion", msg, 
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                                       
            if confirm == QMessageBox.Yes:
                # Perform deletion
                deleted_count = 0
                failed_count = 0
                failed_files = []
                
                for file_path in files_to_delete:
                    try:
                        os.remove(file_path)
                        deleted_count += 1
                    except Exception as e:
                        failed_count += 1
                        failed_files.append(f"{file_path}: {str(e)}")
                
                # Show results
                if failed_count == 0:
                    QMessageBox.information(self, "Deletion Complete", 
                                         f"Successfully deleted {deleted_count} file(s).")
                    
                    # Update the results by removing the deleted files
                    updated_files = [f for f in files if f['path'] not in files_to_delete]
                    
                    # If only one file remains, remove this group from duplicates
                    if len(updated_files) <= 1:
                        del self.duplicates[signature]
                    else:
                        self.duplicates[signature] = updated_files
                        
                    # Refresh the results table
                    self.display_results(self.duplicates)
                else:
                    error_msg = f"Deleted {deleted_count} file(s), but {failed_count} file(s) could not be deleted:\n\n"
                    error_msg += "\n".join(failed_files)
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