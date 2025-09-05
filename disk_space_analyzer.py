import os
import sys
import shutil
import psutil
import heapq
from datetime import datetime
from pathlib import Path
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                            QPushButton, QLabel, QProgressBar, 
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QComboBox, QMessageBox, QFileDialog, QGroupBox,
                            QLineEdit, QApplication)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor

class FileSizeScanner(QThread):
    """Worker thread for finding large files"""
    progress_update = pyqtSignal(int, int, str)
    scan_complete = pyqtSignal(list)
    
    def __init__(self, root_path, min_size=10*1024, max_files=100):
        super().__init__()
        self.root_path = root_path
        self.min_size = min_size  # Minimum file size in bytes (default: 10KB to catch more files)
        self.max_files = max_files # Maximum number of files to return
        self.running = True
        
    def run(self):
        largest_files = []
        file_count = 0
        processed_count = 0
        
        try:
            # First pass to get approximate file count
            self.progress_update.emit(0, 0, "Counting files...")
            total_files = 0
            for _, _, files in os.walk(self.root_path):
                total_files += len(files)
                # Avoid counting too many files which can slow down the scan
                if total_files > 10000:
                    break
                    
            self.progress_update.emit(0, total_files, f"Found approximately {total_files} files to scan")
            
            # Use a list to collect all files first, then sort
            all_files = []
            
            for root, _, files in os.walk(self.root_path):
                if not self.running:
                    break
                    
                for filename in files:
                    if not self.running:
                        break
                        
                    processed_count += 1
                    file_path = os.path.join(root, filename)
                    
                    # Update progress periodically
                    if processed_count % 100 == 0:
                        self.progress_update.emit(processed_count, total_files, file_path)
                    
                    try:
                        # Skip if file doesn't exist or is inaccessible
                        if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                            continue
                            
                        # Get file size
                        file_size = os.path.getsize(file_path)
                        
                        # Skip small files - use a very small minimum to catch more files
                        if file_size < self.min_size:
                            continue
                            
                        # Store file with its size
                        all_files.append((file_path, file_size))
                            
                    except (PermissionError, OSError) as e:
                        # Skip files we can't access
                        continue
            
            # Sort files by size (largest first)
            all_files.sort(key=lambda x: x[1], reverse=True)
            
            # Keep only the top N files
            result = all_files[:self.max_files]
            
            # Debug output
            print(f"Found {len(result)} files. Largest files:")
            for i, (path, size) in enumerate(result[:5]):
                print(f"{i+1}. {path}: {size} bytes ({self.format_size(size)})")
                
            # Final progress update
            self.progress_update.emit(processed_count, total_files, "Completed")
            self.scan_complete.emit(result)
            
        except Exception as e:
            print(f"Error scanning for large files: {str(e)}")
            self.scan_complete.emit([])
            
    def stop(self):
        self.running = False
        
    def format_size(self, size_bytes):
        """Format byte size to human-readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024 or unit == 'TB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024


class DiskSpaceAnalyzer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner_thread = None
        self.initUI()
        self.update_disk_info()
        
    def initUI(self):
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Disk Space Information Section
        disk_info_group = QGroupBox("Disk Space Information")
        disk_info_layout = QVBoxLayout(disk_info_group)
        
        # Drive selection
        drive_layout = QHBoxLayout()
        drive_layout.addWidget(QLabel("Select Drive:"))
        self.drive_combo = QComboBox()
        self.populate_drives()
        self.drive_combo.currentIndexChanged.connect(self.update_disk_info)
        drive_layout.addWidget(self.drive_combo)
        drive_layout.addStretch()
        
        # Refresh button
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.update_disk_info)
        drive_layout.addWidget(refresh_button)
        
        disk_info_layout.addLayout(drive_layout)
        
        # Disk space visualization
        space_layout = QHBoxLayout()
        
        # Used space
        used_layout = QVBoxLayout()
        used_layout.addWidget(QLabel("Used Space:"))
        self.used_label = QLabel("0 GB")
        self.used_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        used_layout.addWidget(self.used_label)
        space_layout.addLayout(used_layout)
        
        # Free space
        free_layout = QVBoxLayout()
        free_layout.addWidget(QLabel("Free Space:"))
        self.free_label = QLabel("0 GB")
        self.free_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        free_layout.addWidget(self.free_label)
        space_layout.addLayout(free_layout)
        
        # Total space
        total_layout = QVBoxLayout()
        total_layout.addWidget(QLabel("Total Space:"))
        self.total_label = QLabel("0 GB")
        self.total_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        total_layout.addWidget(self.total_label)
        space_layout.addLayout(total_layout)
        
        disk_info_layout.addLayout(space_layout)
        
        # Progress bar for disk usage
        disk_info_layout.addWidget(QLabel("Disk Usage:"))
        self.disk_progress = QProgressBar()
        self.disk_progress.setTextVisible(True)
        disk_info_layout.addWidget(self.disk_progress)
        
        main_layout.addWidget(disk_info_group)
        
        # Large Files Section
        large_files_group = QGroupBox("Largest Files")
        large_files_layout = QVBoxLayout(large_files_group)
        
        # Path selection
        path_layout = QVBoxLayout()
        path_layout.addWidget(QLabel("Enter the full path to scan:"))
        
        # Create a horizontal layout for path input and examples
        path_input_layout = QHBoxLayout()
        
        self.path_input = QLineEdit()
        self.path_input.setText(os.path.expanduser("~"))  # Default to home directory
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
        
        path_layout.addLayout(path_validation_layout)
        
        large_files_layout.addLayout(path_layout)
        
        # Scan controls
        control_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Find Largest Files")
        self.scan_button.clicked.connect(self.start_scan)
        control_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.stop_button)
        
        # Number of files to show
        control_layout.addWidget(QLabel("Show top:"))
        self.top_combo = QComboBox()
        self.top_combo.addItems(["10", "20", "50", "100"])
        self.top_combo.setCurrentIndex(1)  # Default to 20
        control_layout.addWidget(self.top_combo)
        
        large_files_layout.addLayout(control_layout)
        
        # Progress
        self.scan_progress = QProgressBar()
        large_files_layout.addWidget(self.scan_progress)
        
        self.status_label = QLabel("Ready")
        large_files_layout.addWidget(self.status_label)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["File Name", "Path", "Size", "Last Modified"])
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        large_files_layout.addWidget(self.results_table)
        
        main_layout.addWidget(large_files_group)

        # Add Delete Selected button
        self.delete_button = QPushButton("Delete Selected")
        self.delete_button.clicked.connect(self.delete_selected_files)
        self.delete_button.setEnabled(False)  # Disabled by default
        control_layout.addWidget(self.delete_button)
    
    def populate_drives(self):
        """Populate the drive selection combobox"""
        self.drive_combo.clear()
        
        # Get all disk partitions
        partitions = psutil.disk_partitions()
        
        for p in partitions:
            # Skip CD-ROM drives on Windows which may not be ready
            if 'cdrom' in p.opts or p.fstype == '' and sys.platform == 'win32':
                continue
            self.drive_combo.addItem(f"{p.mountpoint} ({p.device})", p.mountpoint)
    
    def update_disk_info(self):
        """Update the disk space information"""
        try:
            # Get the selected drive
            selected_drive = self.drive_combo.currentData()
            if not selected_drive:
                return
                
            # Get disk usage
            usage = shutil.disk_usage(selected_drive)
            
            # Convert to GB for display
            total_gb = usage.total / (1024**3)
            used_gb = usage.used / (1024**3)
            free_gb = usage.free / (1024**3)
            
            # Update labels
            self.total_label.setText(f"{total_gb:.2f} GB")
            self.used_label.setText(f"{used_gb:.2f} GB")
            self.free_label.setText(f"{free_gb:.2f} GB")
            
            # Update progress bar
            percent_used = (usage.used / usage.total) * 100
            self.disk_progress.setValue(int(percent_used))
            self.disk_progress.setFormat(f"{percent_used:.1f}% used")
            
            # Set color based on space left
            if percent_used > 90:
                self.disk_progress.setStyleSheet("QProgressBar::chunk { background-color: #FF5555; }")
            elif percent_used > 75:
                self.disk_progress.setStyleSheet("QProgressBar::chunk { background-color: #FFAA55; }")
            else:
                self.disk_progress.setStyleSheet("QProgressBar::chunk { background-color: #55AA55; }")
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not get disk information: {str(e)}")
    
    def verify_path(self):
        """Verify that the entered path exists and is accessible"""
        path = self.path_input.text().strip()
        
        if not path:
            self.path_status_label.setText("Please enter a path")
            self.path_status_label.setStyleSheet("color: red")
            return False
            
        if not os.path.exists(path):
            self.path_status_label.setText("Path does not exist!")
            self.path_status_label.setStyleSheet("color: red")
            return False
            
        if not os.path.isdir(path):
            self.path_status_label.setText("Not a directory!")
            self.path_status_label.setStyleSheet("color: red")
            return False
            
        if not os.access(path, os.R_OK):
            self.path_status_label.setText("Directory not readable!")
            self.path_status_label.setStyleSheet("color: red")
            return False
            
        # Try to list contents as a test
        try:
            next(os.scandir(path))
            self.path_status_label.setText("Path is valid and accessible ✓")
            self.path_status_label.setStyleSheet("color: green")
            return True
        except (StopIteration, PermissionError, OSError) as e:
            self.path_status_label.setText(f"Warning: {str(e)}")
            self.path_status_label.setStyleSheet("color: orange")
            return True  # Still return True if directory is empty
            
    def browse_directory(self):
        """This method is no longer used but kept for compatibility"""
        pass
    
    def start_scan(self):
        """Start scanning for large files"""
        scan_path = self.path_input.text().strip()
        if not scan_path:
            QMessageBox.warning(self, "Invalid Path", "Please enter a directory path to scan.")
            return
            
        # Verify path exists and is accessible
        if not self.verify_path():
            QMessageBox.warning(self, "Invalid Path", "Please select a valid and accessible directory.")
            return
            
        # Check if scan is already running
        if self.scanner_thread and self.scanner_thread.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running.")
            return
            
        # Get max files from combo box
        max_files = int(self.top_combo.currentText())
        
        # Update UI
        self.scan_progress.setValue(0)
        self.status_label.setText("Scanning...")
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.results_table.setRowCount(0)
        
        # Start scanner thread - use a smaller minimum size to catch more files
        self.scanner_thread = FileSizeScanner(scan_path, min_size=1024, max_files=max_files)
        self.scanner_thread.progress_update.connect(self.update_scan_progress)
        self.scanner_thread.scan_complete.connect(self.display_large_files)
        self.scanner_thread.start()
    
    def stop_scan(self):
        """Stop the scanning process"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.status_label.setText("Scan stopped by user.")
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
    
    def update_scan_progress(self, current, total, current_file):
        """Update the progress display"""
        if total > 0:
            percentage = int((current / total) * 100)
            self.scan_progress.setValue(percentage)
            
        # Show current file being processed (truncate if too long)
        if len(current_file) > 60:
            display_path = "..." + current_file[-57:]
        else:
            display_path = current_file
            
        self.status_label.setText(f"Scanning: {current}/{total} - {display_path}")
    
    def display_large_files(self, file_list):
        """Display the list of largest files"""
        self.results_table.setRowCount(0)
        
        if not file_list:
            self.status_label.setText("Scan complete. No files found.")
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            return
            
        # Update status
        self.status_label.setText(f"Scan complete. Found {len(file_list)} large files.")
        
        # Add files to table
        for i, (file_path, file_size) in enumerate(file_list):
            self.results_table.insertRow(i)
            
            # File name
            file_name = os.path.basename(file_path)
            self.results_table.setItem(i, 0, QTableWidgetItem(file_name))
            
            # File path (parent directory)
            parent_dir = os.path.dirname(file_path)
            path_item = QTableWidgetItem(parent_dir)
            path_item.setToolTip(file_path)  # Show full path on hover
            self.results_table.setItem(i, 1, path_item)
            
            # File size - ensure we're using the actual file size
            size_str = self.format_size(file_size)
            size_item = QTableWidgetItem(size_str)
            # Store raw size for sorting
            size_item.setData(Qt.UserRole, file_size)
            self.results_table.setItem(i, 2, size_item)
            
            # Last modified date
            try:
                mod_time = os.path.getmtime(file_path)
                date_str = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
                self.results_table.setItem(i, 3, QTableWidgetItem(date_str))
            except (OSError, PermissionError):
                self.results_table.setItem(i, 3, QTableWidgetItem("Unknown"))
        
        # Resize columns to content
        self.results_table.resizeColumnsToContents()
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        
        # Enable scan button and disable stop button
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        # Color code rows based on size
        self.color_code_rows()

        # Enable delete button if files are found
        self.delete_button.setEnabled(len(file_list) > 0)
    
    def delete_selected_files(self):
        """Delete the selected files from the resuls table"""
        selected_rows = set(index.row() for index in self.results_table.selectedIndexes())
        if not selected_rows:
            QMessageBox.warning(self, "No Files Selected", "Please select at least one file to delete.")
            return
        
        # confirm deletion
        confirm = QMessageBox.question(

            self,
            "Delete Files",
            "Are you sure you want to delete the selected files?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if confirm != QMessageBox.Yes:
            return
        
        # Sort rows in reverse order to avoid index shifting issues
        sorted_rows = sorted(selected_rows, reverse=True)
        deleted_files = []
        failed_deletions= []
        for row in sorted_rows:
                file_path = self.results_table.item(row, 1).toolTip()
                try:
                    os.remove(file_path)
                    deleted_files.append(file_path)
                    self.results_table.removeRow(row)
                except Exception as e:
                    failed_deletions.append(f"{file_path}: {str(e)}")
        # show results

        if deleted_files:
            QMessageBox.information(self, "Files Deleted", f"Deleted {len(deleted_files)} files.")
        if failed_deletions:
            QMessageBox.warning(self, "Failed Deletions", f"Failed to delete {len(failed_deletions)} files:\n{', '.join(failed_deletions)}")

        # Update status 
        self.status_label.setText(f"Deleted {len(deleted_files)} files.")

        # disable delete button if no rows left
        if self.results_table.rowCount() == 0:
            self.delete_button.setEnabled(False)

    
    def color_code_rows(self):
        """Color code rows with a gradient based on file size, independent of sorting."""
        sizes = []
        for i in range(self.results_table.rowCount()):
            size_item = self.results_table.item(i, 2)
            if size_item:
                size = size_item.data(Qt.UserRole)
                if size is not None:
                    sizes.append(size)
        
        if not sizes:
            return

        min_size = min(sizes)
        max_size = max(sizes)
        size_range = max_size - min_size

        # Define the gradient colors
        start_color = QColor(255, 255, 224)  # Light Yellow
        end_color = QColor(255, 182, 193)    # Light Red

        for i in range(self.results_table.rowCount()):
            size_item = self.results_table.item(i, 2)
            if not size_item:
                continue
            
            size = size_item.data(Qt.UserRole)
            if size is None:
                continue

            # Calculate the ratio to determine color
            if size_range == 0:
                ratio = 1.0
            else:
                ratio = (size - min_size) / size_range

            # Linear interpolation between start and end colors
            r = int(start_color.red() + ratio * (end_color.red() - start_color.red()))
            g = int(start_color.green() + ratio * (end_color.green() - start_color.green()))
            b = int(start_color.blue() + ratio * (end_color.blue() - start_color.blue()))
            
            color = QColor(r, g, b)

            for j in range(self.results_table.columnCount()):
                # Ensure item exists before setting background
                if self.results_table.item(i, j):
                    self.results_table.item(i, j).setBackground(color)
                    self.results_table.item(i, j).setForeground(QColor('black'))
    
    def format_size(self, size_bytes):
        """Format byte size to human-readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024 or unit == 'TB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024


# If run directly, show a simple demo
if __name__ == '__main__':
    # Set Qt platform-specific workarounds
    if 'linux' in sys.platform:
        # Fix for Wayland issues
        os.environ["QT_QPA_PLATFORM"] = "xcb"
        
        # Fix for file dialog issues on Linux
        os.environ["QT_FILESYSTEMMODEL_WATCH_FILES"] = "0"
    
    app = QApplication(sys.argv)
    window = DiskSpaceAnalyzer()
    window.setWindowTitle("Disk Space Analyzer")
    window.setGeometry(100, 100, 800, 600)
    window.show()
    sys.exit(app.exec_())