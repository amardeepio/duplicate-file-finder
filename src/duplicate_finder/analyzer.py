import os
import sys
import shutil
import psutil
import heapq
import threading
from datetime import datetime
from pathlib import Path
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QComboBox, QMessageBox, QFileDialog, QGroupBox,
    QLineEdit, QApplication, QTabWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor

class AtomicCounter:
    def __init__(self, initial=0):
        self._value = initial
        self._lock = threading.Lock()

    def increment(self, delta=1):
        with self._lock:
            self._value += delta
            return self._value

    def value(self):
        with self._lock:
            return self._value

class FolderScanner(QThread):
    """Worker thread for finding large folders"""
    progress_update = pyqtSignal(int, int, str)
    scan_complete = pyqtSignal(list)
    
    def __init__(self, root_path, max_folders=100, max_depth=10):
        super().__init__()
        self.root_path = root_path
        self.max_folders = max_folders
        self.max_depth = max_depth
        self.running = True
        self.directories = {}
        self.directory_errors = []

    def run(self):
        try:
            total_items = self._count_items(self.root_path)
            processed = AtomicCounter(0)
            
            self._scan_directory(self.root_path, 0, total_items, processed)
            
            sorted_folders = sorted(self.directories.items(), key=lambda item: item[1], reverse=True)
            
            self.progress_update.emit(100, 100, "Scan complete!")
            self.scan_complete.emit(sorted_folders[:self.max_folders])
            
        except Exception as e:
            print(f"Critical error during folder scan: {str(e)}")
            self.scan_complete.emit([])

    def _count_items(self, directory):
        """Count files and directories for progress tracking"""
        count = 0
        try:
            for root, dirs, files in os.walk(directory):
                if not self.running:
                    break
                count += len(dirs) + len(files)
                if count > 50000: # Safety break for very large directories
                    break
        except Exception as e:
            print(f"Error counting items: {str(e)}")
            return 1000
        return max(1, count)

    def _scan_directory(self, directory, current_depth, total_items, processed_counter):
        """Recursively scan directory and calculate sizes accurately"""
        if current_depth > self.max_depth or not self.running:
            return 0
        
        total_size = 0
        
        try:
            entries = list(os.scandir(directory))
            dir_size = 0
            
            for entry in entries:
                if not self.running:
                    return 0
                
                processed_counter.increment()
                progress = min(99, int((processed_counter.value() / total_items) * 100))
                if processed_counter.value() % 100 == 0:
                    self.progress_update.emit(progress, total_items, f"Scanning: {entry.path}")

                if entry.is_file(follow_symlinks=False):
                    try:
                        file_size = entry.stat(follow_symlinks=False).st_size
                        total_size += file_size
                        dir_size += file_size
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
            
            for entry in entries:
                if not self.running:
                    break
                if entry.is_dir(follow_symlinks=False):
                    try:
                        subdir_size = self._scan_directory(
                            entry.path, current_depth + 1, total_items, processed_counter
                        )
                        total_size += subdir_size
                        dir_size += subdir_size
                    except (PermissionError, FileNotFoundError, OSError) as e:
                        self.directory_errors.append(f"Error with directory {entry.path}: {str(e)}")

            self.directories[directory] = dir_size
            
        except (PermissionError, FileNotFoundError, OSError) as e:
            self.directory_errors.append(f"Error accessing directory {directory}: {str(e)}")
            
        return total_size

    def stop(self):
        self.running = False

class FileSizeScanner(QThread):
    """Worker thread for finding large files"""
    progress_update = pyqtSignal(int, int, str)
    scan_complete = pyqtSignal(list)
    
    def __init__(self, root_path, min_size=10*1024, max_files=100):
        super().__init__()
        self.root_path = root_path
        self.min_size = min_size
        self.max_files = max_files
        self.running = True
        
    def run(self):
        all_files = []
        processed_count = 0
        
        try:
            self.progress_update.emit(0, 0, "Counting files...")
            total_files = sum(len(files) for _, _, files in os.walk(self.root_path))
            self.progress_update.emit(0, total_files, f"Found approximately {total_files} files to scan")
            
            for root, _, files in os.walk(self.root_path):
                if not self.running:
                    break
                for filename in files:
                    if not self.running:
                        break
                    processed_count += 1
                    file_path = os.path.join(root, filename)
                    if processed_count % 100 == 0:
                        self.progress_update.emit(processed_count, total_files, file_path)
                    try:
                        if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                            continue
                        file_size = os.path.getsize(file_path)
                        if file_size >= self.min_size:
                            all_files.append((file_path, file_size))
                    except (PermissionError, OSError):
                        continue
            
            all_files.sort(key=lambda x: x[1], reverse=True)
            result = all_files[:self.max_files]
            self.progress_update.emit(processed_count, total_files, "Completed")
            self.scan_complete.emit(result)
        except Exception as e:
            print(f"Error scanning for large files: {str(e)}")
            self.scan_complete.emit([])
            
    def stop(self):
        self.running = False
        
    def format_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024 or unit == 'TB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024


class DiskSpaceAnalyzer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner_thread = None
        self.folder_scanner_thread = None
        self.initUI()
        self.update_disk_info()
        
    def initUI(self):
        main_layout = QVBoxLayout(self)
        
        disk_info_group = QGroupBox("Disk Space Information")
        disk_info_layout = QVBoxLayout(disk_info_group)
        
        drive_layout = QHBoxLayout()
        drive_layout.addWidget(QLabel("Select Drive:"))
        self.drive_combo = QComboBox()
        self.populate_drives()
        self.drive_combo.currentIndexChanged.connect(self.update_disk_info)
        drive_layout.addWidget(self.drive_combo)
        drive_layout.addStretch()
        
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.update_disk_info)
        drive_layout.addWidget(refresh_button)
        disk_info_layout.addLayout(drive_layout)
        
        space_layout = QHBoxLayout()
        used_layout = QVBoxLayout()
        used_layout.addWidget(QLabel("Used Space:"))
        self.used_label = QLabel("0 GB")
        self.used_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        used_layout.addWidget(self.used_label)
        space_layout.addLayout(used_layout)
        
        free_layout = QVBoxLayout()
        free_layout.addWidget(QLabel("Free Space:"))
        self.free_label = QLabel("0 GB")
        self.free_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        free_layout.addWidget(self.free_label)
        space_layout.addLayout(free_layout)
        
        total_layout = QVBoxLayout()
        total_layout.addWidget(QLabel("Total Space:"))
        self.total_label = QLabel("0 GB")
        self.total_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        total_layout.addWidget(self.total_label)
        space_layout.addLayout(total_layout)
        disk_info_layout.addLayout(space_layout)
        
        disk_info_layout.addWidget(QLabel("Disk Usage:"))
        self.disk_progress = QProgressBar()
        self.disk_progress.setTextVisible(True)
        disk_info_layout.addWidget(self.disk_progress)
        main_layout.addWidget(disk_info_group)
        
        self.tabs = QTabWidget()
        self.create_large_files_tab()
        self.create_large_folders_tab()
        main_layout.addWidget(self.tabs)

    def create_large_files_tab(self):
        large_files_widget = QWidget()
        large_files_layout = QVBoxLayout(large_files_widget)
        
        path_layout = self.create_path_input()
        large_files_layout.addLayout(path_layout)
        
        control_layout = QHBoxLayout()
        self.scan_button = QPushButton("Find Largest Files")
        self.scan_button.clicked.connect(self.start_scan)
        control_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.stop_button)
        
        control_layout.addWidget(QLabel("Show top:"))
        self.top_combo = QComboBox()
        self.top_combo.addItems(["10", "20", "50", "100"])
        self.top_combo.setCurrentIndex(1)
        control_layout.addWidget(self.top_combo)
        large_files_layout.addLayout(control_layout)
        
        self.scan_progress = QProgressBar()
        large_files_layout.addWidget(self.scan_progress)
        self.status_label = QLabel("Ready")
        large_files_layout.addWidget(self.status_label)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["File Name", "Path", "Size", "Last Modified"])
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        large_files_layout.addWidget(self.results_table)
        
        self.delete_button = QPushButton("Delete Selected")
        self.delete_button.clicked.connect(self.delete_selected_files)
        self.delete_button.setEnabled(False)
        control_layout.addWidget(self.delete_button)
        
        self.tabs.addTab(large_files_widget, "Largest Files")

    def create_large_folders_tab(self):
        large_folders_widget = QWidget()
        large_folders_layout = QVBoxLayout(large_folders_widget)

        path_layout = self.create_path_input()
        large_folders_layout.addLayout(path_layout)

        control_layout = QHBoxLayout()
        self.scan_folders_button = QPushButton("Find Largest Folders")
        self.scan_folders_button.clicked.connect(self.start_folder_scan)
        control_layout.addWidget(self.scan_folders_button)

        self.stop_folders_button = QPushButton("Stop")
        self.stop_folders_button.clicked.connect(self.stop_folder_scan)
        self.stop_folders_button.setEnabled(False)
        control_layout.addWidget(self.stop_folders_button)

        control_layout.addWidget(QLabel("Show top:"))
        self.top_folders_combo = QComboBox()
        self.top_folders_combo.addItems(["10", "20", "50", "100"])
        self.top_folders_combo.setCurrentIndex(1)
        control_layout.addWidget(self.top_folders_combo)
        large_folders_layout.addLayout(control_layout)

        self.folder_scan_progress = QProgressBar()
        large_folders_layout.addWidget(self.folder_scan_progress)
        self.folder_status_label = QLabel("Ready")
        large_folders_layout.addWidget(self.folder_status_label)

        self.folder_results_table = QTableWidget()
        self.folder_results_table.setColumnCount(3)
        self.folder_results_table.setHorizontalHeaderLabels(["Folder Name", "Path", "Size"])
        self.folder_results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        large_folders_layout.addWidget(self.folder_results_table)

        self.tabs.addTab(large_folders_widget, "Largest Folders")

    def create_path_input(self):
        path_layout = QVBoxLayout()
        path_layout.addWidget(QLabel("Enter the full path to scan:"))
        path_input_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setText(os.path.expanduser("~"))
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
        path_layout.addLayout(path_validation_layout)
        return path_layout

    def populate_drives(self):
        self.drive_combo.clear()
        partitions = psutil.disk_partitions()
        for p in partitions:
            if 'cdrom' in p.opts or p.fstype == '' and sys.platform == 'win32':
                continue
            self.drive_combo.addItem(f"{p.mountpoint} ({p.device})", p.mountpoint)
    
    def update_disk_info(self):
        try:
            selected_drive = self.drive_combo.currentData()
            if not selected_drive:
                return
            usage = shutil.disk_usage(selected_drive)
            total_gb = usage.total / (1024**3)
            used_gb = usage.used / (1024**3)
            free_gb = usage.free / (1024**3)
            self.total_label.setText(f"{total_gb:.2f} GB")
            self.used_label.setText(f"{used_gb:.2f} GB")
            self.free_label.setText(f"{free_gb:.2f} GB")
            percent_used = (usage.used / usage.total) * 100
            self.disk_progress.setValue(int(percent_used))
            self.disk_progress.setFormat(f"{percent_used:.1f}% used")
            if percent_used > 90:
                self.disk_progress.setStyleSheet("QProgressBar::chunk { background-color: #FF5555; }")
            elif percent_used > 75:
                self.disk_progress.setStyleSheet("QProgressBar::chunk { background-color: #FFAA55; }")
            else:
                self.disk_progress.setStyleSheet("QProgressBar::chunk { background-color: #55AA55; }")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not get disk information: {str(e)}")
    
    def verify_path(self):
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
        try:
            next(os.scandir(path))
            self.path_status_label.setText("Path is valid and accessible ✓")
            self.path_status_label.setStyleSheet("color: green")
            return True
        except (StopIteration, PermissionError, OSError) as e:
            self.path_status_label.setText(f"Warning: {str(e)}")
            self.path_status_label.setStyleSheet("color: orange")
            return True
            
    def start_scan(self):
        scan_path = self.path_input.text().strip()
        if not self.verify_path():
            QMessageBox.warning(self, "Invalid Path", "Please select a valid and accessible directory.")
            return
        if self.scanner_thread and self.scanner_thread.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running.")
            return
        max_files = int(self.top_combo.currentText())
        self.scan_progress.setValue(0)
        self.status_label.setText("Scanning...")
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.results_table.setRowCount(0)
        self.scanner_thread = FileSizeScanner(scan_path, min_size=1024, max_files=max_files)
        self.scanner_thread.progress_update.connect(self.update_scan_progress)
        self.scanner_thread.scan_complete.connect(self.display_large_files)
        self.scanner_thread.start()
    
    def stop_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.status_label.setText("Scan stopped by user.")
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
    
    def start_folder_scan(self):
        scan_path = self.path_input.text().strip()
        if not self.verify_path():
            QMessageBox.warning(self, "Invalid Path", "Please select a valid and accessible directory.")
            return
        if self.folder_scanner_thread and self.folder_scanner_thread.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running.")
            return
        max_folders = int(self.top_folders_combo.currentText())
        self.folder_scan_progress.setValue(0)
        self.folder_status_label.setText("Scanning folders...")
        self.scan_folders_button.setEnabled(False)
        self.stop_folders_button.setEnabled(True)
        self.folder_results_table.setRowCount(0)
        self.folder_scanner_thread = FolderScanner(scan_path, max_folders=max_folders)
        self.folder_scanner_thread.progress_update.connect(self.update_folder_scan_progress)
        self.folder_scanner_thread.scan_complete.connect(self.display_large_folders)
        self.folder_scanner_thread.start()

    def stop_folder_scan(self):
        if self.folder_scanner_thread and self.folder_scanner_thread.isRunning():
            self.folder_scanner_thread.stop()
            self.folder_status_label.setText("Scan stopped by user.")
            self.scan_folders_button.setEnabled(True)
            self.stop_folders_button.setEnabled(False)

    def update_scan_progress(self, current, total, current_file):
        if total > 0:
            percentage = int((current / total) * 100)
            self.scan_progress.setValue(percentage)
        display_path = "..." + current_file[-57:] if len(current_file) > 60 else current_file
        self.status_label.setText(f"Scanning: {current}/{total} - {display_path}")
    
    def update_folder_scan_progress(self, current, total, current_path):
        if total > 0:
            percentage = int((current / total) * 100)
            self.folder_scan_progress.setValue(percentage)
        display_path = "..." + current_path[-57:] if len(current_path) > 60 else current_path
        self.folder_status_label.setText(f"Scanning: {current}/{total} - {display_path}")

    def display_large_files(self, file_list):
        self.results_table.setRowCount(0)
        if not file_list:
            self.status_label.setText("Scan complete. No files found.")
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            return
        self.status_label.setText(f"Scan complete. Found {len(file_list)} large files.")
        for i, (file_path, file_size) in enumerate(file_list):
            self.results_table.insertRow(i)
            file_name = os.path.basename(file_path)
            self.results_table.setItem(i, 0, QTableWidgetItem(file_name))
            parent_dir = os.path.dirname(file_path)
            path_item = QTableWidgetItem(parent_dir)
            path_item.setToolTip(file_path)
            self.results_table.setItem(i, 1, path_item)
            size_str = self.format_size(file_size)
            size_item = QTableWidgetItem(size_str)
            size_item.setData(Qt.UserRole, file_size)
            self.results_table.setItem(i, 2, size_item)
            try:
                mod_time = os.path.getmtime(file_path)
                date_str = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
                self.results_table.setItem(i, 3, QTableWidgetItem(date_str))
            except (OSError, PermissionError):
                self.results_table.setItem(i, 3, QTableWidgetItem("Unknown"))
        self.results_table.resizeColumnsToContents()
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.color_code_rows(self.results_table)
        self.delete_button.setEnabled(len(file_list) > 0)

    def display_large_folders(self, folder_list):
        self.folder_results_table.setRowCount(0)
        if not folder_list:
            self.folder_status_label.setText("Scan complete. No folders found.")
            self.scan_folders_button.setEnabled(True)
            self.stop_folders_button.setEnabled(False)
            return
        self.folder_status_label.setText(f"Scan complete. Found {len(folder_list)} large folders.")
        for i, (folder_path, folder_size) in enumerate(folder_list):
            self.folder_results_table.insertRow(i)
            folder_name = os.path.basename(folder_path)
            self.folder_results_table.setItem(i, 0, QTableWidgetItem(folder_name))
            parent_dir = os.path.dirname(folder_path)
            path_item = QTableWidgetItem(parent_dir)
            path_item.setToolTip(folder_path)
            self.folder_results_table.setItem(i, 1, path_item)
            size_str = self.format_size(folder_size)
            size_item = QTableWidgetItem(size_str)
            size_item.setData(Qt.UserRole, folder_size)
            self.folder_results_table.setItem(i, 2, size_item)
        self.folder_results_table.resizeColumnsToContents()
        self.folder_results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.scan_folders_button.setEnabled(True)
        self.stop_folders_button.setEnabled(False)
        self.color_code_rows(self.folder_results_table)

    def delete_selected_files(self):
        selected_rows = set(index.row() for index in self.results_table.selectedIndexes())
        if not selected_rows:
            QMessageBox.warning(self, "No Files Selected", "Please select at least one file to delete.")
            return
        confirm = QMessageBox.question(self, "Delete Files", "Are you sure you want to delete the selected files?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return
        sorted_rows = sorted(selected_rows, reverse=True)
        deleted_files, failed_deletions = [], []
        for row in sorted_rows:
            file_path = self.results_table.item(row, 1).toolTip()
            try:
                os.remove(file_path)
                deleted_files.append(file_path)
                self.results_table.removeRow(row)
            except Exception as e:
                failed_deletions.append(f"{file_path}: {str(e)}")
        if deleted_files:
            QMessageBox.information(self, "Files Deleted", f"Deleted {len(deleted_files)} files.")
        if failed_deletions:
            QMessageBox.warning(self, "Failed Deletions", f"Failed to delete {len(failed_deletions)} files:\n{', '.join(failed_deletions)}")
        self.status_label.setText(f"Deleted {len(deleted_files)} files.")
        if self.results_table.rowCount() == 0:
            self.delete_button.setEnabled(False)

    def color_code_rows(self, table):
        sizes = []
        for i in range(table.rowCount()):
            size_item = table.item(i, 2)
            if size_item and size_item.data(Qt.UserRole) is not None:
                sizes.append(size_item.data(Qt.UserRole))
        if not sizes:
            return
        min_size, max_size = min(sizes), max(sizes)
        size_range = max_size - min_size
        start_color, end_color = QColor(255, 255, 224), QColor(255, 182, 193)
        for i in range(table.rowCount()):
            size_item = table.item(i, 2)
            if not size_item or size_item.data(Qt.UserRole) is None:
                continue
            size = size_item.data(Qt.UserRole)
            ratio = (size - min_size) / size_range if size_range > 0 else 1.0
            r = int(start_color.red() + ratio * (end_color.red() - start_color.red()))
            g = int(start_color.green() + ratio * (end_color.green() - start_color.green()))
            b = int(start_color.blue() + ratio * (end_color.blue() - start_color.blue()))
            color = QColor(r, g, b)
            for j in range(table.columnCount()):
                if table.item(i, j):
                    table.item(i, j).setBackground(color)
                    table.item(i, j).setForeground(QColor('black'))
    
    def format_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024 or unit == 'TB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024

if __name__ == '__main__':
    if 'linux' in sys.platform:
        os.environ["QT_QPA_PLATFORM"] = "xcb"
        os.environ["QT_FILESYSTEMMODEL_WATCH_FILES"] = "0"
    app = QApplication(sys.argv)
    window = DiskSpaceAnalyzer()
    window.setWindowTitle("Disk Space Analyzer")
    window.setGeometry(100, 100, 800, 600)
    window.show()
    sys.exit(app.exec_())
