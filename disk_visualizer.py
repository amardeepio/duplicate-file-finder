import os
import sys
import psutil
import threading
from collections import defaultdict
from pathlib import Path
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLabel, QComboBox, 
                           QFileDialog, QTabWidget, QMessageBox, QGroupBox,
                           QLineEdit, QProgressBar, QSplitter)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWebEngineWidgets import QWebEngineView

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np

# Thread-safe counter for progress tracking
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

class DiskScanner(QThread):
    """Worker thread for scanning disk usage data"""
    progress_update = pyqtSignal(int, int, str)
    scan_complete = pyqtSignal(dict)
    
    def __init__(self, root_path, max_depth=10):
        super().__init__()
        self.root_path = root_path
        self.max_depth = max_depth
        self.running = True
        self.file_types = defaultdict(int)
        self.file_counts = defaultdict(int)
        self.directories = {}  # Path -> size
        self.directory_errors = []  # List of directories with errors
        self.file_errors = []  # List of files with errors
        
    def run(self):
        result = {
            'folder_sizes': {},      # path -> size
            'file_types': defaultdict(int),  # extension -> total size
            'file_counts': defaultdict(int), # extension -> count
            'total_size': 0,
            'errors': []
        }
        
        try:
            # Start scan
            self.progress_update.emit(0, 100, "Starting scan...")
            
            # First, count all files and directories for accurate progress reporting
            total_items = self._count_items(self.root_path)
            processed = AtomicCounter(0)
            
            # Scan the directory structure
            total_size = self._scan_directory(
                self.root_path, 
                0,
                total_items,
                processed
            )
            
            # Populate result with scan data
            result['folder_sizes'] = self.directories
            result['file_types'] = dict(self.file_types)
            result['file_counts'] = dict(self.file_counts)
            result['total_size'] = total_size
            result['errors'] = self.directory_errors + self.file_errors
            
            # Final progress update
            self.progress_update.emit(100, 100, "Scan complete!")
            self.scan_complete.emit(result)
            
        except Exception as e:
            self.progress_update.emit(100, 100, f"Error: {str(e)}")
            print(f"Critical error during scan: {str(e)}")
            result['errors'].append(f"Critical error: {str(e)}")
            self.scan_complete.emit(result)
    
    def _count_items(self, directory):
        """Count files and directories for progress tracking"""
        try:
            # Quick count of top-level items
            with os.scandir(directory) as it:
                count = sum(1 for _ in it)
                
            # For very large directories, just estimate
            if count > 10000:
                return count * 5  # Rough estimate
                
            # For smaller directories, count more accurately
            count = 0
            for root, dirs, files in os.walk(directory):
                count += len(files) + len(dirs)
                # Stop if it gets too large
                if count > 50000:
                    return count
                # Stop if thread is canceled
                if not self.running:
                    return count
            return max(count, 1)  # Ensure at least 1
        except Exception as e:
            print(f"Error counting items: {str(e)}")
            return 1000  # Default estimate
            
    def _scan_directory(self, directory, current_depth, total_items, processed_counter):
        """Recursively scan directory and calculate sizes accurately"""
        if current_depth > self.max_depth or not self.running:
            return 0
        
        total_size = 0
        
        try:
            # Get all entries in the directory
            entries = list(os.scandir(directory))
            dir_size = 0
            
            # Process all files first
            for entry in entries:
                try:
                    # Update progress
                    processed = processed_counter.increment()
                    progress = min(99, int((processed / total_items) * 100))
                    if processed % 100 == 0:  # Update every 100 items
                        self.progress_update.emit(progress, 100, f"Scanning: {entry.path}")
                        
                    # Check if thread should stop
                    if not self.running:
                        return 0
                        
                    # Process file
                    if entry.is_file(follow_symlinks=False):
                        try:
                            # Get file size
                            file_size = entry.stat(follow_symlinks=False).st_size
                            total_size += file_size
                            dir_size += file_size
                            
                            # Track file type
                            _, ext = os.path.splitext(entry.name)
                            ext = ext.lower() if ext else "No Extension"
                            self.file_types[ext] += file_size
                            self.file_counts[ext] += 1
                        except (PermissionError, FileNotFoundError, OSError) as e:
                            self.file_errors.append(f"Error with file {entry.path}: {str(e)}")
                except Exception as e:
                    print(f"Error processing entry {getattr(entry, 'path', 'unknown')}: {str(e)}")
            
            # Then process subdirectories
            for entry in entries:
                if not self.running:
                    return total_size
                    
                try:
                    if entry.is_dir(follow_symlinks=False) and current_depth < self.max_depth:
                        # Recursively get subdirectory size
                        subdir_size = self._scan_directory(
                            entry.path,
                            current_depth + 1,
                            total_items,
                            processed_counter
                        )
                        
                        total_size += subdir_size
                        dir_size += subdir_size
                        
                        # Store size for this subdirectory
                        self.directories[entry.path] = subdir_size
                except (PermissionError, FileNotFoundError, OSError) as e:
                    self.directory_errors.append(f"Error with directory {getattr(entry, 'path', 'unknown')}: {str(e)}")
            
            # Store size for this directory
            self.directories[directory] = dir_size
            
        except (PermissionError, FileNotFoundError, OSError) as e:
            self.directory_errors.append(f"Error accessing directory {directory}: {str(e)}")
            
        return total_size
        
    def stop(self):
        self.running = False


class DiskVisualizer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scanner_thread = None
        self.scan_data = {}
        self.current_path = None
        self.initUI()
        
    def initUI(self):
        # Set window properties
        self.setWindowTitle('Disk Usage Visualizer')
        self.setGeometry(100, 100, 1000, 800)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create scan options group
        scan_options_group = QGroupBox("Scan Options")
        scan_options_layout = QVBoxLayout(scan_options_group)
        
        # Path selection
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Directory to Analyze:"))
        
        self.path_input = QLineEdit()
        self.path_input.setText(os.path.expanduser("~"))  # Default to home directory
        path_layout.addWidget(self.path_input)
        
        # Quick path buttons
        home_button = QPushButton("Home")
        home_button.clicked.connect(lambda: self.path_input.setText(os.path.expanduser("~")))
        path_layout.addWidget(home_button)
        
        documents_button = QPushButton("Documents")
        documents_button.clicked.connect(lambda: self.path_input.setText(os.path.join(os.path.expanduser("~"), "Documents")))
        path_layout.addWidget(documents_button)
        
        downloads_button = QPushButton("Downloads")
        downloads_button.clicked.connect(lambda: self.path_input.setText(os.path.join(os.path.expanduser("~"), "Downloads")))
        path_layout.addWidget(downloads_button)
        
        scan_options_layout.addLayout(path_layout)
        
        # Scan depth selection
        depth_layout = QHBoxLayout()
        depth_layout.addWidget(QLabel("Scan Depth:"))
        
        self.depth_combo = QComboBox()
        self.depth_combo.addItems(["1 - Root only", "2 - Root + 1 level", "3 - Root + 2 levels", "4 - Root + 3 levels", "10 - Deep scan"])
        self.depth_combo.setCurrentIndex(4)  # Default to deep scan
        depth_layout.addWidget(self.depth_combo)
        
        # Scan button
        self.scan_button = QPushButton("Scan Directory")
        self.scan_button.clicked.connect(self.start_scan)
        depth_layout.addWidget(self.scan_button)
        
        scan_options_layout.addLayout(depth_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        scan_options_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        scan_options_layout.addWidget(self.status_label)
        
        main_layout.addWidget(scan_options_group)
        
        # Create visualization tabs
        self.tabs = QTabWidget()
        
        # Create web views for each visualization
        self.pie_chart_view = QWebEngineView()
        self.treemap_view = QWebEngineView()
        self.file_types_view = QWebEngineView()
        
        # Add tabs
        self.tabs.addTab(self.pie_chart_view, "Directory Sizes (Pie Chart)")
        self.tabs.addTab(self.treemap_view, "Directory Treemap")
        self.tabs.addTab(self.file_types_view, "File Types")
        
        main_layout.addWidget(self.tabs)
        
        # Set initial visualizations
        self._show_placeholder_visualizations()
        
    def _show_placeholder_visualizations(self):
        """Show placeholder visualizations before any data is loaded"""
        # Create a placeholder pie chart
        fig_pie = go.Figure(go.Pie(
            labels=["No Data"],
            values=[1],
            textinfo="label",
            marker=dict(colors=['#c9c9c9'])
        ))
        fig_pie.update_layout(
            title="Scan a directory to see disk usage breakdown",
            height=500
        )
        placeholder_pie_html = fig_pie.to_html(include_plotlyjs='cdn')
        self.pie_chart_view.setHtml(placeholder_pie_html)
        
        # Create a placeholder treemap
        fig_treemap = go.Figure(go.Treemap(
            labels=["No Data"],
            parents=[""],
            values=[1],
            marker=dict(colors=['#c9c9c9'])
        ))
        fig_treemap.update_layout(
            title="Scan a directory to see disk usage treemap",
            height=500
        )
        placeholder_treemap_html = fig_treemap.to_html(include_plotlyjs='cdn')
        self.treemap_view.setHtml(placeholder_treemap_html)
        
        # Create a placeholder file types chart
        fig_types = go.Figure(go.Bar(
            x=["No Data"],
            y=[1],
            marker=dict(color='#c9c9c9')
        ))
        fig_types.update_layout(
            title="Scan a directory to see file type breakdown",
            height=500
        )
        placeholder_types_html = fig_types.to_html(include_plotlyjs='cdn')
        self.file_types_view.setHtml(placeholder_types_html)
        
    def start_scan(self):
        """Start the directory scanning process"""
        # Get directory path
        dir_path = self.path_input.text()
        if not dir_path or not os.path.exists(dir_path) or not os.path.isdir(dir_path):
            QMessageBox.warning(self, "Invalid Directory", "Please enter a valid directory path.")
            return
            
        # Get scan depth
        depth_idx = self.depth_combo.currentIndex()
        if depth_idx == 4:  # "Deep scan"
            scan_depth = 10
        else:
            scan_depth = depth_idx + 1  # Convert to actual depth value
        
        # Check if scan is already running
        if self.scanner_thread and self.scanner_thread.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running.")
            return
            
        # Update UI
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting scan...")
        self.scan_button.setEnabled(False)
        self.current_path = dir_path
        
        # Start scanner thread
        self.scanner_thread = DiskScanner(dir_path, max_depth=scan_depth)
        self.scanner_thread.progress_update.connect(self.update_progress)
        self.scanner_thread.scan_complete.connect(self.display_visualizations)
        self.scanner_thread.start()
        
    def update_progress(self, current, total, message):
        """Update the progress bar and status label"""
        if total > 0:
            percentage = int((current / total) * 100)
            self.progress_bar.setValue(percentage)
            
        self.status_label.setText(message)
        
    def display_visualizations(self, scan_data):
        """Create and display visualizations based on scan results"""
        self.scan_data = scan_data
        
        # Check if we have valid data
        if not scan_data or scan_data.get('total_size', 0) == 0:
            self.status_label.setText("Scan failed or directory is empty.")
            self.scan_button.setEnabled(True)
            if scan_data.get('errors'):
                print("Scan errors:")
                for error in scan_data.get('errors'):
                    print(f"  - {error}")
            return
            
        # Create and display the visualizations
        self._create_directory_pie_chart()
        self._create_directory_treemap()
        self._create_file_types_chart()
        
        # Update UI
        self.status_label.setText("Visualization complete!")
        self.scan_button.setEnabled(True)
        
    def _create_directory_pie_chart(self):
        """Create a pie chart of top directory sizes"""
        if not self.current_path or not self.scan_data:
            return
            
        # Get direct subdirectories from scan data
        subdirs = {}
        files_size = 0
        total_size = self.scan_data.get('total_size', 0)
        
        # First pass: Get sizes of all direct subdirectories
        for path, size in self.scan_data.get('folder_sizes', {}).items():
            if os.path.dirname(path) == self.current_path and path != self.current_path:
                # This is a direct subdirectory
                subdirs[os.path.basename(path)] = size
        
        # Second pass: Calculate size of files directly in root
        root_size = self.scan_data.get('folder_sizes', {}).get(self.current_path, 0)
        subdir_total = sum(subdirs.values())
        files_size = max(0, root_size - subdir_total)
        
        # Create structure for chart
        structure = subdirs.copy()
        if files_size > 0:
            structure["Files"] = files_size
            
        if structure and total_size > 0:
            # Prepare data for pie chart
            items = sorted(structure.items(), key=lambda x: x[1], reverse=True)
            
            # Keep only top 5 items and group the rest as "Other"
            if len(items) > 5:
                top_items = items[:4]  # Take top 4
                other_size = sum(size for _, size in items[4:])
                
                labels = [name for name, _ in top_items]
                values = [size for _, size in top_items]
                
                if other_size > 0:
                    labels.append("Other")
                    values.append(other_size)
            else:
                labels = [name for name, _ in items]
                values = [size for _, size in items]
                
            # Custom hover template with human-readable sizes
            custom_data = []
            for size in values:
                custom_data.append([self._format_size(size), f"{size/total_size*100:.1f}%"])
                
            # Create the pie chart
            fig = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                customdata=custom_data,
                hovertemplate='%{label}<br>Size: %{customdata[0]}<extra></extra>',
                textinfo="percent+label",
                insidetextorientation="radial",
                hole=0.3,
                marker=dict(
                    line=dict(color='#FFFFFF', width=2)
                )
            )])
            
            # Simple title with just the total size
            fig.update_layout(
                title=f"Total: {self._format_size(total_size)}",
                height=500,
                margin=dict(t=50, b=10, l=10, r=10)  # Reduce margins
            )
        else:
            # No data case
            fig = go.Figure(data=[go.Pie(
                labels=["No data"],
                values=[1],
                textinfo="label"
            )])
            fig.update_layout(
                title="No data available",
                height=500
            )
            
        # Convert to HTML and display
        html = fig.to_html(include_plotlyjs='cdn', full_html=False)
        
        # Wrap in a custom HTML to ensure proper styling
        full_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{
                    margin: 0;
                    padding: 0;
                    font-family: Arial, sans-serif;
                }}
            </style>
        </head>
        <body>
            {html}
        </body>
        </html>
        """
        
        self.pie_chart_view.setHtml(full_html)
            
    def _create_directory_treemap(self):
        """Create a treemap visualization of the directory structure"""
        if not self.current_path or not self.scan_data:
            return
            
        # Prepare treemap data
        labels = []
        parents = []
        values = []
        hover_texts = []
        
        # Add the root node
        root_name = os.path.basename(self.current_path) or self.current_path
        total_size = self.scan_data.get('total_size', 0)
        
        # Add root node
        labels.append(root_name)
        parents.append("")
        values.append(total_size)
        hover_texts.append(f"{root_name}: {self._format_size(total_size)}")
        
        # Add all directories from scan data
        for path, size in self.scan_data.get('folder_sizes', {}).items():
            if path == self.current_path:
                continue  # Skip root directory (already added)
                
            # Only include directories under the root path
            if not path.startswith(self.current_path):
                continue
                
            # Get relative path and parent
            rel_path = os.path.relpath(path, self.current_path)
            if rel_path == '.':
                continue
                
            # Split into parts
            parts = rel_path.split(os.sep)
            
            # For direct children
            if len(parts) == 1:
                name = parts[0]
                parent = root_name
            else:
                # For nested directories
                name = parts[-1]
                parent = parts[-2]
                
            # Check if this directory's ancestors are in the list
            ancestors_valid = True
            for i in range(1, len(parts)):
                ancestor = parts[i-1]
                if ancestor not in labels:
                    ancestors_valid = False
                    break
                    
            if not ancestors_valid:
                continue
                
            # Add to treemap data
            labels.append(name)
            parents.append(parent)
            values.append(size)
            hover_texts.append(f"{name}: {self._format_size(size)}")
            
        # Create the treemap
        if len(labels) > 1:  # Only if we have more than just the root
            fig = go.Figure(go.Treemap(
                labels=labels,
                parents=parents,
                values=values,
                hovertext=hover_texts,
                hoverinfo="text",
                branchvalues="total",
                marker=dict(
                    line=dict(width=2)
                )
            ))
            
            fig.update_layout(
                title=f"Directory Structure - {self._format_size(total_size)}",
                height=600
            )
        else:
            # No data or only root
            fig = go.Figure(go.Treemap(
                labels=["No detailed directory data"],
                parents=[""],
                values=[1]
            ))
            fig.update_layout(
                title="Not enough directory data for treemap",
                height=600
            )
            
        # Convert to HTML and display
        html = fig.to_html(include_plotlyjs='cdn')
        self.treemap_view.setHtml(html)
        
    def _create_file_types_chart(self):
        """Create a chart showing file types breakdown"""
        # Get file type data
        file_types = self.scan_data.get('file_types', {})
        file_counts = self.scan_data.get('file_counts', {})
        
        if file_types:
            # Sort file types by size (descending)
            sorted_types = sorted(file_types.items(), key=lambda x: x[1], reverse=True)
            
            # Take top 15 types
            if len(sorted_types) > 15:
                top_types = sorted_types[:14]
                other_size = sum(size for _, size in sorted_types[14:])
                other_count = sum(file_counts.get(ext, 0) for ext, _ in sorted_types[14:])
                
                ext_list = [ext for ext, _ in top_types] + ["Other"]
                size_list = [size for _, size in top_types] + [other_size]
                count_list = [file_counts.get(ext, 0) for ext, _ in top_types] + [other_count]
            else:
                ext_list = [ext for ext, _ in sorted_types]
                size_list = [size for _, size in sorted_types]
                count_list = [file_counts.get(ext, 0) for ext, _ in sorted_types]
                
            # Format extensions for display
            display_ext = [ext if ext != "No Extension" else "(no extension)" for ext in ext_list]
            
            # Format sizes for hover text
            size_text = [self._format_size(size) for size in size_list]
            hover_text = [f"{ext}: {size}<br>{count} files" 
                         for ext, size, count in zip(display_ext, size_text, count_list)]
            
            # Create the bar chart
            fig = go.Figure()
            
            # Add bar for file sizes
            fig.add_trace(go.Bar(
                x=display_ext,
                y=size_list,
                text=size_text,
                hovertext=hover_text,
                name="File Size",
                marker=dict(color='rgba(58, 71, 80, 0.8)'),
                hoverinfo="text"
            ))
            
            # Update layout
            fig.update_layout(
                title="File Types by Size",
                xaxis=dict(
                    title="File Extension",
                    tickangle=45
                ),
                yaxis=dict(
                    title="Size",
                    type='log'  # Log scale to better show differences
                ),
                height=500,
                margin=dict(t=50, b=100)  # Extra bottom margin for rotated labels
            )
        else:
            # No data case
            fig = go.Figure(go.Bar(
                x=["No file type data"],
                y=[0]
            ))
            fig.update_layout(
                title="No file type data available",
                height=500
            )
            
        # Convert to HTML and display
        html = fig.to_html(include_plotlyjs='cdn')
        self.file_types_view.setHtml(html)
    
    def _format_size(self, size_bytes):
        """Format byte size to human-readable string"""
        # Handle zero size
        if size_bytes == 0:
            return "0 B"
            
        # Use appropriate units
        units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
        size = float(size_bytes)
        unit_index = 0
        
        while size >= 1024.0 and unit_index < len(units) - 1:
            size /= 1024.0
            unit_index += 1
            
        # Format with appropriate precision
        if unit_index == 0:
            # Bytes - no decimal places
            return f"{int(size)} {units[unit_index]}"
        elif size >= 100:
            # Larger numbers - one decimal place
            return f"{size:.1f} {units[unit_index]}"
        else:
            # Smaller numbers - two decimal places
            return f"{size:.2f} {units[unit_index]}"


def launch_visualizer():
    """Function to launch the visualizer from another application"""
    # Create and show the disk visualizer window
    visualizer = DiskVisualizer()
    visualizer.show()
    
    # Make sure the window stays open if launched from another application
    if not QApplication.instance():
        app = QApplication(sys.argv)
        sys.exit(app.exec_())
    return visualizer


# Main entry point
if __name__ == '__main__':
    # Set Qt platform-specific workarounds
    if 'linux' in sys.platform:
        # Fix for Wayland issues
        os.environ["QT_QPA_PLATFORM"] = "xcb"
    
    app = QApplication(sys.argv)
    window = DiskVisualizer()
    window.show()
    sys.exit(app.exec_())