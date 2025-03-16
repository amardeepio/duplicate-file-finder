# Duplicate File Finder

A desktop application to scan your drive and find duplicate files. It helps you identify and manage duplicate files to free up disk space.

## Features

- Scan any directory for duplicate files
- Filter by file extensions (e.g., .jpg, .pdf, .mp3)
- Set minimum file size to ignore small files
- Choose between different comparison methods:
  - Content Hash (MD5): Most accurate, compares actual file content
  - File Size: Fast but less accurate
  - Filename: Quick check for identically named files
- View detailed information about duplicate groups
- Export results to CSV for further analysis

## Installation

### Prerequisites

- Python 3.6 or higher
- PyQt5

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/duplicate-file-finder.git
cd duplicate-file-finder
```

2. Create a virtual environment:
```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python duplicate_finder.py
```

### Scanning for Duplicates

1. Enter the directory path you want to scan or use the quick access buttons (Home, Documents, Downloads)
2. Optionally set file extensions to filter (e.g., `.jpg,.png,.pdf`)
3. Set the minimum file size to skip small files
4. Choose your preferred scan method (Content Hash recommended for accuracy)
5. Click "Start Scan"

### Managing Results

- View details of each duplicate group by clicking the "View" button
- Export results to CSV for record-keeping or further analysis

## Building a Standalone Executable (Optional)

You can create a standalone executable using PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed duplicate_finder.py
```

The executable will be created in the `dist` directory.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.