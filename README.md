# This Tool is currently under development and may not be fully functional. For any bugs or issues, please open an issue on GitHub.

---

# ReORG - Intelligent File Organizer

A Python tool that automatically organizes files by analyzing their actual content, not just their names or extensions. Perfect for cleaning up messy download folders, organizing project files, or sorting any collection of mixed file types.

## What It Does

ReORG uses **content-aware detection** to identify what files actually are, then organizes them intelligently:

- **Detects misnamed files**: Finds JPEGs named `.txt`, PDFs with no extension, etc.
- **Smart categorization**: Groups files by type, date, size, or project
- **Magic byte analysis**: Reads file signatures to determine true file types
- **Version control detection**: Groups files like `app_v1.exe`, `app_v2.1.zip` into organized folders
- **Flexible organization**: Multiple sorting strategies based on your needs

## Quick Start

```bash
# Clone and run
git clone https://github.com/foglomon/ReORG.git
cd ReORG
python sort.py

# This creates test files and shows you how it works
```

## Basic Usage

```python
from sort import FileSorter

# Create sorter and scan a folder
sorter = FileSorter()
files = sorter.scan_folder("path/to/messy/folder")

# Get recommendations
strategy = sorter.recommend_strategy()
print(f"Recommended: {strategy['strategy'].value}")
print(f"Reason: {strategy['reason']}")

# Preview organization (dry run)
plan = sorter.organize_files("organized_output", strategy['strategy'], dry_run=True)
print(sorter.get_summary(plan))

# Actually organize files
sorter.organize_files("organized_output", strategy['strategy'], dry_run=False)
```

## Features

### Content-Aware Detection

- **Magic byte signatures**: Detects 30+ file types by reading their binary headers
- **Text analysis**: Identifies scripts, HTML, JSON, XML by content patterns
- **Office document handling**: Distinguishes between DOC/XLS/PPT and DOCX/XLSX/PPTX
- **Archive detection**: Properly identifies ZIP, RAR, 7Z regardless of extension

### Version Control Detection

- **Pattern recognition**: Identifies files like `app_v1.exe`, `tool_v2.1.zip`, `backup_2024.tar`
- **Smart grouping**: Creates nested folders like `apps/myapp/` containing all versions
- **Version tracking**: Detects semantic versions (v1.2.3), simple numbers (v1, v2), and release types (beta, final)
- **Automatic organization**: When 20%+ of files are versioned, recommends version-based sorting

### Smart Organization Strategies

- **By Type**: Groups into images/, documents/, videos/, etc.
- **By Version Control**: Creates `apps/appname/` folders for versioned files
- **By Date**: Organizes by year or month for time-based sorting
- **By Size**: Separates large files from small ones
- **By Project**: Attempts to group related files together
- **By Extension**: Traditional extension-based sorting

### Detection Reports

```bash
Content Detection Report
==============================

Files analyzed: 156
Content detected: 142
Misnamed files: 23

Files missing extensions:
  📄 important_document → .pdf
  📄 vacation_photo → .jpg
  📄 backup_archive → .zip

Files with wrong extensions:
  ⚠️  music.doc (.doc) → .mp3
  ⚠️  image.txt (.txt) → .png

Version Control Report
======================

Files analyzed: 156
Versioned files: 32
App groups found: 8

Version groups detected:
  📦 myapp: 5 files, versions 1.0, 1.1, 2.0, 2.1, 3.0
  📦 photoshop: 3 files, versions 2023, 2024, beta
  📦 gamedata: 4 files, versions 1, 2, 3, final
```

## Supported File Types

| Category      | Extensions                    | Detection Method      |
| ------------- | ----------------------------- | --------------------- |
| **Images**    | jpg, png, gif, bmp, webp, ico | Magic bytes           |
| **Documents** | pdf, doc, docx, txt, rtf, odt | Magic bytes + content |
| **Videos**    | mp4, avi, mkv, mov, wmv, webm | Magic bytes           |
| **Audio**     | mp3, wav, flac, aac, ogg      | Magic bytes           |
| **Archives**  | zip, rar, 7z, tar, gz         | Magic bytes           |
| **Code**      | py, js, html, css, java, cpp  | Content analysis      |
| **Data**      | json, xml, csv, sql, yml      | Content patterns      |

## Real-World Examples

### Cleaning Downloads Folder

```
Before:
Downloads/
├── IMG_001 (actually a JPEG)
├── document.txt (actually a PDF)
├── file (actually a ZIP archive)
├── song.doc (actually an MP3)
└── backup (actually a 7Z archive)

After:
Organized/
├── images/IMG_001
├── documents/document.txt
├── archives/file
├── audio/song.doc
└── archives/backup
```

### Project Organization

```
Before: Mixed project files
After:
projects/
├── web_development/
│   ├── index.html
│   ├── styles.css
│   └── script.js
├── python_scripts/
│   ├── analyzer.py
│   └── utils.py
└── documents/
    ├── requirements.pdf
    └── notes.txt
```

## Advanced Features

### Custom Organization

```python
# Organize by size categories
plan = sorter.organize_files("by_size", SortCriteria.SIZE)

# Organize by date for photos
plan = sorter.organize_files("by_date", SortCriteria.DATE)

# Get detailed statistics
stats = sorter.get_stats()
print(f"Misnamed files: {stats['misnamed_files']}")
print(f"File categories: {stats['categories']}")
```

### Detection Analysis

```python
# Get list of problematic files
misnamed = sorter.get_misnamed_files()
for file in misnamed:
    print(f"{file.name}: {file.extension} → .{file.detected_ext}")

# Generate detailed report
print(sorter.detection_report())
```

## Requirements

- Python 3.8+
- No external dependencies (uses only standard library)
- Works on Windows, macOS, and Linux

## Safety Features

- **Dry run mode**: Preview changes before applying them
- **Conflict resolution**: Handles duplicate filenames automatically
- **Error handling**: Graceful failure for permission issues or corrupted files
- **Backup recommendations**: Always test on copies first

## Limitations

- Large files (>1GB) may take longer to analyze
- Some exotic file formats aren't recognized
- Binary file content isn't analyzed (only headers)
- Requires read permissions on source files

## Contributing

Found a file type that isn't detected correctly? Want to add a new organization strategy? Pull requests welcome!

## License

MIT License - see LICENSE file for details.
