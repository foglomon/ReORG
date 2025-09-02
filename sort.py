
import os
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Union
from dataclasses import dataclass
from enum import Enum
import mimetypes
import json
import re


class FileCategory(Enum):
    """Categories for file types"""
    IMAGE = "images"
    DOCUMENT = "documents"
    VIDEO = "videos"
    AUDIO = "audio"
    ARCHIVE = "archives"
    CODE = "code"
    DATA = "data"
    OTHER = "other"


class SortCriteria(Enum):
    """Different criteria for sorting files"""
    TYPE = "file_type"
    DATE_CREATED = "date_created"
    DATE_MODIFIED = "date_modified"
    SIZE = "file_size"
    NAME = "file_name"
    EXTENSION = "file_extension"
    YEAR = "year"
    MONTH = "month"
    PROJECT = "project"


@dataclass
class FileInfo:
    path: Path
    name: str
    extension: str
    size: int
    created_date: datetime
    modified_date: datetime
    category: FileCategory
    mime_type: Optional[str]
    is_hidden: bool
    
    def get_year(self) -> str:
        return str(self.modified_date.year)
    
    def get_month(self) -> str:
        return f"{self.modified_date.year}-{self.modified_date.month:02d}"
    
    def get_size_category(self) -> str:
        """Categorize file by size"""
        if self.size < 1024 * 1024:  # < 1MB
            return "small"
        elif self.size < 50 * 1024 * 1024:  # < 50MB
            return "medium"
        elif self.size < 500 * 1024 * 1024:  # < 500MB
            return "large"
        else:
            return "huge"
    
    def get_project_name(self) -> str:
        path_parts = self.path.parts
        name_lower = self.name.lower()
        stem_lower = self.path.stem.lower()
        
        #Try to extract project from filename patterns
        filename_patterns = [
            r'project[_-]?(\w+)',
            r'(\w+)[_-]project',
            r'(\w+)[_-]v?\d+',
            r'draft[_-]?(\w+)',
            r'(\w+)[_-]draft',
            r'(\w+)[_-]final',
            r'final[_-]?(\w+)',
            r'(\w+)[_-]presentation',
            r'(\w+)[_-]report',
            r'(\w+)[_-]doc',
            r'(\w+)[_-]notes'
        ]
        
        for pattern in filename_patterns:
            match = re.search(pattern, stem_lower)
            if match:
                project_name = match.group(1)
                # Filter out generic terms
                if project_name not in ['file', 'data', 'new', 'old', 'temp', 'test', 'sample']:
                    return project_name
        
        # Look for meaningful keywords in filename that suggest content type
        content_keywords = {
            'meeting': 'meetings',
            'presentation': 'presentations', 
            'spreadsheet': 'spreadsheets',
            'report': 'reports',
            'invoice': 'financial',
            'budget': 'financial',
            'photo': 'photos',
            'image': 'graphics',
            'video': 'media',
            'tutorial': 'tutorials',
            'music': 'audio',
            'script': 'scripts',
            'code': 'development',
            'backup': 'backups',
            'archive': 'archives',
            'data': 'datasets'
        }
        
        for keyword, category in content_keywords.items():
            if keyword in stem_lower:
                return category
        
        # Look at file extension for content-based grouping
        extension_groups = {
            '.py': 'python_scripts',
            '.js': 'javascript',
            '.html': 'web_development',
            '.css': 'web_development',
            '.java': 'java_projects',
            '.cpp': 'cpp_projects',
            '.c': 'c_projects',
            '.sql': 'database',
            '.pdf': 'documents',
            '.doc': 'documents',
            '.docx': 'documents',
            '.ppt': 'presentations',
            '.pptx': 'presentations',
            '.xls': 'spreadsheets',
            '.xlsx': 'spreadsheets',
            '.jpg': 'photos',
            '.png': 'images',
            '.mp4': 'videos',
            '.mp3': 'audio',
            '.zip': 'archives',
            '.csv': 'data_files'
        }
        
        ext_project = extension_groups.get(self.extension.lower())
        if ext_project:
            return ext_project
        
        # Use parent directory name only if it's meaningful
        if len(path_parts) > 1:
            parent = path_parts[-2].lower()
            # Skip generic folder names
            generic_folders = {
                'desktop', 'downloads', 'documents', 'pictures', 'videos', 'music',
                'temp', 'tmp', 'test', 'tests', 'sample', 'examples', 'misc',
                'new folder', 'untitled folder', 'folder'
            }
            
            if parent not in generic_folders and len(parent) > 2:
                # Check if parent folder name suggests a project
                if any(char.isalpha() for char in parent):
                    return parent.replace('_', ' ').replace('-', ' ')
        
        category_projects = {
            FileCategory.IMAGE: 'images',
            FileCategory.DOCUMENT: 'documents',
            FileCategory.VIDEO: 'videos', 
            FileCategory.AUDIO: 'audio',
            FileCategory.CODE: 'code',
            FileCategory.ARCHIVE: 'archives',
            FileCategory.DATA: 'data'
        }
        
        return category_projects.get(self.category, 'miscellaneous')


class IntelligentFileSorter:
    
    def __init__(self):
        self.file_type_mappings = {
            # Images
            '.jpg': FileCategory.IMAGE, '.jpeg': FileCategory.IMAGE, '.png': FileCategory.IMAGE,
            '.gif': FileCategory.IMAGE, '.bmp': FileCategory.IMAGE, '.tiff': FileCategory.IMAGE,
            '.svg': FileCategory.IMAGE, '.webp': FileCategory.IMAGE, '.ico': FileCategory.IMAGE,
            '.raw': FileCategory.IMAGE, '.cr2': FileCategory.IMAGE, '.nef': FileCategory.IMAGE,
            
            # Documents
            '.pdf': FileCategory.DOCUMENT, '.doc': FileCategory.DOCUMENT, '.docx': FileCategory.DOCUMENT,
            '.txt': FileCategory.DOCUMENT, '.rtf': FileCategory.DOCUMENT, '.odt': FileCategory.DOCUMENT,
            '.xls': FileCategory.DOCUMENT, '.xlsx': FileCategory.DOCUMENT, '.ppt': FileCategory.DOCUMENT,
            '.pptx': FileCategory.DOCUMENT, '.odp': FileCategory.DOCUMENT, '.ods': FileCategory.DOCUMENT,
            
            # Videos
            '.mp4': FileCategory.VIDEO, '.avi': FileCategory.VIDEO, '.mkv': FileCategory.VIDEO,
            '.mov': FileCategory.VIDEO, '.wmv': FileCategory.VIDEO, '.flv': FileCategory.VIDEO,
            '.webm': FileCategory.VIDEO, '.m4v': FileCategory.VIDEO, '.3gp': FileCategory.VIDEO,
            
            # Audio
            '.mp3': FileCategory.AUDIO, '.wav': FileCategory.AUDIO, '.flac': FileCategory.AUDIO,
            '.aac': FileCategory.AUDIO, '.ogg': FileCategory.AUDIO, '.wma': FileCategory.AUDIO,
            '.m4a': FileCategory.AUDIO,
            
            # Archives
            '.zip': FileCategory.ARCHIVE, '.rar': FileCategory.ARCHIVE, '.7z': FileCategory.ARCHIVE,
            '.tar': FileCategory.ARCHIVE, '.gz': FileCategory.ARCHIVE, '.bz2': FileCategory.ARCHIVE,
            
            # Code
            '.py': FileCategory.CODE, '.js': FileCategory.CODE, '.html': FileCategory.CODE,
            '.css': FileCategory.CODE, '.java': FileCategory.CODE, '.cpp': FileCategory.CODE,
            '.c': FileCategory.CODE, '.php': FileCategory.CODE, '.rb': FileCategory.CODE,
            '.go': FileCategory.CODE, '.rs': FileCategory.CODE, '.ts': FileCategory.CODE,
            
            # Data
            '.json': FileCategory.DATA, '.xml': FileCategory.DATA, '.csv': FileCategory.DATA,
            '.yml': FileCategory.DATA, '.yaml': FileCategory.DATA, '.sql': FileCategory.DATA,
        }
        
        self.files_info: List[FileInfo] = []
        self.source_folder: Optional[Path] = None
        
    def scan_folder(self, folder_path: Union[str, Path]) -> List[FileInfo]:
        """
        Scan a folder and analyze all files
        
        Args:
            folder_path: Path to the folder to scan
            
        Returns:
            List of FileInfo objects
        """
        self.source_folder = Path(folder_path)
        if not self.source_folder.exists():
            raise ValueError(f"Folder does not exist: {folder_path}")
        
        self.files_info = []
        
        for file_path in self.source_folder.rglob('*'):
            if file_path.is_file():
                file_info = self._analyze_file(file_path)
                self.files_info.append(file_info)
        
        return self.files_info
    
    def _analyze_file(self, file_path: Path) -> FileInfo:
        stat = file_path.stat()
        
        # Basic file information
        name = file_path.name
        extension = file_path.suffix.lower()
        size = stat.st_size
        created_date = datetime.fromtimestamp(stat.st_ctime)
        modified_date = datetime.fromtimestamp(stat.st_mtime)
        is_hidden = name.startswith('.')
        
        # Determine category
        category = self.file_type_mappings.get(extension, FileCategory.OTHER)
        
        # Get MIME type
        mime_type, _ = mimetypes.guess_type(str(file_path))
        
        return FileInfo(
            path=file_path,
            name=name,
            extension=extension,
            size=size,
            created_date=created_date,
            modified_date=modified_date,
            category=category,
            mime_type=mime_type,
            is_hidden=is_hidden
        )
    
    def get_recommended_sort_strategy(self) -> Dict[str, any]:
        """
        Analyze the files and recommend the best sorting strategy
        
        Returns:
            Dictionary with recommended sorting approach
        """
        if not self.files_info:
            return {"strategy": "none", "reason": "No files to analyze"}
        
        # Analyze file characteristics
        total_files = len(self.files_info)
        categories = {}
        date_spread = {}
        size_spread = {}
        
        for file_info in self.files_info:
            # Count categories
            cat = file_info.category.value
            categories[cat] = categories.get(cat, 0) + 1
            
            # Analyze date spread
            year = file_info.get_year()
            date_spread[year] = date_spread.get(year, 0) + 1
            
            # Analyze size spread
            size_cat = file_info.get_size_category()
            size_spread[size_cat] = size_spread.get(size_cat, 0) + 1
        
        # Determine best strategy
        recommendations = []
        
        if len(categories) > 1 and max(categories.values()) / total_files < 0.8:
            recommendations.append({
                "strategy": SortCriteria.TYPE,
                "score": 90,
                "reason": f"Multiple file types detected ({len(categories)} categories)"
            })
        
        if len(date_spread) > 1:
            years_span = max(map(int, date_spread.keys())) - min(map(int, date_spread.keys()))
            if years_span > 0:
                score = min(85, 60 + years_span * 5)
                recommendations.append({
                    "strategy": SortCriteria.YEAR,
                    "score": score,
                    "reason": f"Files span {years_span + 1} years ({min(date_spread.keys())}-{max(date_spread.keys())})"
                })
        
        dominant_category = max(categories.items(), key=lambda x: x[1])
        if dominant_category[1] / total_files > 0.7:
            if dominant_category[0] == "images":
                recommendations.append({
                    "strategy": SortCriteria.MONTH,
                    "score": 75,
                    "reason": f"Mostly images ({dominant_category[1]} files) - sort by date for photo organization"
                })
            elif dominant_category[0] == "documents":
                recommendations.append({
                    "strategy": SortCriteria.PROJECT,
                    "score": 70,
                    "reason": f"Mostly documents ({dominant_category[1]} files) - sort by project/topic"
                })
        
        # If no clear pattern, suggest type-based as fallback
        if not recommendations:
            recommendations.append({
                "strategy": SortCriteria.TYPE,
                "score": 50,
                "reason": "Mixed content - organize by file type"
            })
        
        best = max(recommendations, key=lambda x: x["score"])
        return {
            "primary_strategy": best["strategy"],
            "reason": best["reason"],
            "confidence": best["score"],
            "alternatives": [r for r in recommendations if r != best],
            "file_stats": {
                "total_files": total_files,
                "categories": categories,
                "date_range": f"{min(date_spread.keys())}-{max(date_spread.keys())}" if date_spread else "N/A",
                "size_distribution": size_spread
            }
        }
    
    def organize_files(self, target_folder: Union[str, Path], 
                      strategy: SortCriteria, 
                      dry_run: bool = True,
                      create_folders: bool = True) -> Dict[str, List[str]]:
        """
        Organize files according to the specified strategy
        
        Args:
            target_folder: Where to organize the files
            strategy: How to organize (by type, date, etc.)
            dry_run: If True, only simulate the organization
            create_folders: Whether to create folder structure
            
        Returns:
            Dictionary mapping destination folders to list of files
        """
        target_path = Path(target_folder)
        organization_plan = {}
        
        for file_info in self.files_info:
            if strategy == SortCriteria.TYPE:
                dest_folder = file_info.category.value
            elif strategy == SortCriteria.YEAR:
                dest_folder = file_info.get_year()
            elif strategy == SortCriteria.MONTH:
                dest_folder = f"{file_info.category.value}/{file_info.get_month()}"
            elif strategy == SortCriteria.SIZE:
                dest_folder = f"by_size/{file_info.get_size_category()}"
            elif strategy == SortCriteria.EXTENSION:
                ext = file_info.extension[1:] if file_info.extension else "no_extension"
                dest_folder = f"by_extension/{ext}"
            elif strategy == SortCriteria.PROJECT:
                project = file_info.get_project_name()
                dest_folder = f"projects/{project}"
            else:
                dest_folder = file_info.category.value
            
            if dest_folder not in organization_plan:
                organization_plan[dest_folder] = []
            organization_plan[dest_folder].append(str(file_info.path))
        
        if not dry_run:
            self._execute_organization_plan(target_path, organization_plan, create_folders)
        
        return organization_plan
    
    def _execute_organization_plan(self, target_path: Path, plan: Dict[str, List[str]], 
                                 create_folders: bool):
        moved_files = 0
        
        for dest_folder, file_paths in plan.items():
            dest_dir = target_path / dest_folder
            
            if create_folders:
                dest_dir.mkdir(parents=True, exist_ok=True)
            
            for file_path in file_paths:
                source = Path(file_path)
                destination = dest_dir / source.name
                
                counter = 1
                while destination.exists():
                    name_parts = source.stem, counter, source.suffix
                    new_name = f"{name_parts[0]}_{name_parts[1]}{name_parts[2]}"
                    destination = dest_dir / new_name
                    counter += 1
                
                try:
                    shutil.move(str(source), str(destination))
                    moved_files += 1
                except Exception as e:
                    print(f"Failed to move {source}: {e}")
        
        print(f"Successfully moved {moved_files} files")
    
    def get_organization_summary(self, plan: Dict[str, List[str]]) -> str:
        summary = "File Organization Plan Summary:\n"
        summary += "=" * 40 + "\n\n"
        
        total_files = sum(len(files) for files in plan.values())
        summary += f"Total files to organize: {total_files}\n"
        summary += f"Number of destination folders: {len(plan)}\n\n"
        
        summary += "Folder breakdown:\n"
        for folder, files in sorted(plan.items()):
            summary += f"  📁 {folder}: {len(files)} files\n"
            
            if len(files) <= 3:
                for file_path in files:
                    file_name = Path(file_path).name
                    summary += f"    - {file_name}\n"
            else:
                for file_path in files[:2]:
                    file_name = Path(file_path).name
                    summary += f"    - {file_name}\n"
                summary += f"    - ... and {len(files) - 2} more files\n"
            summary += "\n"
        
        return summary
    
    def get_file_statistics(self) -> Dict[str, any]:
        if not self.files_info:
            return {}
        
        stats = {
            "total_files": len(self.files_info),
            "total_size": sum(f.size for f in self.files_info),
            "categories": {},
            "extensions": {},
            "size_distribution": {},
            "date_range": {
                "oldest": min(f.modified_date for f in self.files_info),
                "newest": max(f.modified_date for f in self.files_info)
            },
            "hidden_files": sum(1 for f in self.files_info if f.is_hidden)
        }
        
        for file_info in self.files_info:
            cat = file_info.category.value
            stats["categories"][cat] = stats["categories"].get(cat, 0) + 1
            
            ext = file_info.extension or "no_extension"
            stats["extensions"][ext] = stats["extensions"].get(ext, 0) + 1
            
            size_cat = file_info.get_size_category()
            stats["size_distribution"][size_cat] = stats["size_distribution"].get(size_cat, 0) + 1
        
        return stats


def format_file_size(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def create_test_files(test_folder: Union[str, Path]):
    """Create test files for demonstration"""
    test_path = Path(test_folder)
    test_path.mkdir(exist_ok=True)
    
    # Create sample files
    sample_files = [
        "vacation_2023.jpg", "project_report.pdf", "meeting_notes.txt",
        "video_tutorial.mp4", "data_backup.zip", "script.py",
        "presentation.pptx", "music_file.mp3", "old_document_2020.doc",
        "image_2024.png", "spreadsheet.xlsx", "archive_data.csv"
    ]
    
    for filename in sample_files:
        file_path = test_path / filename
        file_path.write_text(f"Sample content for {filename}")
        
        import random
        import time
        days_ago = random.randint(1, 365)
        timestamp = time.time() - (days_ago * 24 * 3600)
        os.utime(file_path, (timestamp, timestamp))


if __name__ == "__main__":
    sorter = IntelligentFileSorter()
    
    test_folder = "test_files"
    create_test_files(test_folder)
    print(f"Created test files in {test_folder}")
    
    files = sorter.scan_folder(test_folder)
    print(f"Found {len(files)} files")
    
    recommendation = sorter.get_recommended_sort_strategy()
    print(f"\nRecommended strategy: {recommendation['primary_strategy'].value}")
    print(f"Reason: {recommendation['reason']}")
    print(f"Confidence: {recommendation['confidence']}%")
    
    plan = sorter.organize_files("organized_files", recommendation['primary_strategy'], dry_run=True)
    print(f"\n{sorter.get_organization_summary(plan)}")
    
    stats = sorter.get_file_statistics()
    print("File Statistics:")
    print(f"Total size: {format_file_size(stats['total_size'])}")
    print(f"Categories: {stats['categories']}")
    if stats['date_range']['oldest'] and stats['date_range']['newest']:
        print(f"Date range: {stats['date_range']['oldest'].strftime('%Y-%m-%d')} to {stats['date_range']['newest'].strftime('%Y-%m-%d')}")
