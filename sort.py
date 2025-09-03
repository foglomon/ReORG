
#!/usr/bin/env python3
"""
File organization tool with content-aware detection.

Sorts files by analyzing their actual content (magic bytes) rather than just
trusting extensions. Useful for cleaning up downloads folders and organizing
misnamed files.
"""

import os
import re
import shutil
import mimetypes
import zipfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Union
from dataclasses import dataclass
from enum import Enum


class FileSignatureDetector:
    """Detects actual file types by reading magic bytes instead of trusting extensions"""
    
    def __init__(self):
        # Common file signatures - organized by frequency in typical use
        self.signatures = {
            # Images (most common downloads)
            b'\xFF\xD8\xFF': ('jpg', 'image/jpeg'),
            b'\x89PNG\r\n\x1a\n': ('png', 'image/png'),
            b'GIF87a': ('gif', 'image/gif'),
            b'GIF89a': ('gif', 'image/gif'),
            b'BM': ('bmp', 'image/bmp'),
            b'RIFF': ('webp', 'image/webp'),  # needs secondary check
            b'\x00\x00\x01\x00': ('ico', 'image/x-icon'),
            
            # Documents
            b'%PDF': ('pdf', 'application/pdf'),
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('doc', 'application/msword'),  # old office
            b'PK\x03\x04': ('zip', 'application/zip'),  # also new office formats
            
            # Archives
            b'Rar!\x1a\x07\x00': ('rar', 'application/x-rar-compressed'),
            b'7z\xBC\xAF\x27\x1C': ('7z', 'application/x-7z-compressed'),
            b'\x1f\x8b': ('gz', 'application/gzip'),
            b'BZh': ('bz2', 'application/x-bzip2'),
            
            # Media files  
            b'\x00\x00\x00\x14ftypqt': ('mov', 'video/quicktime'),
            b'\x00\x00\x00\x18ftypmp4': ('mp4', 'video/mp4'),
            b'\x1aE\xdf\xa3': ('mkv', 'video/x-matroska'),
            b'FLV\x01': ('flv', 'video/x-flv'),
            b'ID3': ('mp3', 'audio/mpeg'),
            b'\xff\xfb': ('mp3', 'audio/mpeg'),
            b'fLaC': ('flac', 'audio/flac'),
            b'OggS': ('ogg', 'audio/ogg'),
            
            # Executables
            b'MZ': ('exe', 'application/x-msdownload'),
            b'\x7fELF': ('elf', 'application/x-executable'),
            
            # Scripts/code
            b'#!/': ('script', 'text/plain'),
            b'<?xml': ('xml', 'application/xml'),
            b'\xef\xbb\xbf': ('utf8_bom', 'text/plain'),
        }
        
        # Files that need a second look after initial signature match
        self.ambiguous_signatures = {
            b'RIFF': self._identify_riff_file,
            b'PK\x03\x04': self._identify_zip_file,
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': self._identify_ole_file,
        }
    
    def detect_file_type(self, file_path: Path) -> Tuple[Optional[str], Optional[str]]:
        try:
            with open(file_path, 'rb') as f:
                header = f.read(64)  # should be enough for most signatures
                
            if not header:
                return None, None
            
            # Check signatures in order of likelihood
            for signature, (ext, mime) in self.signatures.items():
                if header.startswith(signature):
                    # Some signatures need disambiguation
                    if signature in self.ambiguous_signatures:
                        result = self.ambiguous_signatures[signature](header, file_path)
                        if result:
                            return result
                    return ext, mime
            
            # Fallback to text analysis for unrecognized files
            if self._looks_like_text(header):
                return self._guess_text_type(file_path, header)
                
            return None, None
            
        except (IOError, OSError, PermissionError):
            # File access issues - just give up gracefully
            return None, None
    
    def _identify_riff_file(self, header: bytes, file_path: Path) -> Optional[Tuple[str, str]]:
        # RIFF files have format identifier at offset 8
        if len(header) >= 12:
            format_type = header[8:12]
            if format_type == b'WAVE':
                return 'wav', 'audio/wav'
            elif format_type == b'AVI ':
                return 'avi', 'video/x-msvideo'
            elif format_type == b'WEBP':
                return 'webp', 'image/webp'
        return None
    
    def _identify_zip_file(self, header: bytes, file_path: Path) -> Optional[Tuple[str, str]]:
        # Modern office docs are just zip files with specific structure
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                filenames = zf.namelist()
                
                # Check for office document patterns
                if 'word/document.xml' in filenames:
                    return 'docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                elif 'xl/workbook.xml' in filenames:
                    return 'xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                elif 'ppt/presentation.xml' in filenames:
                    return 'pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
                elif 'META-INF/manifest.xml' in filenames:
                    return 'odt', 'application/vnd.oasis.opendocument.text'
                
        except (zipfile.BadZipFile, IOError):
            pass
        
        return 'zip', 'application/zip'
    
    def _identify_ole_file(self, header: bytes, file_path: Path) -> Optional[Tuple[str, str]]:
        # Old office formats - this is a simplified check
        # Real OLE parsing would be overkill for our use case
        try:
            with open(file_path, 'rb') as f:
                content = f.read(2048)  # read a bit more to find identifying strings
            
            if b'Microsoft Office Word' in content or b'Word.Document' in content:
                return 'doc', 'application/msword'
            elif b'Microsoft Office Excel' in content or b'Excel.Sheet' in content:
                return 'xls', 'application/vnd.ms-excel'
            elif b'Microsoft Office PowerPoint' in content:
                return 'ppt', 'application/vnd.ms-powerpoint'
                
        except (IOError, OSError):
            pass
        
        # Default assumption for OLE files
        return 'doc', 'application/msword'
    
    def _looks_like_text(self, header: bytes) -> bool:
        if not header:
            return False
        
        # UTF-8 BOM is a dead giveaway
        if header.startswith(b'\xef\xbb\xbf'):
            return True
        
        # Count how many bytes look like printable text
        try:
            header.decode('utf-8')
            printable = sum(1 for b in header if 32 <= b <= 126 or b in [9, 10, 13])
            return printable / len(header) > 0.7
        except UnicodeDecodeError:
            return False
    
    def _guess_text_type(self, file_path: Path, header: bytes) -> Tuple[str, str]:
        # For text files, we need to peek at more content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024).lower()
            
            # Check for common patterns
            if content.startswith('#!/'):
                if 'python' in content[:100]:
                    return 'py', 'text/x-python'
                elif 'bash' in content[:100] or 'sh' in content[:100]:
                    return 'sh', 'text/x-shellscript'
                return 'script', 'text/plain'
            
            if '<!doctype html' in content or '<html' in content:
                return 'html', 'text/html'
            elif content.strip().startswith('{') and '}' in content:
                return 'json', 'application/json'
            elif content.startswith('<?xml'):
                return 'xml', 'application/xml'
            elif 'def ' in content and 'import ' in content:
                return 'py', 'text/x-python'
            elif 'function' in content and ('{' in content or '=>' in content):
                return 'js', 'text/javascript'
            elif '#include' in content and 'main(' in content:
                return 'c', 'text/x-c'
                
        except (IOError, UnicodeDecodeError):
            pass
        
        return 'txt', 'text/plain'


class FileCategory(Enum):
    IMAGE = "images"
    DOCUMENT = "documents"
    VIDEO = "videos"
    AUDIO = "audio"
    ARCHIVE = "archives"
    CODE = "code"
    DATA = "data"
    OTHER = "other"


class SortCriteria(Enum):
    TYPE = "file_type"
    DATE = "date"
    SIZE = "file_size"
    NAME = "file_name"
    EXTENSION = "file_extension"
    PROJECT = "project"
    VERSION = "version_control"


@dataclass
class FileInfo:
    path: Path
    name: str
    extension: str
    size: int
    created: datetime
    modified: datetime
    category: FileCategory
    mime_type: Optional[str]
    is_hidden: bool
    detected_ext: Optional[str] = None
    detected_mime: Optional[str] = None
    is_misnamed: bool = False
    # Version control fields
    app_name: Optional[str] = None
    version: Optional[str] = None
    is_versioned: bool = False
    
    @property
    def year(self) -> str:
        return str(self.modified.year)
    
    @property
    def month_folder(self) -> str:
        return f"{self.modified.year}-{self.modified.month:02d}"
    
    def size_category(self) -> str:
        if self.size < 1024 * 1024:  # < 1MB
            return "small"
        elif self.size < 50 * 1024 * 1024:  # < 50MB
            return "medium"
        elif self.size < 500 * 1024 * 1024:  # < 500MB
            return "large"
        else:
            return "huge"
    
    def guess_project(self) -> str:
        path_parts = self.path.parts
        name_lower = self.name.lower()
        
        # Try common filename patterns first
        patterns = [
            r'project[_-]?(\w+)',
            r'(\w+)[_-]project', 
            r'(\w+)[_-]v?\d+',
            r'(\w+)[_-](final|draft|report)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, name_lower)
            if match and match.group(1) not in ['file', 'new', 'temp', 'test']:
                return match.group(1)
        
        # Check for content keywords
        keywords = {
            'meeting': 'meetings', 'report': 'reports', 'invoice': 'financial',
            'photo': 'photos', 'music': 'audio', 'backup': 'backups'
        }
        
        for keyword, folder in keywords.items():
            if keyword in name_lower:
                return folder
        
        # Use parent folder if it's not generic
        if len(path_parts) > 1:
            parent = path_parts[-2].lower()
            generic = {'desktop', 'downloads', 'documents', 'pictures', 'videos', 
                      'music', 'temp', 'test', 'new folder'}
            if parent not in generic and len(parent) > 2:
                return parent.replace('_', ' ').replace('-', ' ')
        
        # Fallback to file category
        return {
            FileCategory.IMAGE: 'images',
            FileCategory.DOCUMENT: 'documents', 
            FileCategory.VIDEO: 'videos',
            FileCategory.AUDIO: 'audio',
            FileCategory.CODE: 'code',
            FileCategory.ARCHIVE: 'archives',
            FileCategory.DATA: 'data'
        }.get(self.category, 'misc')


class FileSorter:
    """Main file organization class. Scans folders and sorts files intelligently."""
    
    def __init__(self):
        self.detector = FileSignatureDetector()
        
        # Extension to category mapping - keeping it simple but comprehensive
        self.ext_to_category = {
            # Images
            '.jpg': FileCategory.IMAGE, '.jpeg': FileCategory.IMAGE, '.png': FileCategory.IMAGE,
            '.gif': FileCategory.IMAGE, '.bmp': FileCategory.IMAGE, '.svg': FileCategory.IMAGE,
            '.webp': FileCategory.IMAGE, '.ico': FileCategory.IMAGE,
            
            # Documents  
            '.pdf': FileCategory.DOCUMENT, '.doc': FileCategory.DOCUMENT, '.docx': FileCategory.DOCUMENT,
            '.txt': FileCategory.DOCUMENT, '.rtf': FileCategory.DOCUMENT, '.odt': FileCategory.DOCUMENT,
            '.xls': FileCategory.DOCUMENT, '.xlsx': FileCategory.DOCUMENT, '.ppt': FileCategory.DOCUMENT,
            '.pptx': FileCategory.DOCUMENT,
            
            # Media
            '.mp4': FileCategory.VIDEO, '.avi': FileCategory.VIDEO, '.mkv': FileCategory.VIDEO,
            '.mov': FileCategory.VIDEO, '.wmv': FileCategory.VIDEO, '.webm': FileCategory.VIDEO,
            '.mp3': FileCategory.AUDIO, '.wav': FileCategory.AUDIO, '.flac': FileCategory.AUDIO,
            '.aac': FileCategory.AUDIO, '.ogg': FileCategory.AUDIO,
            
            # Archives
            '.zip': FileCategory.ARCHIVE, '.rar': FileCategory.ARCHIVE, '.7z': FileCategory.ARCHIVE,
            '.tar': FileCategory.ARCHIVE, '.gz': FileCategory.ARCHIVE,
            
            # Code
            '.py': FileCategory.CODE, '.js': FileCategory.CODE, '.html': FileCategory.CODE,
            '.css': FileCategory.CODE, '.java': FileCategory.CODE, '.cpp': FileCategory.CODE,
            '.c': FileCategory.CODE, '.php': FileCategory.CODE,
            
            # Data
            '.json': FileCategory.DATA, '.xml': FileCategory.DATA, '.csv': FileCategory.DATA,
            '.sql': FileCategory.DATA, '.yml': FileCategory.DATA,
        }
        
        self.files = []
        self.source_path = None
    
    def _detect_version_info(self, file_path: Path) -> Tuple[Optional[str], Optional[str], bool]:
        """
        Detect if file follows version naming patterns and extract app name and version
        
        Returns:
            Tuple of (app_name, version, is_versioned)
        """
        name = file_path.stem  # filename without extension
        name_lower = name.lower()
        
        # Version patterns to match
        version_patterns = [
            # Standard patterns: app_v1.2.3, app_v1, app_version1.0
            r'^(.+?)_v(\d+(?:\.\d+)*(?:\.\d+)?)$',
            r'^(.+?)_version(\d+(?:\.\d+)*(?:\.\d+)?)$',
            r'^(.+?)_ver(\d+(?:\.\d+)*(?:\.\d+)?)$',
            
            # Patterns with spaces: "App v1.2", "App Version 1.0"
            r'^(.+?)\s+v(\d+(?:\.\d+)*(?:\.\d+)?)$',
            r'^(.+?)\s+version\s+(\d+(?:\.\d+)*(?:\.\d+)?)$',
            r'^(.+?)\s+ver\s+(\d+(?:\.\d+)*(?:\.\d+)?)$',
            
            # Bracketed versions: app(v1.2), app[v1.0]
            r'^(.+?)\s*[\(\[]v?(\d+(?:\.\d+)*(?:\.\d+)?)[\)\]]$',
            
            # Simple numbered versions: app1, app2, myfile3
            r'^(.+?)(\d+)$',
            
            # Date-like versions: app_2024, app_20240903
            r'^(.+?)_(\d{4})(?:\d{4})?$',
            
            # Release patterns: app_final, app_beta, app_alpha2
            r'^(.+?)_(final|beta|alpha|rc)(\d*)$',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, name_lower)
            if match:
                app_name = match.group(1).strip()
                version_part = match.group(2) if len(match.groups()) >= 2 else "1"
                
                # Clean up app name
                app_name = re.sub(r'[_\-\s]+', ' ', app_name).strip()
                
                # Skip if app name is too generic or short
                if len(app_name) < 2 or app_name in ['new', 'old', 'temp', 'test', 'file', 'document', 'image']:
                    continue
                
                # Handle release pattern specially
                if len(match.groups()) >= 3:
                    release_type = match.group(2)
                    release_num = match.group(3) or ""
                    version_part = f"{release_type}{release_num}"
                
                return app_name, version_part, True
        
        return None, None, False
        
    def scan_folder(self, folder_path: Union[str, Path]) -> List[FileInfo]:
        self.source_path = Path(folder_path)
        if not self.source_path.exists():
            raise ValueError(f"Folder doesn't exist: {folder_path}")
        
        self.files = []
        for file_path in self.source_path.rglob('*'):
            if file_path.is_file():
                self.files.append(self._analyze_file(file_path))
        
        return self.files
    
    def _analyze_file(self, file_path: Path) -> FileInfo:
        stat = file_path.stat()
        
        name = file_path.name
        extension = file_path.suffix.lower()
        size = stat.st_size
        created = datetime.fromtimestamp(stat.st_ctime)
        modified = datetime.fromtimestamp(stat.st_mtime)
        is_hidden = name.startswith('.')
        
        # Try content detection
        detected_ext, detected_mime = self.detector.detect_file_type(file_path)
        
        # Check if file seems misnamed
        is_misnamed = False
        if detected_ext:
            if extension and extension != f".{detected_ext}":
                is_misnamed = True
            elif not extension:  # no extension but we detected one
                is_misnamed = True
        
        # Choose the best extension/category
        final_ext = f".{detected_ext}" if detected_ext else extension
        category = self.ext_to_category.get(final_ext, FileCategory.OTHER)
        
        # Prefer detected info when we're confident about it
        if detected_ext and is_misnamed:
            detected_cat = self.ext_to_category.get(f".{detected_ext}", FileCategory.OTHER)
            if detected_cat != FileCategory.OTHER:
                category = detected_cat
        
        mime_type = detected_mime or mimetypes.guess_type(str(file_path))[0]
        
        # Detect version information
        app_name, version, is_versioned = self._detect_version_info(file_path)
        
        return FileInfo(
            path=file_path,
            name=name,
            extension=extension,
            size=size,
            created=created,
            modified=modified,
            category=category,
            mime_type=mime_type,
            is_hidden=is_hidden,
            detected_ext=detected_ext,
            detected_mime=detected_mime,
            is_misnamed=is_misnamed,
            app_name=app_name,
            version=version,
            is_versioned=is_versioned
        )
    
    def recommend_strategy(self) -> Dict:
        if not self.files:
            return {"strategy": SortCriteria.TYPE, "reason": "No files to analyze"}
        
        total = len(self.files)
        categories = {}
        years = set()
        versioned_files = sum(1 for f in self.files if f.is_versioned)
        app_groups = {}
        
        for f in self.files:
            categories[f.category.value] = categories.get(f.category.value, 0) + 1
            years.add(f.year)
            if f.is_versioned:
                app_groups[f.app_name] = app_groups.get(f.app_name, 0) + 1
        
        # Check if version control organization would be beneficial
        if versioned_files >= 3 and versioned_files / total > 0.2:  # 20% or more are versioned
            return {
                "strategy": SortCriteria.VERSION,
                "reason": f"Found {versioned_files} versioned files across {len(app_groups)} apps",
                "confidence": 85
            }
        
        # Simple heuristics for other strategies
        if len(categories) > 3 and max(categories.values()) / total < 0.8:
            return {
                "strategy": SortCriteria.TYPE,
                "reason": f"Multiple file types found ({len(categories)} categories)",
                "confidence": 85
            }
        
        if len(years) > 2:
            return {
                "strategy": SortCriteria.DATE,
                "reason": f"Files span multiple years ({min(years)}-{max(years)})",
                "confidence": 70
            }
        
        # Default to type-based sorting
        return {
            "strategy": SortCriteria.TYPE,
            "reason": "General purpose organization",
            "confidence": 60
        }
    
    def organize_files(self, target_folder: Union[str, Path], strategy: SortCriteria, 
                      dry_run: bool = True) -> Dict[str, List[str]]:
        target_path = Path(target_folder)
        plan = {}
        
        for file_info in self.files:
            if strategy == SortCriteria.TYPE:
                if file_info.is_versioned:
                    # Group versioned files within their category
                    dest_folder = f"{file_info.category.value}/{file_info.app_name}"
                else:
                    dest_folder = file_info.category.value
            elif strategy == SortCriteria.VERSION:
                if file_info.is_versioned:
                    # Primary version-based organization
                    dest_folder = f"apps/{file_info.app_name}"
                else:
                    # Non-versioned files go to category folders
                    dest_folder = f"unversioned/{file_info.category.value}"
            elif strategy == SortCriteria.DATE:
                dest_folder = f"by_year/{file_info.year}"
            elif strategy == SortCriteria.SIZE:
                dest_folder = f"by_size/{file_info.size_category()}"
            elif strategy == SortCriteria.EXTENSION:
                ext = file_info.extension[1:] if file_info.extension else "no_extension"
                dest_folder = f"by_extension/{ext}"
            elif strategy == SortCriteria.PROJECT:
                dest_folder = f"projects/{file_info.guess_project()}"
            else:
                dest_folder = file_info.category.value
            
            if dest_folder not in plan:
                plan[dest_folder] = []
            plan[dest_folder].append(str(file_info.path))
        
        if not dry_run:
            self._execute_plan(target_path, plan)
        
        return plan
    
    def _execute_plan(self, target_path: Path, plan: Dict[str, List[str]]):
        moved = 0
        
        for dest_folder, file_paths in plan.items():
            dest_dir = target_path / dest_folder
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            for file_path in file_paths:
                source = Path(file_path)
                destination = dest_dir / source.name
                
                # Handle name conflicts
                counter = 1
                while destination.exists():
                    stem = source.stem
                    suffix = source.suffix
                    destination = dest_dir / f"{stem}_{counter}{suffix}"
                    counter += 1
                
                try:
                    shutil.move(str(source), str(destination))
                    moved += 1
                except Exception as e:
                    print(f"Failed to move {source}: {e}")
        
        print(f"Moved {moved} files")
    
    def get_summary(self, plan: Dict[str, List[str]]) -> str:
        total = sum(len(files) for files in plan.values())
        summary = f"Organization Plan ({total} files, {len(plan)} folders)\n"
        summary += "=" * 50 + "\n\n"
        
        for folder, files in sorted(plan.items()):
            summary += f"📁 {folder}: {len(files)} files\n"
            if len(files) <= 3:
                for file_path in files:
                    summary += f"  - {Path(file_path).name}\n"
            else:
                for file_path in files[:2]:
                    summary += f"  - {Path(file_path).name}\n"
                summary += f"  - ... and {len(files) - 2} more\n"
            summary += "\n"
        
        return summary
    
    def get_stats(self) -> Dict:
        if not self.files:
            return {}
        
        stats = {
            "total_files": len(self.files),
            "total_size": sum(f.size for f in self.files),
            "categories": {},
            "misnamed_files": sum(1 for f in self.files if f.is_misnamed),
            "extension_less": sum(1 for f in self.files if not f.extension),
            "detected_types": sum(1 for f in self.files if f.detected_ext),
            "versioned_files": sum(1 for f in self.files if f.is_versioned),
            "app_groups": {}
        }
        
        for f in self.files:
            cat = f.category.value
            stats["categories"][cat] = stats["categories"].get(cat, 0) + 1
            
            if f.is_versioned:
                app = f.app_name
                if app not in stats["app_groups"]:
                    stats["app_groups"][app] = {"count": 0, "versions": set()}
                stats["app_groups"][app]["count"] += 1
                stats["app_groups"][app]["versions"].add(f.version)
        
        # Convert sets to lists for JSON serialization
        for app_info in stats["app_groups"].values():
            app_info["versions"] = sorted(list(app_info["versions"]))
        
        return stats
    
    def get_versioned_files(self) -> List[FileInfo]:
        return [f for f in self.files if f.is_versioned]
    
    def get_version_groups(self) -> Dict[str, List[FileInfo]]:
        """Group files by app name for version control analysis"""
        groups = {}
        for f in self.files:
            if f.is_versioned:
                if f.app_name not in groups:
                    groups[f.app_name] = []
                groups[f.app_name].append(f)
        return groups
    
    def get_misnamed_files(self) -> List[FileInfo]:
        return [f for f in self.files if f.is_misnamed]
    
    def detection_report(self) -> str:
        if not self.files:
            return "No files analyzed."
        
        misnamed = self.get_misnamed_files()
        no_ext = [f for f in self.files if not f.extension and f.detected_ext]
        wrong_ext = [f for f in misnamed if f.extension and f.detected_ext]
        
        report = f"Content Detection Report\n"
        report += "=" * 30 + "\n\n"
        report += f"Files analyzed: {len(self.files)}\n"
        report += f"Content detected: {sum(1 for f in self.files if f.detected_ext)}\n"
        report += f"Misnamed files: {len(misnamed)}\n\n"
        
        if no_ext:
            report += "Files missing extensions:\n"
            for f in no_ext[:5]:  # show first 5
                report += f"  📄 {f.name} → .{f.detected_ext}\n"
            if len(no_ext) > 5:
                report += f"  ... and {len(no_ext) - 5} more\n"
            report += "\n"
        
        if wrong_ext:
            report += "Files with wrong extensions:\n" 
            for f in wrong_ext[:5]:  # show first 5
                report += f"  ⚠️  {f.name} ({f.extension}) → .{f.detected_ext}\n"
            if len(wrong_ext) > 5:
                report += f"  ... and {len(wrong_ext) - 5} more\n"
        
        return report
    
    def version_control_report(self) -> str:
        """Generate a report about version control detection"""
        if not self.files:
            return "No files analyzed."
        
        versioned = self.get_versioned_files()
        version_groups = self.get_version_groups()
        
        report = f"Version Control Report\n"
        report += "=" * 25 + "\n\n"
        report += f"Files analyzed: {len(self.files)}\n"
        report += f"Versioned files: {len(versioned)}\n"
        report += f"App groups found: {len(version_groups)}\n\n"
        
        if version_groups:
            report += "Version groups detected:\n"
            for app_name, files in sorted(version_groups.items()):
                versions = sorted(set(f.version for f in files))
                report += f"  📦 {app_name}: {len(files)} files, versions {', '.join(versions)}\n"
                for f in files[:3]:  # show first 3 files
                    report += f"    - {f.name} (v{f.version})\n"
                if len(files) > 3:
                    report += f"    - ... and {len(files) - 3} more\n"
                report += "\n"
        
        return report


def format_size(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def create_test_files(test_folder: Union[str, Path]):
    """Create test files including some misnamed ones and versioned files"""
    test_path = Path(test_folder)
    test_path.mkdir(exist_ok=True)
    
    # Normal files
    normal_files = [
        ("vacation.jpg", "fake jpg content"),
        ("report.pdf", "fake pdf content"), 
        ("notes.txt", "Meeting notes from yesterday"),
        ("script.py", "#!/usr/bin/env python\nimport os\nprint('Hello')"),
        ("data.json", '{"name": "test", "value": 123}'),
        ("page.html", "<!DOCTYPE html><html><body>Hello</body></html>"),
    ]
    
    # Misnamed files for testing detection
    misnamed_files = [
        ("photo_no_ext", b'\xFF\xD8\xFF\xE0\x00\x10JFIF'),  # JPEG
        ("document.txt", b'%PDF-1.4\n%\xE2\xE3\xCF\xD3'),  # PDF in txt
        ("compressed", b'PK\x03\x04\x14\x00\x00\x00'),  # ZIP
        ("song.doc", b'ID3\x03\x00\x00\x00'),  # MP3 in doc
        ("movie", b'RIFF\x00\x00\x00\x00AVI '),  # AVI
        ("python_code", "#!/usr/bin/env python\nprint('Hello world')"),
        ("web_file", "<!DOCTYPE html>\n<html>\n<body>Test</body>\n</html>"),
    ]
    
    # Versioned files for testing version control
    versioned_files = [
        ("myapp_v1.0.exe", b'MZ\x90\x00'),  # Executable v1.0
        ("myapp_v1.1.exe", b'MZ\x90\x00'),  # Executable v1.1
        ("myapp_v2.0.exe", b'MZ\x90\x00'),  # Executable v2.0
        ("gamedata_v1.zip", b'PK\x03\x04'),  # Game data v1
        ("gamedata_v2.zip", b'PK\x03\x04'),  # Game data v2
        ("PhotoEditor v1.2.dmg", "fake dmg content"),  # Mac app v1.2
        ("PhotoEditor v2.0.dmg", "fake dmg content"),  # Mac app v2.0
        ("backup_2023.tar", "fake tar content"),  # Date-based version
        ("backup_2024.tar", "fake tar content"),  # Date-based version
        ("tool_final.exe", b'MZ\x90\x00'),  # Release version
        ("tool_beta2.exe", b'MZ\x90\x00'),  # Beta version
    ]
    
    import random
    import time
    
    for filename, content in normal_files + misnamed_files + versioned_files:
        file_path = test_path / filename
        if isinstance(content, str):
            file_path.write_text(content)
        else:
            file_path.write_bytes(content)
        
        # Random timestamps for variety
        days_ago = random.randint(1, 365)
        timestamp = time.time() - (days_ago * 24 * 3600)
        os.utime(file_path, (timestamp, timestamp))


if __name__ == "__main__":
    sorter = FileSorter()
    
    test_folder = "test_files"
    create_test_files(test_folder)
    print(f"Created test files in {test_folder}")
    
    files = sorter.scan_folder(test_folder)
    print(f"Found {len(files)} files")
    
    # Show detection results
    print("\n" + sorter.detection_report())
    
    # Show version control detection
    print(sorter.version_control_report())
    
    recommendation = sorter.recommend_strategy()
    print(f"Recommended: {recommendation['strategy'].value}")
    print(f"Reason: {recommendation['reason']}")
    
    plan = sorter.organize_files("organized", recommendation['strategy'])
    print(f"\n{sorter.get_summary(plan)}")
    
    stats = sorter.get_stats()
    print("Statistics:")
    print(f"Total size: {format_size(stats['total_size'])}")
    print(f"Categories: {stats['categories']}")
    print(f"Misnamed files: {stats['misnamed_files']}")
    print(f"Detected types: {stats['detected_types']}")
    print(f"Versioned files: {stats['versioned_files']}")
    if stats['app_groups']:
        print(f"App groups: {list(stats['app_groups'].keys())}")
