
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
                return 'py', 'text/x-python'  # Default script to python for simplicity
            
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
    CUSTOM_REGEX = "custom_regex"


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
        
        # Try common filename patterns first - but be more conservative
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
        
        # Check for content keywords - but avoid overly broad matching
        keywords = {
            'meeting': 'meetings', 'report': 'reports', 'invoice': 'financial',
            'backup': 'backups'
        }
        
        for keyword, folder in keywords.items():
            if keyword in name_lower:
                return folder
        
        # Use parent folder if it's not generic
        if len(path_parts) > 1:
            parent = path_parts[-2].lower()
            generic = {'desktop', 'downloads', 'documents', 'pictures', 'videos', 
                      'music', 'temp', 'test', 'new folder', 'projects'}
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


@dataclass
class CustomRegexRule:
    """A custom rule for organizing files using regex patterns"""
    name: str
    pattern: str
    folder_template: str
    description: str = ""
    case_sensitive: bool = False
    
    def matches(self, filename: str) -> Optional[Dict[str, str]]:
        """Check if filename matches this rule and return capture groups"""
        flags = 0 if self.case_sensitive else re.IGNORECASE
        match = re.search(self.pattern, filename, flags)
        if match:
            # Return named groups and numbered groups
            groups = match.groupdict()
            # Add numbered groups as well
            for i, group in enumerate(match.groups(), 1):
                if group is not None:
                    groups[f'group{i}'] = group
            return groups
        return None
    
    def generate_folder_path(self, groups: Dict[str, str], file_info: 'FileInfo') -> str:
        """Generate the destination folder path using the template and captured groups"""
        # Add file info variables that can be used in templates
        template_vars = {
            **groups,
            'category': file_info.category.value,
            'year': file_info.year,
            'month': file_info.month_folder,
            'size_category': file_info.size_category(),
            'extension': file_info.extension[1:] if file_info.extension else 'no_extension',
            'detected_ext': file_info.detected_ext or 'unknown'
        }
        
        try:
            return self.folder_template.format(**template_vars)
        except KeyError as e:
            # If template variable is missing, fall back to a safe default
            return f"custom_regex/{self.name}/{groups.get('group1', 'unmatched')}"


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
            '.c': FileCategory.CODE, '.php': FileCategory.CODE, '.json': FileCategory.CODE,
            '.xml': FileCategory.CODE, '.yml': FileCategory.CODE, '.yaml': FileCategory.CODE,
            '.sh': FileCategory.CODE, '.script': FileCategory.CODE,
            
            # Data
            '.csv': FileCategory.DATA, '.sql': FileCategory.DATA, '.db': FileCategory.DATA,
        }
        
        self.files = []
        self.source_path = None
        self.custom_regex_rules = []  # List of CustomRegexRule objects
    
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
                # Only consider it misnamed if the detected type is very different
                ext_category = self.ext_to_category.get(extension, FileCategory.OTHER)
                detected_category = self.ext_to_category.get(f".{detected_ext}", FileCategory.OTHER)
                # If both categories are the same, don't consider it misnamed
                if ext_category != detected_category:
                    is_misnamed = True
            elif not extension:  # no extension but we detected one
                is_misnamed = True
        
        # Choose the best extension/category
        final_ext = f".{detected_ext}" if detected_ext else extension
        category = self.ext_to_category.get(final_ext, FileCategory.OTHER)
        
        # Always prioritize the file extension over content detection
        # This prevents files like song.doc from being categorized as audio
        if extension:
            category = self.ext_to_category.get(extension, FileCategory.OTHER)
        
        # Only use content detection for files without extensions
        if not extension and detected_ext:
            detected_cat = self.ext_to_category.get(f".{detected_ext}", FileCategory.OTHER)
            if detected_cat != FileCategory.OTHER:
                category = detected_cat
        
        # For clearly misnamed files, be very conservative about overriding
        # Only override if the file has no meaningful extension
        elif is_misnamed and detected_ext and extension:
            ext_category = self.ext_to_category.get(extension, FileCategory.OTHER)
            detected_category = self.ext_to_category.get(f".{detected_ext}", FileCategory.OTHER)
            
            # Only override if original extension gives us "OTHER" category
            # This preserves document files even if they have embedded media content
            if ext_category == FileCategory.OTHER:
                category = detected_category
        
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
        
        for f in self.files:
            categories[f.category.value] = categories.get(f.category.value, 0) + 1
            years.add(f.year)
        
        # Simple heuristics for strategies
        
        # If custom regex rules are defined, recommend using them
        if self.custom_regex_rules:
            matches = sum(1 for f in self.files 
                         for rule in self.custom_regex_rules 
                         if rule.matches(f.name))
            if matches > total * 0.3:  # If >30% of files match custom rules
                return {
                    "strategy": SortCriteria.CUSTOM_REGEX,
                    "reason": f"Custom regex rules match {matches}/{total} files",
                    "confidence": 80
                }
        
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
    
    def add_custom_regex_rule(self, rule: CustomRegexRule) -> None:
        """Add a custom regex rule for file organization"""
        self.custom_regex_rules.append(rule)
    
    def remove_custom_regex_rule(self, rule_name: str) -> bool:
        """Remove a custom regex rule by name. Returns True if removed, False if not found"""
        for i, rule in enumerate(self.custom_regex_rules):
            if rule.name == rule_name:
                del self.custom_regex_rules[i]
                return True
        return False
    
    def clear_custom_regex_rules(self) -> None:
        """Remove all custom regex rules"""
        self.custom_regex_rules.clear()
    
    def get_custom_regex_rules(self) -> List[CustomRegexRule]:
        """Get a copy of all custom regex rules"""
        return self.custom_regex_rules.copy()
    
    def _apply_custom_regex_rules(self, file_info: FileInfo) -> str:
        """Apply custom regex rules to determine destination folder"""
        filename = file_info.name
        
        # Try each rule in order until one matches
        for rule in self.custom_regex_rules:
            groups = rule.matches(filename)
            if groups:
                try:
                    return rule.generate_folder_path(groups, file_info)
                except Exception as e:
                    # If rule fails, log it but continue to next rule
                    print(f"Warning: Custom rule '{rule.name}' failed for '{filename}': {e}")
                    continue
        
        # If no custom rules match, fall back to category-based organization
        if file_info.is_versioned:
            return f"custom_unmatched/{file_info.category.value}/{file_info.app_name}"
        else:
            return f"custom_unmatched/{file_info.category.value}"
    
    def validate_custom_regex_rule(self, rule: CustomRegexRule) -> List[str]:
        """Validate a custom regex rule and return any errors found"""
        errors = []
        
        # Test regex pattern
        try:
            re.compile(rule.pattern)
        except re.error as e:
            errors.append(f"Invalid regex pattern: {e}")
        
        # Test folder template with dummy data
        try:
            dummy_groups = {'group1': 'test', 'group2': 'example'}
            dummy_file_info = FileInfo(
                path=Path('test.txt'),
                name='test.txt',
                extension='.txt',
                size=1024,
                created=datetime.now(),
                modified=datetime.now(),
                category=FileCategory.DOCUMENT,
                mime_type='text/plain',
                is_hidden=False
            )
            rule.generate_folder_path(dummy_groups, dummy_file_info)
        except Exception as e:
            errors.append(f"Invalid folder template: {e}")
        
        return errors
    
    def test_custom_regex_rules(self) -> Dict[str, List[Tuple[str, str]]]:
        """Test custom regex rules against current files and return matches"""
        results = {}
        
        for rule in self.custom_regex_rules:
            matches = []
            for file_info in self.files:
                groups = rule.matches(file_info.name)
                if groups:
                    try:
                        dest_folder = rule.generate_folder_path(groups, file_info)
                        matches.append((file_info.name, dest_folder))
                    except Exception as e:
                        matches.append((file_info.name, f"ERROR: {e}"))
            
            results[rule.name] = matches
        
        return results
    
    def organize_files(self, strategy: SortCriteria, dry_run: bool = True) -> Dict[str, List[str]]:
        if not self.source_path:
            raise ValueError("No source folder has been scanned. Call scan_folder() first.")
        
        target_path = self.source_path  # Organize within the same folder
        plan = {}
        
        for file_info in self.files:
            if strategy == SortCriteria.TYPE:
                if file_info.is_versioned:
                    # Group versioned files under their app name within category
                    dest_folder = f"{file_info.category.value}/{file_info.app_name}"
                else:
                    dest_folder = file_info.category.value
            elif strategy == SortCriteria.DATE:
                if file_info.is_versioned:
                    # Group versioned files under their app name within date folders
                    dest_folder = f"by_year/{file_info.year}/{file_info.app_name}"
                else:
                    dest_folder = f"by_year/{file_info.year}"
            elif strategy == SortCriteria.SIZE:
                if file_info.is_versioned:
                    # Group versioned files under their app name within size folders
                    dest_folder = f"by_size/{file_info.size_category()}/{file_info.app_name}"
                else:
                    dest_folder = f"by_size/{file_info.size_category()}"
            elif strategy == SortCriteria.EXTENSION:
                ext = file_info.extension[1:] if file_info.extension else "no_extension"
                if file_info.is_versioned:
                    # Group versioned files under their app name within extension folders
                    dest_folder = f"by_extension/{ext}/{file_info.app_name}"
                else:
                    dest_folder = f"by_extension/{ext}"
            elif strategy == SortCriteria.PROJECT:
                project_name = file_info.guess_project()
                if file_info.is_versioned:
                    # For versioned files, use app name as project if it's different from guessed project
                    if file_info.app_name.lower() != project_name.lower():
                        dest_folder = f"projects/{file_info.app_name}"
                    else:
                        dest_folder = f"projects/{project_name}"
                else:
                    dest_folder = f"projects/{project_name}"
            elif strategy == SortCriteria.CUSTOM_REGEX:
                dest_folder = self._apply_custom_regex_rules(file_info)
            else:
                # Default to category-based organization
                if file_info.is_versioned:
                    dest_folder = f"{file_info.category.value}/{file_info.app_name}"
                else:
                    dest_folder = file_info.category.value
            
            if dest_folder not in plan:
                plan[dest_folder] = []
            plan[dest_folder].append(str(file_info.path))
        
        # Post-process: move beta/alpha versions under their main app folder if it exists
        plan = self._consolidate_beta_versions(plan)
        
        if not dry_run:
            self._execute_plan(target_path, plan)
        
        return plan
    
    def _consolidate_beta_versions(self, plan: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """
        Move beta/alpha versions under their main app folder if it exists.
        For example, if both 'tool' and 'tool beta' folders exist, move 'tool beta' under 'tool'.
        """
        new_plan = {}
        folders_to_remove = set()
        
        # First, identify potential beta/alpha folders and their main counterparts
        beta_mappings = {}
        
        for folder_path in plan.keys():
            folder_parts = folder_path.split('/')
            if len(folder_parts) >= 2:  # category/app_name
                category = folder_parts[0]
                app_name = folder_parts[-1].lower()  # Get the last part (app name)
                
                # Check if this looks like a beta/alpha version
                beta_indicators = ['beta', 'alpha', 'rc', 'dev', 'test', 'preview']
                for indicator in beta_indicators:
                    if indicator in app_name:
                        # Extract the base app name (remove beta/alpha part)
                        base_name = app_name.replace(f' {indicator}', '').replace(f'_{indicator}', '').replace(f'-{indicator}', '').replace(indicator, '').strip()
                        
                        # Look for the main app folder in the same category
                        main_folder = f"{category}/{base_name}"
                        if main_folder in plan:
                            # Found the main folder, plan to move beta under it
                            beta_folder_name = folder_parts[-1]  # Keep original case
                            new_beta_path = f"{main_folder}/{beta_folder_name}"
                            beta_mappings[folder_path] = new_beta_path
                            folders_to_remove.add(folder_path)
                            break
        
        # Copy all folders to new plan, applying beta mappings
        for folder_path, files in plan.items():
            if folder_path in beta_mappings:
                # This is a beta folder that should be moved
                new_path = beta_mappings[folder_path]
                new_plan[new_path] = files
            elif folder_path not in folders_to_remove:
                # This is a regular folder (including main app folders)
                new_plan[folder_path] = files
        
        return new_plan
    
    def _execute_plan(self, target_path: Path, plan: Dict[str, List[str]]):
        moved = 0
        skipped = 0
        
        for dest_folder, file_paths in plan.items():
            dest_dir = target_path / dest_folder
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            for file_path in file_paths:
                source = Path(file_path)
                destination = dest_dir / source.name
                
                # Skip if file is already in the correct location
                if source.parent == dest_dir:
                    skipped += 1
                    continue
                
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
        
        print(f"Moved {moved} files" + (f", skipped {skipped} files already in correct location" if skipped > 0 else ""))
    
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


def create_example_regex_rules() -> List[CustomRegexRule]:
    """Create a set of example custom regex rules that users can use as templates"""
    return [
        CustomRegexRule(
            name="Screenshots",
            pattern=r"(?i)screenshot[_\s-]*(\d{4})[_\s-]*(\d{2})[_\s-]*(\d{2})",
            folder_template="screenshots/{group1}/{group1}-{group2}",
            description="Organize screenshots by year and month"
        ),
        CustomRegexRule(
            name="Invoice Files",
            pattern=r"(?i)invoice[_\s-]*(?P<company>\w+)[_\s-]*(?P<date>\d{4}[-_]\d{2}[-_]\d{2})",
            folder_template="financial/invoices/{company}/{date}",
            description="Organize invoices by company and date"
        ),
        CustomRegexRule(
            name="Meeting Notes",
            pattern=r"(?i)(?:meeting|notes?)[_\s-]*(?P<project>\w+)[_\s-]*(?P<date>\d{4}[-_]\d{2}[-_]\d{2})",
            folder_template="meetings/{project}/{date}",
            description="Organize meeting notes by project and date"
        ),
        CustomRegexRule(
            name="Project Files",
            pattern=r"(?P<project>[A-Za-z]+(?:\s+[A-Za-z]+)?)[_\s-]+(?P<type>design|spec|doc|final)",
            folder_template="projects/{project}/{type}s",
            description="Organize project files by project name and type"
        ),
        CustomRegexRule(
            name="Backup Files",
            pattern=r"(?i)backup[_\s-]*(?P<source>\w+)[_\s-]*(?P<date>\d{4}[-_]\d{2}[-_]\d{2})",
            folder_template="backups/{source}/{date}",
            description="Organize backup files by source and date"
        ),
        CustomRegexRule(
            name="Photo Collections",
            pattern=r"(?i)(?P<event>\w+(?:\s+\w+)?)[_\s-]*(?P<year>\d{4})[_\s-]*(?P<month>\d{2})",
            folder_template="photos/{year}/{event}",
            description="Organize photos by event and year"
        ),
        CustomRegexRule(
            name="Code Archives",
            pattern=r"(?P<project>\w+)[_\s-]*(?:v|version)[_\s-]*(?P<version>\d+(?:\.\d+)*)",
            folder_template="code/{project}/v{version}",
            description="Organize code archives by project and version"
        ),
        CustomRegexRule(
            name="Client Work",
            pattern=r"(?i)(?P<client>\w+)[_\s-]*(?P<type>proposal|contract|delivery|invoice)",
            folder_template="clients/{client}/{type}s",
            description="Organize client work by client name and document type"
        ),
        CustomRegexRule(
            name="Year-Month Sort",
            pattern=r"(?P<year>\d{4})[_\s-]*(?P<month>\d{2})",
            folder_template="by_date/{year}/{year}-{month}",
            description="Simple year-month based organization"
        ),
        CustomRegexRule(
            name="File Types with Prefixes",
            pattern=r"(?P<prefix>\w+)[_\s-]+.*\.(?P<ext>\w+)$",
            folder_template="{category}/{prefix}",
            description="Organize by file prefix within categories"
        )
    ]


def create_custom_regex_rule_interactive() -> Optional[CustomRegexRule]:
    """Interactive helper to create a custom regex rule with validation"""
    print("\n" + "="*50)
    print("CREATE CUSTOM REGEX RULE")
    print("="*50)
    
    try:
        name = input("Rule name: ").strip()
        if not name:
            print("Rule name cannot be empty")
            return None
        
        print("\nRegex pattern (use named groups like (?P<name>pattern) for better templates):")
        pattern = input("Pattern: ").strip()
        if not pattern:
            print("Pattern cannot be empty")
            return None
        
        print("\nFolder template (use {group_name} or {group1}, {group2}, etc.):")
        print("Available variables: {category}, {year}, {month}, {size_category}, {extension}, {detected_ext}")
        folder_template = input("Template: ").strip()
        if not folder_template:
            print("Folder template cannot be empty")
            return None
        
        description = input("Description (optional): ").strip()
        
        case_sensitive = input("Case sensitive? (y/N): ").strip().lower() == 'y'
        
        rule = CustomRegexRule(
            name=name,
            pattern=pattern,
            folder_template=folder_template,
            description=description,
            case_sensitive=case_sensitive
        )
        
        # Test the rule
        print("\nTesting rule...")
        test_filename = input("Enter a test filename (or press Enter to skip): ").strip()
        if test_filename:
            matches = rule.matches(test_filename)
            if matches:
                print(f"✓ Matches! Groups found: {matches}")
                # Create a dummy FileInfo for template testing
                dummy_file = FileInfo(
                    path=Path(test_filename),
                    name=test_filename,
                    extension=Path(test_filename).suffix,
                    size=1024,
                    created=datetime.now(),
                    modified=datetime.now(),
                    category=FileCategory.OTHER,
                    mime_type='text/plain',
                    is_hidden=False
                )
                try:
                    dest = rule.generate_folder_path(matches, dummy_file)
                    print(f"✓ Would organize to: {dest}")
                except Exception as e:
                    print(f"✗ Template error: {e}")
                    return None
            else:
                print("✗ No match found")
        
        return rule
        
    except KeyboardInterrupt:
        print("\nCancelled")
        return None


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
        # Custom regex test files
        ("screenshot_2024_03_15.png", "fake screenshot"),
        ("invoice_CompanyA_2024-03-10.pdf", "fake invoice"),
        ("meeting_ProjectX_2024-03-12.docx", "fake meeting notes"),
        ("backup_database_2024-03-08.sql", "fake backup"),
        ("photo_vacation_2024_03.jpg", "fake photo"),
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
    
    # Demonstrate custom regex rules
    print("\n" + "="*50)
    print("CUSTOM REGEX RULES DEMONSTRATION")
    print("="*50)
    
    # Add some example rules
    example_rules = create_example_regex_rules()
    
    # Add a rule specifically for our test files
    custom_rule = CustomRegexRule(
        name="Test Files",
        pattern=r"(?P<type>script|data|page|report)",
        folder_template="custom/{type}_files",
        description="Custom rule for test files"
    )
    
    sorter.add_custom_regex_rule(custom_rule)
    
    # Add a versioned files rule
    version_rule = CustomRegexRule(
        name="Version Control",
        pattern=r"(?P<app>\w+)_v(?P<version>\d+\.\d+)",
        folder_template="software/{app}/versions/v{version}",
        description="Organize versioned software by app and version"
    )
    sorter.add_custom_regex_rule(version_rule)
    
    print(f"Added {len(sorter.get_custom_regex_rules())} custom rules")
    
    # Test the rules
    test_results = sorter.test_custom_regex_rules()
    for rule_name, matches in test_results.items():
        if matches:
            print(f"\nRule '{rule_name}' matches:")
            for filename, dest in matches[:3]:  # Show first 3 matches
                print(f"  {filename} → {dest}")
            if len(matches) > 3:
                print(f"  ... and {len(matches) - 3} more")
    
    recommendation = sorter.recommend_strategy()
    print(f"\nRecommended: {recommendation['strategy'].value}")
    print(f"Reason: {recommendation['reason']}")
    
    # Try organizing with custom regex if rules match files
    if recommendation['strategy'] == SortCriteria.CUSTOM_REGEX:
        plan = sorter.organize_files(SortCriteria.CUSTOM_REGEX)
        print(f"\nCustom Regex Organization Plan:")
        print(sorter.get_summary(plan))
    else:
        plan = sorter.organize_files(recommendation['strategy'])
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
    
    # Show example rules that users can use
    print("\n" + "="*50)
    print("EXAMPLE REGEX RULES")
    print("="*50)
    print("Here are some example custom regex rules you can use:")
    for rule in example_rules[:5]:  # Show first 5 examples
        print(f"\n• {rule.name}: {rule.description}")
        print(f"  Pattern: {rule.pattern}")
        print(f"  Template: {rule.folder_template}")
