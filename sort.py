import os
import re
import shutil
import mimetypes
import zipfile
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Union
from dataclasses import dataclass
from enum import Enum


class FileDetector:
    def __init__(self):
        self.sigs = {
            b'\xFF\xD8\xFF': ('jpg', 'image/jpeg'),
            b'\x89PNG\r\n\x1a\n': ('png', 'image/png'),
            b'GIF87a': ('gif', 'image/gif'),
            b'GIF89a': ('gif', 'image/gif'),
            b'BM': ('bmp', 'image/bmp'),
            b'RIFF': ('webp', 'image/webp'),
            b'\x00\x00\x01\x00': ('ico', 'image/x-icon'),
            b'%PDF': ('pdf', 'application/pdf'),
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('doc', 'application/msword'),
            b'PK\x03\x04': ('zip', 'application/zip'),
            b'Rar!\x1a\x07\x00': ('rar', 'application/x-rar-compressed'),
            b'7z\xBC\xAF\x27\x1C': ('7z', 'application/x-7z-compressed'),
            b'\x1f\x8b': ('gz', 'application/gzip'),
            b'BZh': ('bz2', 'application/x-bzip2'),
            b'\x00\x00\x00\x14ftypqt': ('mov', 'video/quicktime'),
            b'\x00\x00\x00\x18ftypmp4': ('mp4', 'video/mp4'),
            b'\x1aE\xdf\xa3': ('mkv', 'video/x-matroska'),
            b'FLV\x01': ('flv', 'video/x-flv'),
            b'ID3': ('mp3', 'audio/mpeg'),
            b'\xff\xfb': ('mp3', 'audio/mpeg'),
            b'fLaC': ('flac', 'audio/flac'),
            b'OggS': ('ogg', 'audio/ogg'),
            b'MZ': ('exe', 'application/x-msdownload'),
            b'\x7fELF': ('elf', 'application/x-executable'),
            b'#!/': ('script', 'text/plain'),
            b'<?xml': ('xml', 'application/xml'),
            b'\xef\xbb\xbf': ('utf8_bom', 'text/plain'),
        }
        
        self.special = {
            b'RIFF': self.check_riff,
            b'PK\x03\x04': self.check_zip,
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': self.check_ole,
        }
    
    def detect_type(self, file_path: Path) -> Tuple[Optional[str], Optional[str]]:
        try:
            with open(file_path, 'rb') as f:
                data = f.read(64)
                
            if not data:
                return None, None
            
            for sig, (ext, mime) in self.sigs.items():
                if data.startswith(sig):
                    if sig in self.special:
                        result = self.special[sig](data, file_path)
                        if result:
                            return result
                    return ext, mime
            
            if self.is_text(data):
                return self.guess_text(file_path, data)
                
            return None, None
            
        except:
            return None, None
    
    def check_riff(self, data: bytes, file_path: Path) -> Optional[Tuple[str, str]]:
        if len(data) >= 12:
            fmt = data[8:12]
            if fmt == b'WAVE':
                return 'wav', 'audio/wav'
            elif fmt == b'AVI ':
                return 'avi', 'video/x-msvideo'
            elif fmt == b'WEBP':
                return 'webp', 'image/webp'
        return None
    
    def check_zip(self, data: bytes, file_path: Path) -> Optional[Tuple[str, str]]:
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                files = zf.namelist()
                
                if 'word/document.xml' in files:
                    return 'docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                elif 'xl/workbook.xml' in files:
                    return 'xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                elif 'ppt/presentation.xml' in files:
                    return 'pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
                elif 'META-INF/manifest.xml' in files:
                    return 'odt', 'application/vnd.oasis.opendocument.text'
                
        except:
            pass
        
        return 'zip', 'application/zip'
    
    def check_ole(self, data: bytes, file_path: Path) -> Optional[Tuple[str, str]]:
        try:
            with open(file_path, 'rb') as f:
                content = f.read(2048)
            
            if b'Microsoft Office Word' in content or b'Word.Document' in content:
                return 'doc', 'application/msword'
            elif b'Microsoft Office Excel' in content or b'Excel.Sheet' in content:
                return 'xls', 'application/vnd.ms-excel'
            elif b'Microsoft Office PowerPoint' in content:
                return 'ppt', 'application/vnd.ms-powerpoint'
                
        except:
            pass
        
        return 'doc', 'application/msword'
    
    def is_text(self, data: bytes) -> bool:
        if not data:
            return False
        
        if data.startswith(b'\xef\xbb\xbf'):
            return True
        
        try:
            data.decode('utf-8')
            count = 0
            for b in data:
                if 32 <= b <= 126 or b in [9, 10, 13]:
                    count += 1
            return count / len(data) > 0.7
        except:
            return False
    
    def guess_text(self, file_path: Path, data: bytes) -> Tuple[str, str]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024).lower()
            
            if content.startswith('#!/'):
                if 'python' in content[:100]:
                    return 'py', 'text/x-python'
                elif 'bash' in content[:100] or 'sh' in content[:100]:
                    return 'sh', 'text/x-shellscript'
                return 'py', 'text/x-python'
            
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
                
        except:
            pass
        
        return 'txt', 'text/plain'


class FileCat(Enum):
    IMAGE = "images"
    DOCUMENT = "documents"
    VIDEO = "videos"
    AUDIO = "audio"
    ARCHIVE = "archives"
    CODE = "code"
    DATA = "data"
    OTHER = "other"


class SortBy(Enum):
    TYPE = "file_type"
    DATE = "date"
    SIZE = "file_size"
    NAME = "file_name"
    EXTENSION = "file_extension"
    PROJECT = "project"
    CUSTOM_REGEX = "custom_regex"


@dataclass
class BkpEntry:
    orig: str
    curr: str
    name: str
    size: int
    mod: str
    checksum: Optional[str] = None


@dataclass
class Backup:
    time: str
    dir: str
    strat: str
    total: int
    ver: str = "1.0"
    entries: List[BkpEntry] = None
    
    def __post_init__(self):
        if self.entries is None:
            self.entries = []


@dataclass
class FileData:
    path: Path
    name: str
    ext: str
    size: int
    created: datetime
    modified: datetime
    cat: FileCat
    mime: Optional[str]
    hidden: bool
    det_ext: Optional[str] = None
    det_mime: Optional[str] = None
    wrong: bool = False
    app: Optional[str] = None
    ver: Optional[str] = None
    versioned: bool = False
    
    @property
    def year(self) -> str:
        return str(self.modified.year)
    
    @property
    def month_folder(self) -> str:
        return f"{self.modified.year}-{self.modified.month:02d}"
    
    def size_cat(self) -> str:
        if self.size < 1024 * 1024:
            return "small"
        elif self.size < 50 * 1024 * 1024:
            return "medium"
        elif self.size < 500 * 1024 * 1024:
            return "large"
        else:
            return "huge"
    
    def guess_proj(self) -> str:
        parts = self.path.parts
        name = self.name.lower()
        
        patterns = [
            r'project[_-]?(\w+)',
            r'(\w+)[_-]project', 
            r'(\w+)[_-]v?\d+',
            r'(\w+)[_-](final|draft|report)'
        ]
        
        for p in patterns:
            match = re.search(p, name)
            if match and match.group(1) not in ['file', 'new', 'temp', 'test']:
                return match.group(1)
        
        keywords = {
            'meeting': 'meetings', 'report': 'reports', 'invoice': 'financial',
            'backup': 'backups'
        }
        
        for k, folder in keywords.items():
            if k in name:
                return folder
        
        return self.analyze_folders()
    
    def analyze_folders(self) -> str:
        path_parts = self.path.parts
        
        learned_patterns = {}
        if hasattr(self, '_parent_sorter') and self._parent_sorter:
            learned_patterns = self._parent_sorter.analyze_existing_organization()
        
        sys_dirs = {
            'users', 'user', 'home', 'documents', 'desktop', 'downloads', 'pictures', 
            'videos', 'music', 'appdata', 'program files', 'windows', 'system32',
            'applications', 'library', 'volumes', 'mnt', 'usr', 'bin', 'etc', 'var'
        }
        
        temp_dirs = {
            'temp', 'tmp', 'cache', 'backup', 'recycle', 'trash', 'archive',
            'old', 'new', 'copy', 'duplicate', 'test', 'sample'
        }
        
        candidates = []
        for i, part in enumerate(path_parts[:-1]):
            folder_name = part.lower()
            clean_name = part
            
            if len(folder_name) <= 2:
                continue
                
            if folder_name in sys_dirs:
                continue
                
            score = self.calc_score(folder_name, i, len(path_parts))
            
            if folder_name in learned_patterns:
                score += learned_patterns[folder_name] * 2.0
            
            if score > 0:
                candidates.append({
                    'name': clean_name,
                    'score': score,
                    'depth': i,
                    'folder': folder_name,
                    'learned': folder_name in learned_patterns
                })
        
        if not candidates:
            return {
                FileCat.IMAGE: 'images',
                FileCat.DOCUMENT: 'documents', 
                FileCat.VIDEO: 'videos',
                FileCat.AUDIO: 'audio',
                FileCat.CODE: 'code',
                FileCat.ARCHIVE: 'archives',
                FileCat.DATA: 'data'
            }.get(self.cat, 'misc')
        
        learned_candidates = [c for c in candidates if c.get('learned', False)]
        if learned_candidates:
            best = max(learned_candidates, key=lambda x: x['score'])
        else:
            best = max(candidates, key=lambda x: x['score'])
            
        return best['name'].replace('_', ' ').replace('-', ' ')
    
    def calc_score(self, folder_name: str, depth: int, total_depth: int) -> float:
        score = 0.0
        
        distance_from_file = (total_depth - depth - 2)
        if distance_from_file >= 0:
            score += 1.0 / (1 + distance_from_file * 0.3)
        
        positive_patterns = [
            (r'project', 2.0),
            (r'work', 1.5),
            (r'dev', 1.5),
            (r'code', 1.5),
            (r'app', 1.2),
            (r'src', 1.2),
            (r'source', 1.2),
            (r'\d{4}', 1.0),
            (r'v\d+', 0.8),
            (r'[A-Z][a-z]+[A-Z]', 1.0),
        ]
        
        for pattern, weight in positive_patterns:
            if re.search(pattern, folder_name, re.IGNORECASE):
                score += weight
        
        negative_patterns = [
            (r'^(temp|tmp|cache|backup|old|new|copy|test|sample)$', -3.0),
            (r'^(bin|lib|node_modules|__pycache__|\.git|\.vscode)$', -2.0),
            (r'^(misc|other|random|stuff|files|data)$', -1.5),
            (r'^\d+$', -1.0),
            (r'^[a-z]{1,3}$', -0.5),
        ]
        
        for pattern, weight in negative_patterns:
            if re.search(pattern, folder_name, re.IGNORECASE):
                score += weight
        
        if 4 <= len(folder_name) <= 20:
            score += 0.5
        elif len(folder_name) > 20:
            score -= 0.3
        
        if re.search(r'[A-Z]', folder_name) and re.search(r'[a-z]', folder_name):
            score += 0.3
        
        if re.search(r'[_-]', folder_name) and not re.search(r'^[_-]|[_-]$', folder_name):
            score += 0.2
        
        return score


@dataclass
class CustomRegexRule:
    name: str
    pattern: str
    folder_template: str
    description: str = ""
    case_sensitive: bool = False
    
    def matches(self, filename: str) -> Optional[Dict[str, str]]:
        flags = 0 if self.case_sensitive else re.IGNORECASE
        match = re.search(self.pattern, filename, flags)
        if match:
            groups = match.groupdict()
            for i, group in enumerate(match.groups(), 1):
                if group is not None:
                    groups[f'group{i}'] = group
            return groups
        return None
    
    def generate_folder_path(self, groups: Dict[str, str], file_info: 'FileData') -> str:
        template_vars = {
            **groups,
            'category': file_info.cat.value,
            'year': file_info.year,
            'month': file_info.month_folder,
            'size_category': file_info.size_cat(),
            'extension': file_info.ext[1:] if file_info.ext else 'no_extension',
            'detected_ext': file_info.det_ext or 'unknown'
        }
        
        try:
            return self.folder_template.format(**template_vars)
        except KeyError as e:
            return f"custom_regex/{self.name}/{groups.get('group1', 'unmatched')}"


class FileSorter:
    
    def __init__(self):
        self.detector = FileDetector()
        
        self.ext_map = {
            '.jpg': FileCat.IMAGE, '.jpeg': FileCat.IMAGE, '.png': FileCat.IMAGE,
            '.gif': FileCat.IMAGE, '.bmp': FileCat.IMAGE, '.svg': FileCat.IMAGE,
            '.webp': FileCat.IMAGE, '.ico': FileCat.IMAGE,
            
            '.pdf': FileCat.DOCUMENT, '.doc': FileCat.DOCUMENT, '.docx': FileCat.DOCUMENT,
            '.txt': FileCat.DOCUMENT, '.rtf': FileCat.DOCUMENT, '.odt': FileCat.DOCUMENT,
            '.xls': FileCat.DOCUMENT, '.xlsx': FileCat.DOCUMENT, '.ppt': FileCat.DOCUMENT,
            '.pptx': FileCat.DOCUMENT,
            
            '.mp4': FileCat.VIDEO, '.avi': FileCat.VIDEO, '.mkv': FileCat.VIDEO,
            '.mov': FileCat.VIDEO, '.wmv': FileCat.VIDEO, '.webm': FileCat.VIDEO,
            '.mp3': FileCat.AUDIO, '.wav': FileCat.AUDIO, '.flac': FileCat.AUDIO,
            '.aac': FileCat.AUDIO, '.ogg': FileCat.AUDIO,
            
            '.zip': FileCat.ARCHIVE, '.rar': FileCat.ARCHIVE, '.7z': FileCat.ARCHIVE,
            '.tar': FileCat.ARCHIVE, '.gz': FileCat.ARCHIVE,
            
            '.py': FileCat.CODE, '.js': FileCat.CODE, '.html': FileCat.CODE,
            '.css': FileCat.CODE, '.java': FileCat.CODE, '.cpp': FileCat.CODE,
            '.c': FileCat.CODE, '.php': FileCat.CODE, '.json': FileCat.CODE,
            '.xml': FileCat.CODE, '.yml': FileCat.CODE, '.yaml': FileCat.CODE,
            '.sh': FileCat.CODE, '.script': FileCat.CODE,
            
            '.csv': FileCat.DATA, '.sql': FileCat.DATA, '.db': FileCat.DATA,
        }
        
        self.files = []
        self.source_path = None
        self.rules = []
    
    def get_version_info(self, file_path: Path) -> Tuple[Optional[str], Optional[str], bool]:
        name = file_path.stem
        name_lower = name.lower()
        
        patterns = [
            r'^(.+?)_v(\d+(?:\.\d+)*(?:\.\d+)?)$',
            r'^(.+?)_version(\d+(?:\.\d+)*(?:\.\d+)?)$',
            r'^(.+?)_ver(\d+(?:\.\d+)*(?:\.\d+)?)$',
            r'^(.+?)\s+v(\d+(?:\.\d+)*(?:\.\d+)?)$',
            r'^(.+?)\s+version\s+(\d+(?:\.\d+)*(?:\.\d+)?)$',
            r'^(.+?)\s+ver\s+(\d+(?:\.\d+)*(?:\.\d+)?)$',
            r'^(.+?)\s*[\(\[]v?(\d+(?:\.\d+)*(?:\.\d+)?)[\)\]]$',
            r'^(.+?)(\d+)$',
            r'^(.+?)_(\d{4})(?:\d{4})?$',
            
            r'^(.+?)_(final|beta|alpha|rc)(\d*)$',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, name_lower)
            if match:
                app_name = match.group(1).strip()
                version_part = match.group(2) if len(match.groups()) >= 2 else "1"
                
                app_name = re.sub(r'[_\-\s]+', ' ', app_name).strip()
                
                if len(app_name) < 2 or app_name in ['new', 'old', 'temp', 'test', 'file', 'document', 'image']:
                    continue
                
                if len(match.groups()) >= 3:
                    release_type = match.group(2)
                    release_num = match.group(3) or ""
                    version_part = f"{release_type}{release_num}"
                
                return app_name, version_part, True
        
        return None, None, False
        
    def scan(self, folder_path: Union[str, Path]) -> List[FileData]:
        self.source_path = Path(folder_path)
        if not self.source_path.exists():
            raise ValueError(f"Folder doesn't exist: {folder_path}")
        
        self.files = []
        for file_path in self.source_path.rglob('*'):
            if file_path.is_file():
                self.files.append(self.analyze(file_path))
        
        return self.files
    
    def analyze(self, file_path: Path) -> FileData:
        stat = file_path.stat()
        
        name = file_path.name
        extension = file_path.suffix.lower()
        size = stat.st_size
        created = datetime.fromtimestamp(stat.st_ctime)
        modified = datetime.fromtimestamp(stat.st_mtime)
        is_hidden = name.startswith('.')
        
        detected_ext, detected_mime = self.detector.detect_type(file_path)
        
        is_misnamed = False
        if detected_ext:
            if extension and extension != f".{detected_ext}":
                ext_category = self.ext_map.get(extension, FileCat.OTHER)
                detected_category = self.ext_map.get(f".{detected_ext}", FileCat.OTHER)
                if ext_category != detected_category:
                    is_misnamed = True
            elif not extension:
                is_misnamed = True
        
        final_ext = f".{detected_ext}" if detected_ext else extension
        category = self.ext_map.get(final_ext, FileCat.OTHER)
        
        if extension:
            category = self.ext_map.get(extension, FileCat.OTHER)
        
        if not extension and detected_ext:
            detected_cat = self.ext_map.get(f".{detected_ext}", FileCat.OTHER)
            if detected_cat != FileCat.OTHER:
                category = detected_cat
        
        elif is_misnamed and detected_ext and extension:
            ext_category = self.ext_map.get(extension, FileCat.OTHER)
            detected_category = self.ext_map.get(f".{detected_ext}", FileCat.OTHER)
            
            if ext_category == FileCat.OTHER:
                category = detected_category
        
        mime_type = detected_mime or mimetypes.guess_type(str(file_path))[0]
        
        app_name, version, is_versioned = self.get_version_info(file_path)
        
        file_info = FileData(
            path=file_path,
            name=name,
            ext=extension,
            size=size,
            created=created,
            modified=modified,
            cat=category,
            mime=mime_type,
            hidden=is_hidden,
            det_ext=detected_ext,
            det_mime=detected_mime,
            wrong=is_misnamed,
            app=app_name,
            ver=version,
            versioned=is_versioned
        )
        
        file_info._parent_sorter = self
        
        return file_info
    
    def recommend(self) -> Dict:
        if not self.files:
            return {"strategy": SortBy.TYPE, "reason": "No files to analyze"}
        
        total = len(self.files)
        categories = {}
        years = set()
        
        for f in self.files:
            categories[f.cat.value] = categories.get(f.cat.value, 0) + 1
            years.add(f.year)
        
        if self.rules:
            matches = sum(1 for f in self.files 
                         for rule in self.rules 
                         if rule.matches(f.name))
            if matches > total * 0.3:
                return {
                    "strategy": SortBy.CUSTOM_REGEX,
                    "reason": f"Custom regex rules match {matches}/{total} files",
                    "confidence": 80
                }
        
        if len(categories) > 3 and max(categories.values()) / total < 0.8:
            return {
                "strategy": SortBy.TYPE,
                "reason": f"Multiple file types found ({len(categories)} categories)",
                "confidence": 85
            }
        
        if len(years) > 2:
            return {
                "strategy": SortBy.DATE,
                "reason": f"Files span multiple years ({min(years)}-{max(years)})",
                "confidence": 70
            }
        
        return {
            "strategy": SortBy.TYPE,
            "reason": "General purpose organization",
            "confidence": 60
        }
    
    def add_rule(self, rule: CustomRegexRule) -> None:
        self.rules.append(rule)
    
    def remove_rule(self, rule_name: str) -> bool:
        for i, rule in enumerate(self.rules):
            if rule.name == rule_name:
                del self.rules[i]
                return True
        return False
    
    def clear_rules(self) -> None:
        self.rules.clear()
    
    def get_rules(self) -> List[CustomRegexRule]:
        return self.rules.copy()
    
    def apply_rules(self, file_info: FileData) -> str:
        filename = file_info.name
        
        for rule in self.rules:
            groups = rule.matches(filename)
            if groups:
                try:
                    return rule.generate_folder_path(groups, file_info)
                except Exception as e:
                    continue
        
        if file_info.versioned:
            return f"custom_unmatched/{file_info.cat.value}/{file_info.app}"
        else:
            return f"custom_unmatched/{file_info.cat.value}"
    
    def validate_rule(self, rule: CustomRegexRule) -> List[str]:
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
            dummy_file_info = FileData(
                path=Path('test.txt'),
                name='test.txt',
                extension='.txt',
                size=1024,
                created=datetime.now(),
                modified=datetime.now(),
                category=FileCat.DOCUMENT,
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
    
    def organize_files(self, strategy: SortBy, dry_run: bool = True, create_backup: bool = True, exclude_new_files: bool = False) -> Dict[str, List[str]]:
        if not self.source_path:
            raise ValueError("No source folder has been scanned. Call scan() first.")

        backup_path = None
        backup_file_names = set()
        
        if create_backup and not dry_run:
            try:
                backup_path = self.create_backup(strategy)
                
                if exclude_new_files:
                    backup = self.load_backup(backup_path)
                    backup_file_names = {entry.name for entry in backup.entries}
                    
            except Exception as e:
                # Proceeding without backup...
                pass

        target_path = self.source_path
        plan = {}
        excluded_new_files = []
        
        for file_info in self.files:
            if exclude_new_files and backup_file_names and file_info.name not in backup_file_names:
                excluded_new_files.append(file_info.name)
                continue
                
            if strategy == SortBy.TYPE:
                if file_info.versioned:
                    dest_folder = f"{file_info.cat.value}/{file_info.app}"
                else:
                    dest_folder = file_info.cat.value
            elif strategy == SortBy.DATE:
                if file_info.versioned:
                    dest_folder = f"by_year/{file_info.year}/{file_info.app}"
                else:
                    dest_folder = f"by_year/{file_info.year}"
            elif strategy == SortBy.SIZE:
                if file_info.versioned:
                    dest_folder = f"by_size/{file_info.size_cat()}/{file_info.app}"
                else:
                    dest_folder = f"by_size/{file_info.size_cat()}"
            elif strategy == SortBy.EXTENSION:
                ext = file_info.ext[1:] if file_info.ext else "no_extension"
                if file_info.versioned:
                    dest_folder = f"by_extension/{ext}/{file_info.app}"
                else:
                    dest_folder = f"by_extension/{ext}"
            elif strategy == SortBy.PROJECT:
                project_name = file_info.guess_proj()
                if file_info.versioned:
                    if file_info.app.lower() != project_name.lower():
                        dest_folder = f"projects/{file_info.app}"
                    else:
                        dest_folder = f"projects/{project_name}"
                else:
                    dest_folder = f"projects/{project_name}"
            elif strategy == SortBy.CUSTOM_REGEX:
                dest_folder = self.apply_rules(file_info)
            else:
                if file_info.versioned:
                    dest_folder = f"{file_info.cat.value}/{file_info.app}"
                else:
                    dest_folder = file_info.cat.value
            
            if dest_folder not in plan:
                plan[dest_folder] = []
            plan[dest_folder].append(str(file_info.path))
        
        if excluded_new_files:
            pass
        
        plan = self.beta_consolidate(plan)
        
        if not dry_run:
            self.do_organize(target_path, plan)
            
            if backup_path:
                self.update_backup_locations(backup_path, plan)
        
        return plan
    
    def beta_consolidate(self, plan: Dict[str, List[str]]) -> Dict[str, List[str]]:
        new_plan = {}
        folders_to_remove = set()
        beta_mappings = {}
        
        for folder_path in plan.keys():
            folder_parts = folder_path.split('/')
            if len(folder_parts) >= 2:
                category = folder_parts[0]
                app_name = folder_parts[-1].lower()
                
                beta_indicators = ['beta', 'alpha', 'rc', 'dev', 'test', 'preview']
                for indicator in beta_indicators:
                    if indicator in app_name:
                        base_name = app_name.replace(f' {indicator}', '').replace(f'_{indicator}', '').replace(f'-{indicator}', '').replace(indicator, '').strip()
                        
                        main_folder = f"{category}/{base_name}"
                        if main_folder in plan:
                            beta_folder_name = folder_parts[-1]
                            new_beta_path = f"{main_folder}/{beta_folder_name}"
                            beta_mappings[folder_path] = new_beta_path
                            folders_to_remove.add(folder_path)
                        break
        
        for folder_path, files in plan.items():
            if folder_path in beta_mappings:
                new_path = beta_mappings[folder_path]
                new_plan[new_path] = files
            elif folder_path not in folders_to_remove:
                new_plan[folder_path] = files
        
        return new_plan
    
    def do_organize(self, target_path: Path, plan: Dict[str, List[str]]):
        moved = 0
        skipped = 0
        
        for dest_folder, file_paths in plan.items():
            dest_dir = target_path / dest_folder
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            for file_path in file_paths:
                source = Path(file_path)
                destination = dest_dir / source.name
                
                if source.parent == dest_dir:
                    skipped += 1
                    continue
                
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
                    pass
    
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
            "misnamed_files": sum(1 for f in self.files if f.wrong),
            "extension_less": sum(1 for f in self.files if not f.ext),
            "detected_types": sum(1 for f in self.files if f.det_ext),
            "versioned_files": sum(1 for f in self.files if f.versioned),
            "app_groups": {}
        }
        
        for f in self.files:
            cat = f.cat.value
            stats["categories"][cat] = stats["categories"].get(cat, 0) + 1
            
            if f.versioned:
                app = f.app
                if app not in stats["app_groups"]:
                    stats["app_groups"][app] = {"count": 0, "versions": set()}
                stats["app_groups"][app]["count"] += 1
                stats["app_groups"][app]["versions"].add(f.ver)
        
        for app_info in stats["app_groups"].values():
            app_info["versions"] = sorted(list(app_info["versions"]))
        
        return stats
    
    def get_versioned_files(self) -> List[FileData]:
        return [f for f in self.files if f.versioned]
    
    def get_version_groups(self) -> Dict[str, List[FileData]]:
        groups = {}
        for f in self.files:
            if f.versioned:
                if f.app not in groups:
                    groups[f.app] = []
                groups[f.app].append(f)
        return groups
    
    def get_misnamed_files(self) -> List[FileData]:
        return [f for f in self.files if f.wrong]
    
    def analyze_existing_organization(self) -> Dict[str, float]:
        if not self.files:
            return {}
        
        folder_analysis = {}
        
        folder_file_counts = {}
        folder_depths = {}
        
        for file_info in self.files:
            parts = file_info.path.parts
            
            for i, part in enumerate(parts[:-1]):
                folder_key = part.lower()
                
                if folder_key not in folder_file_counts:
                    folder_file_counts[folder_key] = 0
                    folder_depths[folder_key] = []
                
                folder_file_counts[folder_key] += 1
                folder_depths[folder_key].append(i)
        
        for folder, count in folder_file_counts.items():
            if count < 3:
                continue
                
            usage_score = min(count / len(self.files), 0.5)
            
            depths = folder_depths[folder]
            depth_consistency = 1.0 / (1.0 + len(set(depths)))
            
            avg_depth = sum(depths) / len(depths)
            depth_score = 1.0 / (1.0 + abs(avg_depth - 3))
            
            significance = usage_score * depth_consistency * depth_score
            folder_analysis[folder] = significance
        
        return folder_analysis
    
    def get_adaptive_project_suggestions(self) -> Dict[str, List[str]]:
        """
        Use the learned organizational patterns to suggest better project groupings.
        """
        patterns = self.analyze_existing_organization()
        suggestions = {}
        
        # Group files by their most significant folder
        for file_info in self.files:
            best_folder = None
            best_score = 0
            
            parts = file_info.path.parts
            for part in parts[:-1]:  # exclude filename
                folder_key = part.lower()
                if folder_key in patterns and patterns[folder_key] > best_score:
                    best_score = patterns[folder_key]
                    best_folder = part
            
            if best_folder:
                if best_folder not in suggestions:
                    suggestions[best_folder] = []
                suggestions[best_folder].append(file_info.name)
        
        return suggestions
    
    def create_backup(self, strategy: SortBy) -> str:
        if not self.source_path or not self.files:
            raise ValueError("No files to backup. Scan a folder first.")
        
        backup = Backup(
            time=datetime.now().isoformat(),
            dir=str(self.source_path),
            strat=strategy.value,
            total=len(self.files)
        )
        
        for file_info in self.files:
            try:
                relative_path = file_info.path.relative_to(self.source_path)
            except ValueError:
                relative_path = file_info.path
            
            entry = BkpEntry(
                orig=str(relative_path),
                curr=str(relative_path),
                name=file_info.name,
                size=file_info.size,
                mod=file_info.modified.isoformat()
            )
            backup.entries.append(entry)
        
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"reorg_backup_{timestamp_str}.bkp"
        backup_path = self.source_path / backup_filename
        
        backup_data = {
            'timestamp': backup.time,
            'source_directory': backup.dir,
            'strategy_used': backup.strat,
            'total_files': backup.total,
            'backup_version': backup.ver,
            'entries': [
                {
                    'original_path': entry.orig,
                    'current_path': entry.curr,
                    'file_name': entry.name,
                    'file_size': entry.size,
                    'last_modified': entry.mod,
                    'checksum': entry.checksum
                }
                for entry in backup.entries
            ]
        }
        
        try:
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
            return str(backup_path)
            
        except Exception as e:
            raise Exception(f"Failed to create backup file: {e}")
    
    def load_backup(self, backup_path: Union[str, Path]) -> Backup:
        """Load a backup file and return the SortingBackup object"""
        backup_path = Path(backup_path)
        
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup file not found: {backup_path}")
        
        if not backup_path.suffix == '.bkp':
            raise ValueError("Invalid backup file. Must have .bkp extension")
        
        try:
            with open(backup_path, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            # Validate backup format
            required_fields = ['timestamp', 'source_directory', 'strategy_used', 'total_files', 'entries']
            for field in required_fields:
                if field not in backup_data:
                    raise ValueError(f"Invalid backup file: missing '{field}' field")
            
            # Create backup object
            backup = Backup(
                timestamp=backup_data['timestamp'],
                source_directory=backup_data['source_directory'],
                strategy_used=backup_data['strategy_used'],
                total_files=backup_data['total_files'],
                backup_version=backup_data.get('backup_version', '1.0')
            )
            
            # Load entries
            for entry_data in backup_data['entries']:
                entry = BkpEntry(
                    original_path=entry_data['original_path'],
                    current_path=entry_data['current_path'],
                    file_name=entry_data['file_name'],
                    file_size=entry_data['file_size'],
                    last_modified=entry_data['last_modified'],
                    checksum=entry_data.get('checksum')
                )
                backup.entries.append(entry)
            
            return backup
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid backup file format: {e}")
        except Exception as e:
            raise Exception(f"Failed to load backup file: {e}")
    
    def restore_from_backup(self, backup_path: Union[str, Path], dry_run: bool = True) -> Dict[str, any]:
        """
        Restore files to their original locations using a backup file.
        
        Args:
            backup_path: Path to the .bkp backup file
            dry_run: If True, only show what would be restored without moving files
            
        Returns:
            Dictionary with restoration results and statistics
        """
        backup = self.load_backup(backup_path)
        
        # Verify we're in the correct directory
        current_source = Path(backup.source_directory)
        if not current_source.exists():
            raise ValueError(f"Original source directory not found: {current_source}")
        
        # Track restoration progress
        results = {
            'total_entries': len(backup.entries),
            'restored': 0,
            'missing': 0,
            'conflicts': 0,
            'errors': 0,
            'updated_files': 0,
            'user_deleted': 0,
            'user_updated': 0,
            'missing_files': [],
            'conflicts_found': [],
            'errors_encountered': [],
            'updated_files_info': [],
            'user_decisions': []
        }
        
        # Restore operation starting
        
        # First pass: identify all files and their status
        missing_entries = []
        
        for entry in backup.entries:
            try:
                # Construct current and original paths
                original_abs_path = current_source / entry.original_path
                
                # Try to find the file using multiple methods
                current_file = self._find_file_for_restore(entry, current_source)
                
                if not current_file:
                    missing_entries.append(entry)
                    continue
                
                # Check if file is already in the correct location
                if current_file == original_abs_path:
                    results['restored'] += 1  # Already in correct place
                    continue
                
                # Check for conflicts at destination
                if original_abs_path.exists() and original_abs_path != current_file:
                    results['conflicts'] += 1
                    results['conflicts_found'].append({
                        'file': entry.file_name,
                        'original_location': str(original_abs_path),
                        'blocking_file': str(original_abs_path)
                    })
                    continue
                
                if not dry_run:
                    # Create destination directory if needed
                    original_abs_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Move file back to original location
                    shutil.move(str(current_file), str(original_abs_path))
                
                results['restored'] += 1
                
            except Exception as e:
                results['errors'] += 1
                results['errors_encountered'].append({
                    'file': entry.file_name,
                    'error': str(e)
                })
        
        # Handle missing files non-interactively
        if missing_entries:
            # Non-interactive mode - just count as missing
            results['missing'] = len(missing_entries)
            results['missing_files'] = [entry.file_name for entry in missing_entries]
        
        # Restore operation complete
        
        return results
    
    def _find_file_for_restore(self, entry: BkpEntry, search_dir: Path) -> Optional[Path]:
        """
        Find a file for restoration using multiple identification methods.
        
        Args:
            entry: The backup entry to find
            search_dir: Directory to search in
            
        Returns:
            Path to the found file, or None if not found
        """
        # Method 1: Exact name and size match
        for file_path in search_dir.rglob(entry.file_name):
            if file_path.is_file() and file_path.stat().st_size == entry.file_size:
                return file_path
        
        # Method 2: Name match with different size (potential update)
        name_matches = []
        for file_path in search_dir.rglob(entry.file_name):
            if file_path.is_file():
                name_matches.append(file_path)
        
        if name_matches:
            # If there's only one file with the same name, it's likely the updated version
            if len(name_matches) == 1:
                file_path = name_matches[0]
                # Check if modification time suggests it was updated after backup
                try:
                    backup_time = datetime.fromisoformat(entry.last_modified)
                    file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_time > backup_time:
                        # File was modified after backup - likely updated
                        return file_path
                except (ValueError, OSError):
                    pass
        
        return None
    
    def _find_similar_files(self, entry: BkpEntry, search_dir: Path) -> List[Tuple[Path, int]]:
        """
        Find files with similar names to the missing file.
        
        Args:
            entry: The backup entry to find similar files for
            search_dir: Directory to search in
            
        Returns:
            List of tuples (file_path, file_size) sorted by similarity
        """
        similar_files = []
        entry_name_lower = entry.file_name.lower()
        entry_stem = Path(entry.file_name).stem.lower()
        
        for file_path in search_dir.rglob('*'):
            if not file_path.is_file():
                continue
                
            file_name_lower = file_path.name.lower()
            file_stem_lower = file_path.stem.lower()
            
            # Skip exact matches (these should have been found already)
            if file_path.name == entry.file_name:
                continue
            
            similarity_score = 0
            
            # Check for stem similarity (filename without extension)
            if entry_stem in file_stem_lower or file_stem_lower in entry_stem:
                similarity_score += 3
            
            # Check for partial name matches
            if entry_stem in file_name_lower or file_name_lower in entry_name_lower:
                similarity_score += 2
            
            # Check for same extension
            if Path(entry.file_name).suffix.lower() == file_path.suffix.lower():
                similarity_score += 1
            
            if similarity_score > 0:
                try:
                    file_size = file_path.stat().st_size
                    similar_files.append((file_path, file_size))
                except OSError:
                    continue
        
        # Sort by similarity (we could implement more sophisticated scoring)
        # For now, just sort by name similarity
        similar_files.sort(key=lambda x: x[0].name.lower())
        
        return similar_files

    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def list_available_backups(self, directory: Optional[Union[str, Path]] = None) -> List[Dict[str, str]]:
        """
        List all available backup files in the specified directory.
        If no directory specified, uses the current source directory.
        """
        search_dir = Path(directory) if directory else self.source_path
        
        if not search_dir or not search_dir.exists():
            return []
        
        backups = []
        for backup_file in search_dir.glob("*.bkp"):
            try:
                backup = self.load_backup(backup_file)
                backups.append({
                    'filename': backup_file.name,
                    'path': str(backup_file),
                    'timestamp': backup.timestamp,
                    'strategy': backup.strategy_used,
                    'file_count': backup.total_files,
                    'size': f"{backup_file.stat().st_size} bytes"
                })
            except Exception:
                # Skip invalid backup files
                continue
        
        # Sort by timestamp (newest first)
        backups.sort(key=lambda x: x['timestamp'], reverse=True)
        return backups
    
    def update_backup_locations(self, backup_path: str, organization_plan: Dict[str, List[str]]) -> None:
        """Update the backup file with new file locations after organizing"""
        try:
            backup = self.load_backup(backup_path)
            
            # Create a mapping from filename to new location
            file_to_new_location = {}
            for dest_folder, file_paths in organization_plan.items():
                for file_path in file_paths:
                    file_name = Path(file_path).name
                    # Store relative path from source directory
                    try:
                        relative_new_path = Path(dest_folder) / file_name
                        file_to_new_location[file_name] = str(relative_new_path)
                    except Exception:
                        continue
            
            # Update backup entries with new locations
            for entry in backup.entries:
                if entry.file_name in file_to_new_location:
                    entry.current_path = file_to_new_location[entry.file_name]
            
            # Save updated backup
            backup_data = {
                'timestamp': backup.timestamp,
                'source_directory': backup.source_directory,
                'strategy_used': backup.strategy_used,
                'total_files': backup.total_files,
                'backup_version': backup.backup_version,
                'entries': [
                    {
                        'original_path': entry.original_path,
                        'current_path': entry.current_path,
                        'file_name': entry.file_name,
                        'file_size': entry.file_size,
                        'last_modified': entry.last_modified,
                        'checksum': entry.checksum
                    }
                    for entry in backup.entries
                ]
            }
            
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            # Warning: Could not update backup with new locations - continuing silently
            pass

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
