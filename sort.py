import os
import re
import shutil
import mimetypes
import zipfile
import tarfile
import gzip
import json
import threading
import time
import pickle
import logging
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Union, Callable
from dataclasses import dataclass, field
from enum import Enum

try:
    import rarfile
    RAR_AVAILABLE = True
except ImportError:
    RAR_AVAILABLE = False


def setup_error_logging():
    temp_dir = Path(tempfile.gettempdir()) / "reorg_logs"
    temp_dir.mkdir(exist_ok=True)
    
    cutoff_date = datetime.now() - timedelta(days=30)
    for log_file in temp_dir.glob("reorg_*.log"):
        try:
            if datetime.fromtimestamp(log_file.stat().st_mtime) < cutoff_date:
                log_file.unlink()
        except (OSError, ValueError):
            pass
    
    logger = logging.getLogger('reorg')
    logger.setLevel(logging.INFO)
    
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = temp_dir / f"reorg_{timestamp}.log"
    
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    
    print(f"ReORG error logs will be saved to: {log_file}")
    logger.info(f"ReORG session started - Log file: {log_file}")
    
    return logger

logger = setup_error_logging()


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
            
        except PermissionError as e:
            logger.warning(f"Permission denied accessing file {file_path}: {e}")
            return None, None
        except OSError as e:
            logger.error(f"OS error reading file {file_path}: {e}")
            return None, None
        except Exception as e:
            logger.error(f"Unexpected error detecting file type for {file_path}: {e}")
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
                
        except zipfile.BadZipFile as e:
            logger.debug(f"File {file_path} is not a valid ZIP file: {e}")
        except PermissionError as e:
            logger.warning(f"Permission denied accessing ZIP file {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error checking ZIP file {file_path}: {e}")
        
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
                
        except PermissionError as e:
            logger.warning(f"Permission denied accessing OLE file {file_path}: {e}")
        except OSError as e:
            logger.error(f"OS error reading OLE file {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error checking OLE file {file_path}: {e}")
        
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
        except UnicodeDecodeError:
            return False
        except Exception as e:
            logger.debug(f"Error checking if data is text: {e}")
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
                
        except UnicodeDecodeError:
            logger.debug(f"File {file_path} contains non-UTF-8 text")
        except Exception as e:
            logger.debug(f"Error analyzing text file {file_path}: {e}")
        
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


class CompressionFormat(Enum):
    NONE = "none"
    ZIP = "zip"
    RAR = "rar"
    TAR_GZ = "tar.gz"


class ScheduleType(Enum):
    ONE_TIME = "one_time"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class ScheduleStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


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
class ScheduleTask:
    id: str
    name: str
    folder_path: str
    strategy: 'SortBy'
    compression: CompressionFormat
    schedule_type: ScheduleType
    next_run: datetime
    status: ScheduleStatus = ScheduleStatus.PENDING
    created: datetime = field(default_factory=datetime.now)
    last_run: Optional[datetime] = None
    last_result: Optional[str] = None
    error_message: Optional[str] = None
    # For recurring schedules
    interval_days: Optional[int] = None
    run_count: int = 0
    max_runs: Optional[int] = None
    enabled: bool = True


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
        self.files = []
        self.source_path = Path(folder_path)
        
        if not self.source_path.exists():
            logger.error(f"Source path does not exist: {folder_path}")
            raise ValueError(f"Folder doesn't exist: {folder_path}")
            
        if not self.source_path.is_dir():
            logger.error(f"Source path is not a directory: {folder_path}")
            raise ValueError(f"Path is not a directory: {folder_path}")
        
        logger.info(f"Starting scan of directory: {folder_path}")
        
        try:
            for file_path in self.source_path.rglob('*'):
                if file_path.is_file():
                    try:
                        file_info = self.analyze(file_path)
                        self.files.append(file_info)
                    except PermissionError as e:
                        logger.warning(f"Permission denied accessing file {file_path}: {e}")
                    except Exception as e:
                        logger.error(f"Error analyzing file {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error during directory scan: {e}")
            raise
        
        logger.info(f"Scan completed. Found {len(self.files)} files.")
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
        errors = []
        
        try:
            re.compile(rule.pattern)
        except re.error as e:
            errors.append(f"Invalid regex pattern: {e}")
        
        try:
            validation_groups = {'group1': 'example', 'group2': 'value'}
            validation_file = FileData(
                path=Path('validation.txt'),
                name='validation.txt',
                ext='.txt',
                size=1024,
                created=datetime.now(),
                modified=datetime.now(),
                cat=FileCat.DOCUMENT,
                mime='text/plain',
                hidden=False
            )
            rule.generate_folder_path(validation_groups, validation_file)
        except Exception as e:
            errors.append(f"Invalid folder template: {e}")
        
        return errors
    
    def test_custom_regex_rules(self) -> Dict[str, List[Tuple[str, str]]]:
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
    
    def organize_files(self, strategy: SortBy, dry_run: bool = True, create_backup: bool = True, 
                      exclude_new_files: bool = False, compression: CompressionFormat = CompressionFormat.NONE) -> Union[Dict[str, List[str]], str]:
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
                logger.warning(f"Failed to create backup: {e}")
                backup_path = None

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
            if compression != CompressionFormat.NONE:
                archive_path = self.compress_organized_files(target_path, plan, compression)
                
                if backup_path:
                    self.update_backup_locations(backup_path, plan)
                
                return archive_path
            else:
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
                    logger.info(f"Moved file: {source} -> {destination}")
                except PermissionError as e:
                    logger.warning(f"Permission denied moving file {source}: {e}")
                    skipped += 1
                except OSError as e:
                    logger.error(f"OS error moving file {source}: {e}")
                    skipped += 1
                except Exception as e:
                    logger.error(f"Unexpected error moving file {source}: {e}")
                    skipped += 1
    
    def compress_organized_files(self, target_path: Path, plan: Dict[str, List[str]], 
                                compression_format: CompressionFormat = CompressionFormat.ZIP) -> str:
        if compression_format == CompressionFormat.NONE:
            self.do_organize(target_path, plan)
            return str(target_path)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_org_dir = target_path / f"reorg_temp_{timestamp}"
        temp_org_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            self._organize_to_temp_dir(temp_org_dir, plan)
            
            if compression_format == CompressionFormat.ZIP:
                archive_path = target_path / f"organized_files_{timestamp}.zip"
                self._create_zip_archive(temp_org_dir, archive_path)
            elif compression_format == CompressionFormat.RAR:
                archive_path = target_path / f"organized_files_{timestamp}.rar"
                actual_archive_path = self._create_rar_archive(temp_org_dir, archive_path)
                archive_path = actual_archive_path
            elif compression_format == CompressionFormat.TAR_GZ:
                archive_path = target_path / f"organized_files_{timestamp}.tar.gz"
                self._create_tar_archive(temp_org_dir, archive_path, compressed=True)
            else:
                raise ValueError(f"Unsupported compression format: {compression_format}")
            
            return str(archive_path)
            
        finally:
            if temp_org_dir.exists():
                shutil.rmtree(temp_org_dir)
    
    def _organize_to_temp_dir(self, temp_dir: Path, plan: Dict[str, List[str]]):
        moved = 0
        
        for dest_folder, file_paths in plan.items():
            dest_dir = temp_dir / dest_folder
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            for file_path in file_paths:
                source = Path(file_path)
                destination = dest_dir / source.name
                
                counter = 1
                while destination.exists():
                    stem = source.stem
                    suffix = source.suffix
                    destination = dest_dir / f"{stem}_{counter}{suffix}"
                    counter += 1
                
                try:
                    shutil.copy2(str(source), str(destination))
                    moved += 1
                except Exception as e:
                    continue
    
    def _create_zip_archive(self, source_dir: Path, archive_path: Path):
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in source_dir.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(source_dir)
                    zipf.write(file_path, arcname)
    
    def _create_tar_archive(self, source_dir: Path, archive_path: Path, compressed: bool = False):
        mode = 'w:gz' if compressed else 'w'
        
        with tarfile.open(archive_path, mode) as tarf:
            for file_path in source_dir.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(source_dir)
                    tarf.add(file_path, arcname)
    
    def _create_rar_archive(self, source_dir: Path, archive_path: Path):
        if not RAR_AVAILABLE:
            import subprocess
            
            rar_commands = ['rar', 'winrar', 'C:\\Program Files\\WinRAR\\Rar.exe', 'C:\\Program Files (x86)\\WinRAR\\Rar.exe']
            
            rar_exe = None
            for cmd in rar_commands:
                try:
                    result = subprocess.run([cmd], capture_output=True, timeout=5)
                    rar_exe = cmd
                    break
                except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                    continue
            
            if not rar_exe:
                zip_path = archive_path.with_suffix('.zip')
                self._create_zip_archive(source_dir, zip_path)
                return zip_path
            
            try:
                subprocess.run([
                    rar_exe, 'a', '-r', str(archive_path), str(source_dir / '*')
                ], check=True, capture_output=True)
                return archive_path
            except subprocess.CalledProcessError:
                zip_path = archive_path.with_suffix('.zip')
                self._create_zip_archive(source_dir, zip_path)
                return zip_path
        else:
            zip_path = archive_path.with_suffix('.zip')
            self._create_zip_archive(source_dir, zip_path)
            return zip_path
    
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
        patterns = self.analyze_existing_organization()
        suggestions = {}
        
        for file_info in self.files:
            best_folder = None
            best_score = 0
            
            parts = file_info.path.parts
            for part in parts[:-1]:
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
        backup_path = Path(backup_path)
        
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup file not found: {backup_path}")
        
        if not backup_path.suffix == '.bkp':
            raise ValueError("Invalid backup file. Must have .bkp extension")
        
        try:
            with open(backup_path, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            required_fields = ['timestamp', 'source_directory', 'strategy_used', 'total_files', 'entries']
            for field in required_fields:
                if field not in backup_data:
                    raise ValueError(f"Invalid backup file: missing '{field}' field")
            
            backup = Backup(
                timestamp=backup_data['timestamp'],
                source_directory=backup_data['source_directory'],
                strategy_used=backup_data['strategy_used'],
                total_files=backup_data['total_files'],
                backup_version=backup_data.get('backup_version', '1.0')
            )
            
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
        backup = self.load_backup(backup_path)
        
        current_source = Path(backup.source_directory)
        if not current_source.exists():
            raise ValueError(f"Original source directory not found: {current_source}")
        
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
        
        missing_entries = []
        
        for entry in backup.entries:
            try:
                original_abs_path = current_source / entry.original_path
                
                current_file = self._find_file_for_restore(entry, current_source)
                
                if not current_file:
                    missing_entries.append(entry)
                    continue
                
                if current_file == original_abs_path:
                    results['restored'] += 1
                    continue
                
                if original_abs_path.exists() and original_abs_path != current_file:
                    results['conflicts'] += 1
                    results['conflicts_found'].append({
                        'file': entry.file_name,
                        'original_location': str(original_abs_path),
                        'blocking_file': str(original_abs_path)
                    })
                    continue
                
                if not dry_run:
                    original_abs_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    shutil.move(str(current_file), str(original_abs_path))
                
                results['restored'] += 1
                
            except Exception as e:
                results['errors'] += 1
                results['errors_encountered'].append({
                    'file': entry.file_name,
                    'error': str(e)
                })
        
        if missing_entries:
            results['missing'] = len(missing_entries)
            results['missing_files'] = [entry.file_name for entry in missing_entries]
        
        return results
    
    def _find_file_for_restore(self, entry: BkpEntry, search_dir: Path) -> Optional[Path]:
        for file_path in search_dir.rglob(entry.file_name):
            if file_path.is_file() and file_path.stat().st_size == entry.file_size:
                return file_path
        
        name_matches = []
        for file_path in search_dir.rglob(entry.file_name):
            if file_path.is_file():
                name_matches.append(file_path)
        
        if name_matches:
            if len(name_matches) == 1:
                file_path = name_matches[0]
                try:
                    backup_time = datetime.fromisoformat(entry.last_modified)
                    file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_time > backup_time:
                        return file_path
                except (ValueError, OSError):
                    pass
        
        return None
    
    def _find_similar_files(self, entry: BkpEntry, search_dir: Path) -> List[Tuple[Path, int]]:
        similar_files = []
        entry_name_lower = entry.file_name.lower()
        entry_stem = Path(entry.file_name).stem.lower()
        
        for file_path in search_dir.rglob('*'):
            if not file_path.is_file():
                continue
                
            file_name_lower = file_path.name.lower()
            file_stem_lower = file_path.stem.lower()
            
            if file_path.name == entry.file_name:
                continue
            
            similarity_score = 0
            
            if entry_stem in file_stem_lower or file_stem_lower in entry_stem:
                similarity_score += 3
            
            if entry_stem in file_name_lower or file_name_lower in entry_name_lower:
                similarity_score += 2
            
            if Path(entry.file_name).suffix.lower() == file_path.suffix.lower():
                similarity_score += 1
            
            if similarity_score > 0:
                try:
                    file_size = file_path.stat().st_size
                    similar_files.append((file_path, file_size))
                except OSError:
                    continue
        
        similar_files.sort(key=lambda x: x[0].name.lower())
        
        return similar_files

    def _format_size(self, size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def _format_size(self, size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def list_available_backups(self, directory: Optional[Union[str, Path]] = None) -> List[Dict[str, str]]:
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
                continue
        
        backups.sort(key=lambda x: x['timestamp'], reverse=True)
        return backups
    
    def update_backup_locations(self, backup_path: str, organization_plan: Dict[str, List[str]]) -> None:
        try:
            backup = self.load_backup(backup_path)
            
            file_to_new_location = {}
            for dest_folder, file_paths in organization_plan.items():
                for file_path in file_paths:
                    file_name = Path(file_path).name
                    try:
                        relative_new_path = Path(dest_folder) / file_name
                        file_to_new_location[file_name] = str(relative_new_path)
                    except Exception:
                        continue
            
            for entry in backup.entries:
                if entry.file_name in file_to_new_location:
                    entry.current_path = file_to_new_location[entry.file_name]
            
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


class TaskScheduler:
    
    def __init__(self, schedule_file: str = "reorg_schedules.json"):
        self.schedule_file = Path(schedule_file)
        self.tasks: Dict[str, ScheduleTask] = {}
        self.running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        self.load_schedules()
    
    def create_task(self, name: str, folder_path: str, strategy: SortBy, 
                   compression: CompressionFormat, schedule_type: ScheduleType,
                   scheduled_time: datetime, interval_days: Optional[int] = None,
                   max_runs: Optional[int] = None) -> str:
        task_id = f"task_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(self.tasks)}"
        
        task = ScheduleTask(
            id=task_id,
            name=name,
            folder_path=folder_path,
            strategy=strategy,
            compression=compression,
            schedule_type=schedule_type,
            next_run=scheduled_time,
            interval_days=interval_days,
            max_runs=max_runs
        )
        
        self.tasks[task_id] = task
        self.save_schedules()
        return task_id
    
    def get_task(self, task_id: str) -> Optional[ScheduleTask]:
        return self.tasks.get(task_id)
    
    def get_all_tasks(self) -> List[ScheduleTask]:
        return list(self.tasks.values())
    
    def get_pending_tasks(self) -> List[ScheduleTask]:
        return [task for task in self.tasks.values() 
                if task.status == ScheduleStatus.PENDING and task.enabled]
    
    def cancel_task(self, task_id: str) -> bool:
        if task_id in self.tasks:
            self.tasks[task_id].status = ScheduleStatus.CANCELLED
            self.save_schedules()
            return True
        return False
    
    def delete_task(self, task_id: str) -> bool:
        if task_id in self.tasks:
            del self.tasks[task_id]
            self.save_schedules()
            return True
        return False
    
    def enable_task(self, task_id: str, enabled: bool = True) -> bool:
        if task_id in self.tasks:
            self.tasks[task_id].enabled = enabled
            self.save_schedules()
            return True
        return False
    
    def start_scheduler(self):
        if not self.running:
            self.running = True
            self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            self.scheduler_thread.start()
    
    def stop_scheduler(self):
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
    
    def _scheduler_loop(self):
        while self.running:
            try:
                now = datetime.now()
                pending_tasks = self.get_pending_tasks()
                
                for task in pending_tasks:
                    if task.next_run <= now:
                        self._execute_task(task)
                
                time.sleep(30)
            except Exception as e:
                print(f"Scheduler error: {e}")
                time.sleep(60)
    
    def _execute_task(self, task: ScheduleTask):
        try:
            task.status = ScheduleStatus.RUNNING
            task.last_run = datetime.now()
            self.save_schedules()
            
            sorter = FileSorter()
            files = sorter.scan(task.folder_path)
            
            result = sorter.organize_files(
                strategy=task.strategy,
                dry_run=False,
                compression=task.compression
            )
            
            task.status = ScheduleStatus.COMPLETED
            task.run_count += 1
            task.last_result = f"Processed {len(files)} files"
            
            if task.schedule_type != ScheduleType.ONE_TIME:
                if task.max_runs is None or task.run_count < task.max_runs:
                    task.next_run = self._calculate_next_run(task)
                    task.status = ScheduleStatus.PENDING
                else:
                    task.status = ScheduleStatus.COMPLETED
                    task.enabled = False
            
        except Exception as e:
            task.status = ScheduleStatus.FAILED
            task.error_message = str(e)
        
        finally:
            self.save_schedules()
    
    def _calculate_next_run(self, task: ScheduleTask) -> datetime:
        if task.schedule_type == ScheduleType.DAILY:
            return task.next_run + timedelta(days=1)
        elif task.schedule_type == ScheduleType.WEEKLY:
            return task.next_run + timedelta(weeks=1)
        elif task.schedule_type == ScheduleType.MONTHLY:
            return task.next_run + timedelta(days=30)
        elif task.interval_days:
            return task.next_run + timedelta(days=task.interval_days)
        else:
            return task.next_run + timedelta(days=1)
    
    def save_schedules(self):
        try:
            tasks_data = {}
            for task_id, task in self.tasks.items():
                tasks_data[task_id] = {
                    'id': task.id,
                    'name': task.name,
                    'folder_path': task.folder_path,
                    'strategy': task.strategy.value,
                    'compression': task.compression.value,
                    'schedule_type': task.schedule_type.value,
                    'next_run': task.next_run.isoformat(),
                    'status': task.status.value,
                    'created': task.created.isoformat(),
                    'last_run': task.last_run.isoformat() if task.last_run else None,
                    'last_result': task.last_result,
                    'error_message': task.error_message,
                    'interval_days': task.interval_days,
                    'run_count': task.run_count,
                    'max_runs': task.max_runs,
                    'enabled': task.enabled
                }
            
            with open(self.schedule_file, 'w') as f:
                json.dump(tasks_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save schedules: {e}")
            print(f"Failed to save schedules: {e}")
    
    def load_schedules(self):
        try:
            if self.schedule_file.exists():
                with open(self.schedule_file, 'r') as f:
                    tasks_data = json.load(f)
                
                for task_id, data in tasks_data.items():
                    task = ScheduleTask(
                        id=data['id'],
                        name=data['name'],
                        folder_path=data['folder_path'],
                        strategy=SortBy(data['strategy']),
                        compression=CompressionFormat(data['compression']),
                        schedule_type=ScheduleType(data['schedule_type']),
                        next_run=datetime.fromisoformat(data['next_run']),
                        status=ScheduleStatus(data['status']),
                        created=datetime.fromisoformat(data['created']),
                        last_run=datetime.fromisoformat(data['last_run']) if data['last_run'] else None,
                        last_result=data['last_result'],
                        error_message=data['error_message'],
                        interval_days=data['interval_days'],
                        run_count=data['run_count'],
                        max_runs=data['max_runs'],
                        enabled=data['enabled']
                    )
                    self.tasks[task_id] = task
        except Exception as e:
            print(f"Failed to load schedules: {e}")
            self.tasks = {}


FileInfo = FileData
SortCriteria = SortBy
FileCategory = FileCat
