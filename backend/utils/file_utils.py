"""
File utility functions for SecuNik LogX
Common file operations and validations
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Union, List, Tuple
import aiofiles
import aiofiles.os

from config import settings


def ensure_directory(path: Union[str, Path]) -> Path:
    """Ensure a directory exists, create if it doesn't"""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_directories():
    """Ensure all required directories exist"""
    directories = [
        settings.STORAGE_PATH,
        settings.UPLOAD_PATH,
        settings.PARSED_PATH,
        settings.ANALYSIS_PATH,
        settings.TEMP_PATH,
        settings.YARA_RULES_PATH,
        settings.SIGMA_RULES_PATH,
        settings.MITRE_RULES_PATH,
        settings.CUSTOM_RULES_PATH
    ]
    
    for directory in directories:
        ensure_directory(directory)
    
    # Ensure log directory if configured
    if settings.LOG_FILE:
        ensure_directory(settings.LOG_FILE.parent)


def get_file_size(file_path: Union[str, Path]) -> int:
    """Get file size in bytes"""
    path = Path(file_path)
    if path.exists() and path.is_file():
        return path.stat().st_size
    return 0


def get_file_size_mb(file_path: Union[str, Path]) -> float:
    """Get file size in megabytes"""
    size_bytes = get_file_size(file_path)
    return round(size_bytes / (1024 * 1024), 2)


def validate_file_size(size_bytes: int) -> bool:
    """Validate if file size is within limits"""
    return size_bytes <= settings.MAX_FILE_SIZE_BYTES


def validate_file_extension(filename: str) -> bool:
    """Validate if file extension is allowed"""
    if not settings.ALLOWED_EXTENSIONS:
        return True  # All extensions allowed
    
    if "*" in settings.ALLOWED_EXTENSIONS:
        return True
    
    ext = Path(filename).suffix.lower()
    return ext in settings.ALLOWED_EXTENSIONS


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage"""
    # Remove any path components
    filename = os.path.basename(filename)
    
    # Replace problematic characters
    invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0']
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    
    # Ensure filename is not empty
    if not filename:
        filename = "unnamed_file"
    
    # Limit length while preserving extension
    name, ext = os.path.splitext(filename)
    if len(name) > 200:
        name = name[:200]
    
    return f"{name}{ext}"


def get_temp_filepath(prefix: str = "temp", suffix: str = "") -> Path:
    """Get a temporary file path"""
    temp_dir = ensure_directory(settings.TEMP_PATH)
    
    # Create unique filename
    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        dir=temp_dir,
        prefix=f"{prefix}_",
        suffix=suffix
    )
    temp_file.close()
    
    return Path(temp_file.name)


async def safe_delete_file(file_path: Union[str, Path]) -> bool:
    """Safely delete a file"""
    path = Path(file_path)
    
    try:
        if path.exists() and path.is_file():
            await aiofiles.os.remove(str(path))
            return True
    except Exception as e:
        print(f"Error deleting file {path}: {e}")
    
    return False


async def safe_delete_directory(dir_path: Union[str, Path]) -> bool:
    """Safely delete a directory and its contents"""
    path = Path(dir_path)
    
    try:
        if path.exists() and path.is_dir():
            shutil.rmtree(str(path))
            return True
    except Exception as e:
        print(f"Error deleting directory {path}: {e}")
    
    return False


async def copy_file(src: Union[str, Path], dst: Union[str, Path]) -> bool:
    """Copy a file asynchronously"""
    src_path = Path(src)
    dst_path = Path(dst)
    
    try:
        # Ensure destination directory exists
        ensure_directory(dst_path.parent)
        
        # Copy file
        async with aiofiles.open(src_path, 'rb') as src_file:
            async with aiofiles.open(dst_path, 'wb') as dst_file:
                while chunk := await src_file.read(settings.CHUNK_SIZE):
                    await dst_file.write(chunk)
        
        return True
    except Exception as e:
        print(f"Error copying file from {src} to {dst}: {e}")
        return False


async def move_file(src: Union[str, Path], dst: Union[str, Path]) -> bool:
    """Move a file"""
    src_path = Path(src)
    dst_path = Path(dst)
    
    try:
        # Ensure destination directory exists
        ensure_directory(dst_path.parent)
        
        # Try to rename (fastest if on same filesystem)
        src_path.rename(dst_path)
        return True
    except OSError:
        # Fall back to copy and delete
        if await copy_file(src_path, dst_path):
            return await safe_delete_file(src_path)
    except Exception as e:
        print(f"Error moving file from {src} to {dst}: {e}")
    
    return False


def list_files(directory: Union[str, Path], 
               pattern: str = "*",
               recursive: bool = False) -> List[Path]:
    """List files in a directory"""
    path = Path(directory)
    
    if not path.exists() or not path.is_dir():
        return []
    
    if recursive:
        return list(path.rglob(pattern))
    else:
        return list(path.glob(pattern))


def get_file_extension(file_path: Union[str, Path]) -> str:
    """Get file extension (lowercase)"""
    return Path(file_path).suffix.lower()


def get_file_mime_type(file_path: Union[str, Path]) -> Optional[str]:
    """Get MIME type of a file"""
    try:
        import magic
        mime = magic.Magic(mime=True)
        return mime.from_file(str(file_path))
    except Exception:
        # Fallback to extension-based detection
        ext = get_file_extension(file_path)
        mime_map = {
            '.txt': 'text/plain',
            '.log': 'text/plain',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.csv': 'text/csv',
            '.pdf': 'application/pdf',
            '.zip': 'application/zip',
            '.pcap': 'application/vnd.tcpdump.pcap',
        }
        return mime_map.get(ext, 'application/octet-stream')


async def read_file_chunk(file_path: Union[str, Path], 
                         offset: int = 0,
                         size: int = None) -> bytes:
    """Read a chunk of a file"""
    path = Path(file_path)
    
    if not path.exists() or not path.is_file():
        return b''
    
    if size is None:
        size = settings.CHUNK_SIZE
    
    try:
        async with aiofiles.open(path, 'rb') as f:
            await f.seek(offset)
            return await f.read(size)
    except Exception as e:
        print(f"Error reading file chunk from {path}: {e}")
        return b''


async def get_file_head(file_path: Union[str, Path], 
                       lines: int = 100) -> List[str]:
    """Get first N lines of a text file"""
    path = Path(file_path)
    result = []
    
    try:
        async with aiofiles.open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for i in range(lines):
                line = await f.readline()
                if not line:
                    break
                result.append(line.rstrip('\n\r'))
    except Exception as e:
        print(f"Error reading file head from {path}: {e}")
    
    return result


def split_file_path(file_path: Union[str, Path]) -> Tuple[Path, str, str]:
    """Split file path into directory, name, and extension"""
    path = Path(file_path)
    directory = path.parent
    name = path.stem
    extension = path.suffix
    
    return directory, name, extension


def create_archive_from_files(files: List[Union[str, Path]], 
                            output_path: Union[str, Path],
                            archive_type: str = "zip") -> bool:
    """Create an archive from multiple files"""
    output = Path(output_path)
    
    try:
        if archive_type == "zip":
            import zipfile
            with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file in files:
                    file_path = Path(file)
                    if file_path.exists():
                        zf.write(file_path, file_path.name)
        elif archive_type == "tar":
            import tarfile
            with tarfile.open(output, 'w:gz') as tf:
                for file in files:
                    file_path = Path(file)
                    if file_path.exists():
                        tf.add(file_path, arcname=file_path.name)
        else:
            return False
        
        return True
    except Exception as e:
        print(f"Error creating archive: {e}")
        return False


def estimate_processing_time(file_size: int, file_type: str = "generic") -> int:
    """Estimate processing time in seconds based on file size and type"""
    # Base estimation: 1MB per second
    base_time = file_size / (1024 * 1024)
    
    # Multipliers for different file types
    multipliers = {
        "pcap": 2.0,      # Network captures are slower
        "archive": 1.5,   # Need to extract
        "database": 1.8,  # Complex queries
        "forensic": 3.0,  # Very intensive
        "generic": 1.0
    }
    
    multiplier = multipliers.get(file_type, 1.0)
    estimated_time = base_time * multiplier
    
    # Add overhead
    return max(int(estimated_time + 5), 10)  # Minimum 10 seconds


def is_text_file(file_path: Union[str, Path]) -> bool:
    """Check if a file is likely a text file"""
    path = Path(file_path)
    
    # Check extension first
    text_extensions = {
        '.txt', '.log', '.csv', '.json', '.xml', '.yml', '.yaml',
        '.ini', '.conf', '.cfg', '.py', '.js', '.sh', '.bat', '.ps1'
    }
    
    if path.suffix.lower() in text_extensions:
        return True
    
    # Check MIME type
    mime_type = get_file_mime_type(path)
    if mime_type and mime_type.startswith('text/'):
        return True
    
    # Sample file content
    try:
        with open(path, 'rb') as f:
            sample = f.read(512)
            # Check for null bytes
            if b'\x00' in sample:
                return False
            # Try to decode as UTF-8
            try:
                sample.decode('utf-8')
                return True
            except UnicodeDecodeError:
                return False
    except Exception:
        return False


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"