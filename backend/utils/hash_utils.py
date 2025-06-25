"""
Hash utility functions for SecuNik LogX
File hashing and integrity verification
"""

import hashlib
from pathlib import Path
from typing import Union, Dict, Optional, List
import aiofiles

from config import settings


async def calculate_file_hash(file_path: Union[str, Path], 
                            algorithm: str = "sha256") -> str:
    """
    Calculate hash of a file
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
    
    Returns:
        Hex digest of the file hash
    """
    path = Path(file_path)
    
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Select hash algorithm
    hash_algos = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512
    }
    
    if algorithm not in hash_algos:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    hasher = hash_algos[algorithm]()
    
    # Read and hash file in chunks
    async with aiofiles.open(path, 'rb') as f:
        while chunk := await f.read(settings.CHUNK_SIZE):
            hasher.update(chunk)
    
    return hasher.hexdigest()


async def calculate_multiple_hashes(file_path: Union[str, Path], 
                                  algorithms: List[str] = None) -> Dict[str, str]:
    """
    Calculate multiple hashes for a file
    
    Args:
        file_path: Path to the file
        algorithms: List of algorithms to use (default: md5, sha1, sha256)
    
    Returns:
        Dictionary of algorithm -> hash digest
    """
    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256"]
    
    path = Path(file_path)
    
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Initialize hashers
    hashers = {}
    for algo in algorithms:
        if algo == "md5":
            hashers[algo] = hashlib.md5()
        elif algo == "sha1":
            hashers[algo] = hashlib.sha1()
        elif algo == "sha256":
            hashers[algo] = hashlib.sha256()
        elif algo == "sha512":
            hashers[algo] = hashlib.sha512()
        else:
            raise ValueError(f"Unsupported algorithm: {algo}")
    
    # Read and hash file in chunks
    async with aiofiles.open(path, 'rb') as f:
        while chunk := await f.read(settings.CHUNK_SIZE):
            for hasher in hashers.values():
                hasher.update(chunk)
    
    # Return results
    return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}


def calculate_string_hash(data: str, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a string
    
    Args:
        data: String to hash
        algorithm: Hash algorithm
    
    Returns:
        Hex digest of the hash
    """
    if algorithm == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data.encode()).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(data.encode()).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(data.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def calculate_bytes_hash(data: bytes, algorithm: str = "sha256") -> str:
    """
    Calculate hash of bytes
    
    Args:
        data: Bytes to hash
        algorithm: Hash algorithm
    
    Returns:
        Hex digest of the hash
    """
    if algorithm == "md5":
        return hashlib.md5(data).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(data).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


async def verify_file_integrity(file_path: Union[str, Path], 
                              expected_hash: str,
                              algorithm: str = "sha256") -> bool:
    """
    Verify file integrity by comparing hashes
    
    Args:
        file_path: Path to the file
        expected_hash: Expected hash value
        algorithm: Hash algorithm used
    
    Returns:
        True if hashes match, False otherwise
    """
    try:
        actual_hash = await calculate_file_hash(file_path, algorithm)
        return actual_hash.lower() == expected_hash.lower()
    except Exception:
        return False


def generate_file_id(filename: str, timestamp: str) -> str:
    """
    Generate a unique file ID based on filename and timestamp
    
    Args:
        filename: Original filename
        timestamp: Upload timestamp
    
    Returns:
        Unique file ID
    """
    data = f"{filename}_{timestamp}"
    hash_value = calculate_string_hash(data, "sha256")
    return hash_value[:16]  # Use first 16 characters


def fuzzy_hash(file_path: Union[str, Path]) -> Optional[str]:
    """
    Calculate fuzzy hash (ssdeep) for similarity matching
    
    Note: Requires ssdeep library (optional dependency)
    """
    try:
        import ssdeep
        path = Path(file_path)
        
        if not path.exists() or not path.is_file():
            return None
        
        with open(path, 'rb') as f:
            return ssdeep.hash(f.read())
    except ImportError:
        # ssdeep not installed
        return None
    except Exception:
        return None


def compare_fuzzy_hashes(hash1: str, hash2: str) -> int:
    """
    Compare two fuzzy hashes for similarity
    
    Returns:
        Similarity score (0-100), or -1 if comparison fails
    """
    try:
        import ssdeep
        return ssdeep.compare(hash1, hash2)
    except Exception:
        return -1


async def calculate_content_hash(file_path: Union[str, Path], 
                               normalize: bool = True) -> str:
    """
    Calculate content-based hash (ignores metadata)
    
    Args:
        file_path: Path to the file
        normalize: Whether to normalize content (for text files)
    
    Returns:
        Content hash
    """
    path = Path(file_path)
    hasher = hashlib.sha256()
    
    try:
        # For text files, normalize line endings and encoding
        if normalize and _is_text_file(path):
            async with aiofiles.open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = await f.read()
                # Normalize line endings
                content = content.replace('\r\n', '\n').replace('\r', '\n')
                # Remove trailing whitespace
                content = '\n'.join(line.rstrip() for line in content.split('\n'))
                hasher.update(content.encode('utf-8'))
        else:
            # Binary files - hash as-is
            async with aiofiles.open(path, 'rb') as f:
                while chunk := await f.read(settings.CHUNK_SIZE):
                    hasher.update(chunk)
    except Exception:
        # Fallback to binary mode
        async with aiofiles.open(path, 'rb') as f:
            while chunk := await f.read(settings.CHUNK_SIZE):
                hasher.update(chunk)
    
    return hasher.hexdigest()


def _is_text_file(path: Path) -> bool:
    """Check if file is likely a text file"""
    text_extensions = {
        '.txt', '.log', '.csv', '.json', '.xml', '.yml', '.yaml',
        '.ini', '.conf', '.cfg', '.py', '.js', '.sh', '.bat', '.ps1'
    }
    return path.suffix.lower() in text_extensions


def calculate_checksum(data: bytes, algorithm: str = "crc32") -> str:
    """
    Calculate checksum for data
    
    Args:
        data: Data to checksum
        algorithm: Checksum algorithm (crc32, adler32)
    
    Returns:
        Checksum as hex string
    """
    import zlib
    
    if algorithm == "crc32":
        return format(zlib.crc32(data) & 0xffffffff, '08x')
    elif algorithm == "adler32":
        return format(zlib.adler32(data) & 0xffffffff, '08x')
    else:
        raise ValueError(f"Unsupported checksum algorithm: {algorithm}")


class HashCache:
    """Simple in-memory hash cache to avoid recalculation"""
    
    def __init__(self, max_size: int = 1000):
        self._cache: Dict[str, Dict[str, str]] = {}
        self._max_size = max_size
    
    def get(self, file_path: Union[str, Path], algorithm: str = "sha256") -> Optional[str]:
        """Get cached hash if available"""
        key = str(Path(file_path).resolve())
        if key in self._cache and algorithm in self._cache[key]:
            return self._cache[key][algorithm]
        return None
    
    def set(self, file_path: Union[str, Path], algorithm: str, hash_value: str):
        """Cache a hash value"""
        key = str(Path(file_path).resolve())
        
        # Implement simple LRU by removing oldest entries
        if len(self._cache) >= self._max_size:
            # Remove first (oldest) entry
            first_key = next(iter(self._cache))
            del self._cache[first_key]
        
        if key not in self._cache:
            self._cache[key] = {}
        
        self._cache[key][algorithm] = hash_value
    
    def clear(self):
        """Clear the cache"""
        self._cache.clear()


# Global hash cache instance
hash_cache = HashCache()


async def get_file_hash_cached(file_path: Union[str, Path], 
                             algorithm: str = "sha256") -> str:
    """
    Get file hash with caching
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm
    
    Returns:
        Hash digest
    """
    # Check cache first
    cached = hash_cache.get(file_path, algorithm)
    if cached:
        return cached
    
    # Calculate hash
    hash_value = await calculate_file_hash(file_path, algorithm)
    
    # Cache result
    hash_cache.set(file_path, algorithm, hash_value)
    
    return hash_value


def format_hash_for_display(hash_value: str, group_size: int = 8) -> str:
    """
    Format hash for display with grouping
    
    Args:
        hash_value: Hash digest
        group_size: Characters per group
    
    Returns:
        Formatted hash string
    """
    if not hash_value:
        return ""
    
    # Group characters
    groups = [hash_value[i:i+group_size] for i in range(0, len(hash_value), group_size)]
    return " ".join(groups)


def is_valid_hash(hash_value: str, algorithm: str = "sha256") -> bool:
    """
    Validate if a string is a valid hash
    
    Args:
        hash_value: Hash string to validate
        algorithm: Expected algorithm
    
    Returns:
        True if valid hash format
    """
    expected_lengths = {
        "md5": 32,
        "sha1": 40,
        "sha256": 64,
        "sha512": 128
    }
    
    if algorithm not in expected_lengths:
        return False
    
    # Check length
    if len(hash_value) != expected_lengths[algorithm]:
        return False
    
    # Check if all characters are hex
    try:
        int(hash_value, 16)
        return True
    except ValueError:
        return False