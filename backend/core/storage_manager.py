"""
Storage Manager for SecuNik LogX
Handles all file-based storage operations with JSON
"""

import asyncio
import json
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import aiofiles
import aiofiles.os

from config import settings
from utils.file_utils import get_file_size, ensure_directory
from utils.hash_utils import calculate_file_hash


class StorageManager:
    """Manages file-based storage for uploads, parsed data, and analysis results"""
    
    def __init__(self):
        self.upload_path = settings.UPLOAD_PATH
        self.parsed_path = settings.PARSED_PATH
        self.analysis_path = settings.ANALYSIS_PATH
        self.temp_path = settings.TEMP_PATH
        self.history_file = settings.HISTORY_FILE
        self._history_lock = asyncio.Lock()
        self._file_locks = {}
    
    async def initialize(self):
        """Initialize storage manager and ensure directories exist"""
        for path in [self.upload_path, self.parsed_path, 
                    self.analysis_path, self.temp_path]:
            ensure_directory(path)
        
        # Initialize history file if it doesn't exist
        if not self.history_file.exists():
            await self._write_json(self.history_file, {"analyses": []})
    
    async def cleanup(self):
        """Cleanup temporary files and old data"""
        # Clean temp directory
        if self.temp_path.exists():
            for file in self.temp_path.iterdir():
                try:
                    if file.is_file():
                        file.unlink()
                    elif file.is_dir():
                        shutil.rmtree(file)
                except Exception as e:
                    print(f"Error cleaning temp file {file}: {e}")
    
    async def save_upload(self, filename: str, content: bytes) -> Dict[str, Any]:
        """Save uploaded file and return metadata"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_filename = self._sanitize_filename(filename)
        stored_filename = f"{timestamp}_{safe_filename}"
        file_path = self.upload_path / stored_filename
        
        # Save file
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(content)
        
        # Calculate hash
        file_hash = await calculate_file_hash(file_path)
        file_size = get_file_size(file_path)
        
        metadata = {
            "id": f"{timestamp}_{file_hash[:8]}",
            "original_filename": filename,
            "stored_filename": stored_filename,
            "file_path": str(file_path),
            "file_size": file_size,
            "file_hash": file_hash,
            "upload_time": datetime.utcnow().isoformat(),
            "status": "uploaded"
        }
        
        # Add to history
        await self._add_to_history(metadata)
        
        return metadata
    
    async def save_parsed_data(self, file_id: str, parsed_data: Dict[str, Any]) -> str:
        """Save parsed data as JSON"""
        filename = f"{file_id}_parsed.json"
        file_path = self.parsed_path / filename
        
        await self._write_json(file_path, parsed_data)
        
        # Update history
        await self._update_history(file_id, {
            "parsed_file": str(file_path),
            "parse_time": datetime.utcnow().isoformat(),
            "status": "parsed"
        })
        
        return str(file_path)
    
    async def save_analysis_results(self, file_id: str, 
                                  analysis_results: Dict[str, Any]) -> str:
        """Save analysis results as JSON"""
        filename = f"{file_id}_analysis.json"
        file_path = self.analysis_path / filename
        
        # Add metadata
        analysis_results["analysis_id"] = file_id
        analysis_results["completion_time"] = datetime.utcnow().isoformat()
        
        await self._write_json(file_path, analysis_results)
        
        # Update history
        await self._update_history(file_id, {
            "analysis_file": str(file_path),
            "analysis_time": datetime.utcnow().isoformat(),
            "status": "analyzed",
            "summary": analysis_results.get("summary", {})
        })
        
        return str(file_path)
    
    async def get_file_metadata(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a specific file"""
        history = await self._read_history()
        for entry in history.get("analyses", []):
            if entry.get("id") == file_id:
                return entry
        return None
    
    async def get_parsed_data(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get parsed data for a file"""
        metadata = await self.get_file_metadata(file_id)
        if metadata and "parsed_file" in metadata:
            parsed_file = Path(metadata["parsed_file"])
            if parsed_file.exists():
                return await self._read_json(parsed_file)
        return None
    
    async def get_analysis_results(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get analysis results for a file"""
        metadata = await self.get_file_metadata(file_id)
        if metadata and "analysis_file" in metadata:
            analysis_file = Path(metadata["analysis_file"])
            if analysis_file.exists():
                return await self._read_json(analysis_file)
        return None
    
    async def get_history(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Get analysis history with pagination"""
        history = await self._read_history()
        analyses = history.get("analyses", [])
        
        # Sort by upload time (newest first)
        analyses.sort(key=lambda x: x.get("upload_time", ""), reverse=True)
        
        # Apply pagination
        return analyses[offset:offset + limit]
    
    async def delete_analysis(self, file_id: str) -> bool:
        """Delete all files related to an analysis"""
        metadata = await self.get_file_metadata(file_id)
        if not metadata:
            return False
        
        # Delete files
        files_to_delete = [
            metadata.get("file_path"),
            metadata.get("parsed_file"),
            metadata.get("analysis_file")
        ]
        
        for file_path in files_to_delete:
            if file_path:
                path = Path(file_path)
                if path.exists():
                    try:
                        path.unlink()
                    except Exception as e:
                        print(f"Error deleting {file_path}: {e}")
        
        # Remove from history
        await self._remove_from_history(file_id)
        
        return True
    
    async def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        stats = {
            "uploads": await self._get_directory_stats(self.upload_path),
            "parsed": await self._get_directory_stats(self.parsed_path),
            "analysis": await self._get_directory_stats(self.analysis_path),
            "temp": await self._get_directory_stats(self.temp_path),
            "total_analyses": len((await self._read_history()).get("analyses", []))
        }
        
        # Calculate total size
        stats["total_size"] = sum(
            s["total_size"] for s in [
                stats["uploads"], stats["parsed"], 
                stats["analysis"], stats["temp"]
            ]
        )
        
        return stats
    
    async def cleanup_old_files(self, days: int = 30):
        """Clean up files older than specified days"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        history = await self._read_history()
        analyses = history.get("analyses", [])
        
        for analysis in analyses[:]:  # Create a copy to modify during iteration
            upload_time = datetime.fromisoformat(analysis.get("upload_time", ""))
            if upload_time < cutoff_date:
                await self.delete_analysis(analysis["id"])
    
    # Private helper methods
    
    async def _read_json(self, file_path: Path) -> Dict[str, Any]:
        """Read JSON file safely"""
        try:
            async with aiofiles.open(file_path, 'r') as f:
                content = await f.read()
                return json.loads(content)
        except Exception as e:
            print(f"Error reading JSON {file_path}: {e}")
            return {}
    
    async def _write_json(self, file_path: Path, data: Dict[str, Any]):
        """Write JSON file safely"""
        try:
            async with aiofiles.open(file_path, 'w') as f:
                await f.write(json.dumps(data, indent=2))
        except Exception as e:
            print(f"Error writing JSON {file_path}: {e}")
            raise
    
    async def _read_history(self) -> Dict[str, Any]:
        """Read history file with lock"""
        async with self._history_lock:
            return await self._read_json(self.history_file)
    
    async def _write_history(self, history: Dict[str, Any]):
        """Write history file with lock"""
        async with self._history_lock:
            await self._write_json(self.history_file, history)
    
    async def _add_to_history(self, metadata: Dict[str, Any]):
        """Add entry to history"""
        history = await self._read_history()
        analyses = history.get("analyses", [])
        analyses.append(metadata)
        history["analyses"] = analyses
        await self._write_history(history)
    
    async def _update_history(self, file_id: str, updates: Dict[str, Any]):
        """Update existing history entry"""
        history = await self._read_history()
        analyses = history.get("analyses", [])
        
        for i, entry in enumerate(analyses):
            if entry.get("id") == file_id:
                analyses[i].update(updates)
                break
        
        history["analyses"] = analyses
        await self._write_history(history)
    
    async def _remove_from_history(self, file_id: str):
        """Remove entry from history"""
        history = await self._read_history()
        analyses = history.get("analyses", [])
        
        history["analyses"] = [
            entry for entry in analyses 
            if entry.get("id") != file_id
        ]
        
        await self._write_history(history)
    
    async def _get_directory_stats(self, directory: Path) -> Dict[str, Any]:
        """Get statistics for a directory"""
        if not directory.exists():
            return {"file_count": 0, "total_size": 0}
        
        file_count = 0
        total_size = 0
        
        for file in directory.iterdir():
            if file.is_file():
                file_count += 1
                total_size += file.stat().st_size
        
        return {
            "file_count": file_count,
            "total_size": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2)
        }
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe storage"""
        # Remove path components
        filename = os.path.basename(filename)
        
        # Replace problematic characters
        for char in ['/', '\\', ':', '*', '?', '"', '<', '>', '|']:
            filename = filename.replace(char, '_')
        
        # Limit length
        name, ext = os.path.splitext(filename)
        if len(name) > 100:
            name = name[:100]
        
        return f"{name}{ext}"