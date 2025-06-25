"""
File Upload API endpoints for SecuNik LogX
Handles file uploads with validation and storage
"""

import os
from typing import List, Optional
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, File, UploadFile, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from config import settings
from core.storage_manager import StorageManager
from core.file_identifier import FileIdentifier
from utils.file_utils import validate_file_size, validate_file_extension


router = APIRouter()


class UploadResponse(BaseModel):
    """Response model for file upload"""
    id: str
    original_filename: str
    stored_filename: str
    file_size: int
    file_hash: str
    upload_time: str
    status: str
    file_type: dict
    message: str = "File uploaded successfully"


class MultiUploadResponse(BaseModel):
    """Response model for multiple file uploads"""
    uploaded: List[UploadResponse]
    failed: List[dict]
    total: int
    successful: int


@router.post("/", response_model=UploadResponse)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """
    Upload a single file for analysis
    
    - Accepts any file type up to 500MB
    - Auto-detects file type
    - Returns file metadata and assigned parser
    """
    storage_manager: StorageManager = request.app.state.storage_manager
    file_identifier = FileIdentifier()
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    # Check file size
    file.file.seek(0, 2)  # Seek to end
    file_size = file.file.tell()
    file.file.seek(0)  # Reset to beginning
    
    if not validate_file_size(file_size):
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {settings.MAX_FILE_SIZE_MB}MB"
        )
    
    # Check file extension if restrictions are enabled
    if settings.ALLOWED_EXTENSIONS:
        if not validate_file_extension(file.filename):
            raise HTTPException(
                status_code=415,
                detail=f"File type not allowed. Allowed extensions: {', '.join(settings.ALLOWED_EXTENSIONS)}"
            )
    
    try:
        # Read file content
        content = await file.read()
        
        # Save file to storage
        metadata = await storage_manager.save_upload(file.filename, content)
        
        # Identify file type
        file_path = Path(metadata["file_path"])
        file_type_info = await file_identifier.identify_file(file_path)
        
        # Add file type info to metadata
        metadata["file_type"] = file_type_info
        
        # Create response
        response = UploadResponse(
            id=metadata["id"],
            original_filename=metadata["original_filename"],
            stored_filename=metadata["stored_filename"],
            file_size=metadata["file_size"],
            file_hash=metadata["file_hash"],
            upload_time=metadata["upload_time"],
            status=metadata["status"],
            file_type=file_type_info
        )
        
        # Optional: Start analysis automatically in background
        # background_tasks.add_task(start_analysis, metadata["id"])
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.post("/multiple", response_model=MultiUploadResponse)
async def upload_multiple_files(
    request: Request,
    files: List[UploadFile] = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """
    Upload multiple files for analysis
    
    - Accepts up to 10 files at once
    - Each file up to 500MB
    - Returns success/failure for each file
    """
    if len(files) > 10:
        raise HTTPException(
            status_code=400,
            detail="Maximum 10 files can be uploaded at once"
        )
    
    storage_manager: StorageManager = request.app.state.storage_manager
    file_identifier = FileIdentifier()
    
    uploaded = []
    failed = []
    
    for file in files:
        try:
            # Validate file
            if not file.filename:
                failed.append({
                    "filename": "unknown",
                    "error": "No filename provided"
                })
                continue
            
            # Check file size
            file.file.seek(0, 2)
            file_size = file.file.tell()
            file.file.seek(0)
            
            if not validate_file_size(file_size):
                failed.append({
                    "filename": file.filename,
                    "error": f"File too large. Maximum size is {settings.MAX_FILE_SIZE_MB}MB"
                })
                continue
            
            # Read and save file
            content = await file.read()
            metadata = await storage_manager.save_upload(file.filename, content)
            
            # Identify file type
            file_path = Path(metadata["file_path"])
            file_type_info = await file_identifier.identify_file(file_path)
            metadata["file_type"] = file_type_info
            
            # Create response
            upload_response = UploadResponse(
                id=metadata["id"],
                original_filename=metadata["original_filename"],
                stored_filename=metadata["stored_filename"],
                file_size=metadata["file_size"],
                file_hash=metadata["file_hash"],
                upload_time=metadata["upload_time"],
                status=metadata["status"],
                file_type=file_type_info
            )
            
            uploaded.append(upload_response)
            
        except Exception as e:
            failed.append({
                "filename": file.filename,
                "error": str(e)
            })
    
    return MultiUploadResponse(
        uploaded=uploaded,
        failed=failed,
        total=len(files),
        successful=len(uploaded)
    )


@router.get("/status/{file_id}")
async def get_upload_status(request: Request, file_id: str):
    """
    Get status of an uploaded file
    
    Returns file metadata including:
    - Upload status
    - File type detection results
    - Analysis status if started
    """
    storage_manager: StorageManager = request.app.state.storage_manager
    
    metadata = await storage_manager.get_file_metadata(file_id)
    if not metadata:
        raise HTTPException(status_code=404, detail="File not found")
    
    return metadata


@router.delete("/{file_id}")
async def delete_upload(request: Request, file_id: str):
    """
    Delete an uploaded file and all associated data
    
    This will remove:
    - Original uploaded file
    - Parsed data
    - Analysis results
    """
    storage_manager: StorageManager = request.app.state.storage_manager
    
    success = await storage_manager.delete_analysis(file_id)
    if not success:
        raise HTTPException(status_code=404, detail="File not found")
    
    return {"message": "File deleted successfully", "file_id": file_id}


@router.post("/validate")
async def validate_upload(
    filename: str = None,
    file_size: int = None
):
    """
    Pre-validate a file before upload
    
    Checks:
    - File size limits
    - File extension restrictions
    """
    errors = []
    warnings = []
    
    if file_size:
        if not validate_file_size(file_size):
            errors.append(f"File too large. Maximum size is {settings.MAX_FILE_SIZE_MB}MB")
        elif file_size > settings.MAX_FILE_SIZE_MB * 1024 * 1024 * 0.8:
            warnings.append("File is close to size limit")
    
    if filename and settings.ALLOWED_EXTENSIONS:
        if not validate_file_extension(filename):
            errors.append(f"File type not allowed. Allowed extensions: {', '.join(settings.ALLOWED_EXTENSIONS)}")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "limits": {
            "max_file_size_mb": settings.MAX_FILE_SIZE_MB,
            "allowed_extensions": settings.ALLOWED_EXTENSIONS or "all"
        }
    }


@router.get("/supported-types")
async def get_supported_types():
    """
    Get list of supported file types and their parsers
    
    Returns categorized list of all supported file types
    """
    file_identifier = FileIdentifier()
    
    # Group by category
    categories = {}
    
    # Process extension mappings
    for ext, (parser, category) in file_identifier.extension_map.items():
        cat_name = category.value
        if cat_name not in categories:
            categories[cat_name] = {
                "name": cat_name,
                "description": f"{cat_name.title()} files",
                "file_types": []
            }
        
        categories[cat_name]["file_types"].append({
            "extension": ext,
            "parser": parser,
            "mime_types": []
        })
    
    # Add MIME type info
    for mime, (parser, category) in file_identifier.mime_map.items():
        cat_name = category.value
        if cat_name in categories:
            for file_type in categories[cat_name]["file_types"]:
                if file_type["parser"] == parser and mime not in file_type["mime_types"]:
                    file_type["mime_types"].append(mime)
    
    return {
        "total_parsers": len(file_identifier._get_supported_parsers()),
        "categories": list(categories.values())
    }