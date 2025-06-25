"""
Analysis API endpoints for SecuNik LogX
Handles analysis execution and result retrieval
"""

import asyncio
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum

from fastapi import APIRouter, HTTPException, Request, BackgroundTasks, Query, Path
from pydantic import BaseModel, Field

from config import settings
from core.storage_manager import StorageManager


router = APIRouter()


class AnalysisStatus(str, Enum):
    """Analysis status enumeration"""
    PENDING = "pending"
    PARSING = "parsing"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AnalysisRequest(BaseModel):
    """Request model for starting analysis"""
    file_id: str
    enable_yara: bool = True
    enable_sigma: bool = True
    enable_mitre: bool = True
    enable_ai: bool = True
    custom_rules: Optional[List[str]] = None
    priority: str = "normal"  # low, normal, high


class AnalysisResponse(BaseModel):
    """Response model for analysis status"""
    analysis_id: str
    file_id: str
    status: AnalysisStatus
    progress: int = Field(0, ge=0, le=100)
    start_time: str
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None
    stages: Dict[str, Dict[str, Any]]
    summary: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class AnalysisResult(BaseModel):
    """Detailed analysis results"""
    analysis_id: str
    file_id: str
    file_info: Dict[str, Any]
    parsing_results: Dict[str, Any]
    analysis_results: Dict[str, Any]
    summary: Dict[str, Any]
    metadata: Dict[str, Any]


# In-memory analysis queue (will be replaced with proper queue in production)
analysis_queue = asyncio.Queue(maxsize=settings.MAX_CONCURRENT_ANALYSES)
active_analyses = {}


@router.post("/start", response_model=AnalysisResponse)
async def start_analysis(
    request: Request,
    analysis_request: AnalysisRequest,
    background_tasks: BackgroundTasks
):
    """
    Start analysis of an uploaded file
    
    - Queues file for parsing and analysis
    - Returns analysis ID for tracking progress
    - Analysis runs in background
    """
    storage_manager: StorageManager = request.app.state.storage_manager
    
    # Verify file exists
    file_metadata = await storage_manager.get_file_metadata(analysis_request.file_id)
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Check if analysis already in progress
    if analysis_request.file_id in active_analyses:
        existing = active_analyses[analysis_request.file_id]
        if existing["status"] in [AnalysisStatus.PENDING, AnalysisStatus.PARSING, AnalysisStatus.ANALYZING]:
            return AnalysisResponse(**existing)
    
    # Create analysis record
    analysis_id = f"analysis_{analysis_request.file_id}"
    analysis_record = {
        "analysis_id": analysis_id,
        "file_id": analysis_request.file_id,
        "status": AnalysisStatus.PENDING,
        "progress": 0,
        "start_time": datetime.utcnow().isoformat(),
        "end_time": None,
        "duration_seconds": None,
        "stages": {
            "parsing": {"status": "pending", "progress": 0},
            "yara": {"status": "pending", "progress": 0, "enabled": analysis_request.enable_yara},
            "sigma": {"status": "pending", "progress": 0, "enabled": analysis_request.enable_sigma},
            "mitre": {"status": "pending", "progress": 0, "enabled": analysis_request.enable_mitre},
            "ai": {"status": "pending", "progress": 0, "enabled": analysis_request.enable_ai}
        },
        "summary": None,
        "error": None,
        "request": analysis_request.dict()
    }
    
    # Store in active analyses
    active_analyses[analysis_request.file_id] = analysis_record
    
    # Queue for processing
    background_tasks.add_task(
        process_analysis,
        analysis_id,
        analysis_request,
        storage_manager
    )
    
    return AnalysisResponse(**analysis_record)


@router.get("/status/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis_status(request: Request, analysis_id: str):
    """
    Get current status of an analysis
    
    Returns:
    - Current status and progress
    - Stage-by-stage progress
    - Error details if failed
    """
    # Extract file_id from analysis_id
    file_id = analysis_id.replace("analysis_", "")
    
    if file_id not in active_analyses:
        # Check if completed analysis exists in storage
        storage_manager: StorageManager = request.app.state.storage_manager
        analysis_results = await storage_manager.get_analysis_results(file_id)
        
        if analysis_results:
            # Reconstruct response from stored results
            return AnalysisResponse(
                analysis_id=analysis_id,
                file_id=file_id,
                status=AnalysisStatus.COMPLETED,
                progress=100,
                start_time=analysis_results.get("start_time", ""),
                end_time=analysis_results.get("completion_time", ""),
                duration_seconds=analysis_results.get("duration_seconds"),
                stages=analysis_results.get("stages", {}),
                summary=analysis_results.get("summary", {})
            )
        
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return AnalysisResponse(**active_analyses[file_id])


@router.get("/results/{file_id}", response_model=AnalysisResult)
async def get_analysis_results(request: Request, file_id: str):
    """
    Get complete analysis results for a file
    
    Returns detailed results including:
    - Parsed data summary
    - Detection results from all engines
    - IOCs and patterns found
    - AI insights
    """
    storage_manager: StorageManager = request.app.state.storage_manager
    
    # Get all data
    file_metadata = await storage_manager.get_file_metadata(file_id)
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")
    
    parsed_data = await storage_manager.get_parsed_data(file_id)
    analysis_results = await storage_manager.get_analysis_results(file_id)
    
    if not analysis_results:
        raise HTTPException(status_code=404, detail="Analysis results not found")
    
    return AnalysisResult(
        analysis_id=f"analysis_{file_id}",
        file_id=file_id,
        file_info=file_metadata,
        parsing_results=parsed_data or {},
        analysis_results=analysis_results.get("results", {}),
        summary=analysis_results.get("summary", {}),
        metadata={
            "start_time": analysis_results.get("start_time"),
            "end_time": analysis_results.get("completion_time"),
            "duration_seconds": analysis_results.get("duration_seconds"),
            "engines_used": list(analysis_results.get("results", {}).keys())
        }
    )


@router.post("/cancel/{analysis_id}")
async def cancel_analysis(request: Request, analysis_id: str):
    """
    Cancel a running analysis
    
    - Stops analysis if in progress
    - Saves partial results
    """
    file_id = analysis_id.replace("analysis_", "")
    
    if file_id not in active_analyses:
        raise HTTPException(status_code=404, detail="Analysis not found or already completed")
    
    analysis = active_analyses[file_id]
    if analysis["status"] in [AnalysisStatus.COMPLETED, AnalysisStatus.FAILED]:
        raise HTTPException(status_code=400, detail="Analysis already completed")
    
    # Update status
    analysis["status"] = AnalysisStatus.CANCELLED
    analysis["end_time"] = datetime.utcnow().isoformat()
    
    # Calculate duration
    start_time = datetime.fromisoformat(analysis["start_time"])
    end_time = datetime.fromisoformat(analysis["end_time"])
    analysis["duration_seconds"] = (end_time - start_time).total_seconds()
    
    return {"message": "Analysis cancelled", "analysis_id": analysis_id}


@router.get("/queue")
async def get_analysis_queue():
    """
    Get current analysis queue status
    
    Returns:
    - Queue size
    - Active analyses
    - System capacity
    """
    active_count = sum(
        1 for a in active_analyses.values()
        if a["status"] in [AnalysisStatus.PARSING, AnalysisStatus.ANALYZING]
    )
    
    pending_count = sum(
        1 for a in active_analyses.values()
        if a["status"] == AnalysisStatus.PENDING
    )
    
    return {
        "queue_size": analysis_queue.qsize(),
        "active_analyses": active_count,
        "pending_analyses": pending_count,
        "max_concurrent": settings.MAX_CONCURRENT_ANALYSES,
        "capacity_used": f"{(active_count / settings.MAX_CONCURRENT_ANALYSES) * 100:.0f}%"
    }


@router.post("/reanalyze/{file_id}")
async def reanalyze_file(
    request: Request,
    file_id: str,
    analysis_request: Optional[AnalysisRequest] = None,
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """
    Re-run analysis on a previously uploaded file
    
    - Uses existing parsed data if available
    - Can override analysis settings
    """
    storage_manager: StorageManager = request.app.state.storage_manager
    
    # Verify file exists
    file_metadata = await storage_manager.get_file_metadata(file_id)
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Use provided request or create default
    if not analysis_request:
        analysis_request = AnalysisRequest(file_id=file_id)
    else:
        analysis_request.file_id = file_id
    
    # Remove from active analyses if exists
    if file_id in active_analyses:
        del active_analyses[file_id]
    
    # Start new analysis
    return await start_analysis(request, analysis_request, background_tasks)


# Background task for processing analysis
async def process_analysis(
    analysis_id: str,
    analysis_request: AnalysisRequest,
    storage_manager: StorageManager
):
    """
    Process analysis in background
    
    This is a placeholder that will be replaced with actual analysis logic
    when parsers and analyzers are implemented
    """
    file_id = analysis_request.file_id
    analysis = active_analyses[file_id]
    
    try:
        # Update status to parsing
        analysis["status"] = AnalysisStatus.PARSING
        analysis["stages"]["parsing"]["status"] = "running"
        
        # Simulate parsing (will be replaced with actual parser)
        await asyncio.sleep(2)  # Simulate work
        
        analysis["stages"]["parsing"]["status"] = "completed"
        analysis["stages"]["parsing"]["progress"] = 100
        analysis["progress"] = 25
        
        # Save parsed data (placeholder)
        parsed_data = {
            "parser_used": "placeholder",
            "records_found": 1000,
            "parse_time": datetime.utcnow().isoformat(),
            "data": {"placeholder": "This will contain actual parsed data"}
        }
        await storage_manager.save_parsed_data(file_id, parsed_data)
        
        # Update status to analyzing
        analysis["status"] = AnalysisStatus.ANALYZING
        
        # Run each analysis engine (placeholders)
        engines = [
            ("yara", analysis_request.enable_yara),
            ("sigma", analysis_request.enable_sigma),
            ("mitre", analysis_request.enable_mitre),
            ("ai", analysis_request.enable_ai)
        ]
        
        results = {}
        for engine, enabled in engines:
            if enabled:
                analysis["stages"][engine]["status"] = "running"
                await asyncio.sleep(1)  # Simulate work
                
                # Placeholder results
                results[engine] = {
                    "matches": 5,
                    "severity": "medium",
                    "details": f"{engine} analysis placeholder results"
                }
                
                analysis["stages"][engine]["status"] = "completed"
                analysis["stages"][engine]["progress"] = 100
            else:
                analysis["stages"][engine]["status"] = "skipped"
        
        # Calculate final progress
        analysis["progress"] = 100
        
        # Create summary
        summary = {
            "total_threats": 10,
            "high_severity": 2,
            "medium_severity": 5,
            "low_severity": 3,
            "iocs_found": 15,
            "patterns_detected": 8,
            "anomalies": 3,
            "ai_insights": "Placeholder AI insights"
        }
        
        analysis["summary"] = summary
        
        # Save analysis results
        analysis_results = {
            "analysis_id": analysis_id,
            "start_time": analysis["start_time"],
            "completion_time": datetime.utcnow().isoformat(),
            "duration_seconds": None,
            "stages": analysis["stages"],
            "results": results,
            "summary": summary
        }
        
        # Calculate duration
        start_time = datetime.fromisoformat(analysis["start_time"])
        end_time = datetime.utcnow()
        analysis_results["duration_seconds"] = (end_time - start_time).total_seconds()
        
        await storage_manager.save_analysis_results(file_id, analysis_results)
        
        # Update final status
        analysis["status"] = AnalysisStatus.COMPLETED
        analysis["end_time"] = end_time.isoformat()
        analysis["duration_seconds"] = analysis_results["duration_seconds"]
        
    except Exception as e:
        # Handle errors
        analysis["status"] = AnalysisStatus.FAILED
        analysis["error"] = str(e)
        analysis["end_time"] = datetime.utcnow().isoformat()
        
        # Update all stages to failed
        for stage in analysis["stages"].values():
            if stage["status"] == "running":
                stage["status"] = "failed"
    
    finally:
        # Remove from active analyses after a delay
        await asyncio.sleep(300)  # Keep in memory for 5 minutes
        if file_id in active_analyses:
            del active_analyses[file_id]