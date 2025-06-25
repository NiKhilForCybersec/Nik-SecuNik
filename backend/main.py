"""
SecuNik LogX - Main FastAPI Application
Universal Security Log Parser and Analyzer
"""

import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from core.storage_manager import StorageManager
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from config import settings
from api import upload, analysis, history, rules, virustotal, websocket
from utils.file_utils import ensure_directories

# Add backend directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    # Startup
    print(f"🚀 Starting SecuNik LogX v{settings.VERSION}")
    print(f"📁 Storage path: {settings.STORAGE_PATH}")
    
    # Ensure required directories exist
    ensure_directories()
    
    # Initialize storage manager
    storage_manager = StorageManager()
    await storage_manager.initialize()
    
    # Store in app state
    app.state.storage_manager = storage_manager
    
    yield
    
    # Shutdown
    print("👋 Shutting down SecuNik LogX")
    await storage_manager.cleanup()


# Create FastAPI app
app = FastAPI(
    title="SecuNik LogX",
    description="Universal Security Log Parser and Analyzer",
    version=settings.VERSION,
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions"""
    timestamp = datetime.utcnow().isoformat()
    error_id = f"ERR-{timestamp}"
    
    # Log the error
    import traceback
    error_details = {
        "error_id": error_id,
        "timestamp": timestamp,
        "path": request.url.path,
        "method": request.method,
        "error": str(exc),
        "traceback": traceback.format_exc()
    }
    
    # In production, you'd log this to a file or monitoring service
    print(f"❌ Error {error_id}: {exc}")
    
    # Return user-friendly error
    return JSONResponse(
        status_code=500,
        content={
            "error": "An unexpected error occurred",
            "error_id": error_id,
            "timestamp": timestamp,
            "detail": str(exc) if settings.DEBUG else "Internal server error"
        }
    )

# Include API routers
app.include_router(upload.router, prefix="/api/upload", tags=["upload"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["analysis"])
app.include_router(history.router, prefix="/api/history", tags=["history"])
app.include_router(rules.router, prefix="/api/rules", tags=["rules"])
app.include_router(virustotal.router, prefix="/api/virustotal", tags=["virustotal"])
app.include_router(websocket.router, prefix="/ws", tags=["websocket"])

# Mount static files for frontend (in production)
if settings.SERVE_FRONTEND:
    app.mount("/", StaticFiles(directory="../frontend/dist", html=True), name="frontend")

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    storage_stats = await app.state.storage_manager.get_storage_stats()
    
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "timestamp": datetime.utcnow().isoformat(),
        "storage": storage_stats,
        "features": {
            "max_file_size": f"{settings.MAX_FILE_SIZE_MB}MB",
            "supported_parsers": 50,  # Will be dynamic later
            "analysis_engines": ["YARA", "Sigma", "MITRE", "AI"],
            "integrations": {
                "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
                "openai": bool(settings.OPENAI_API_KEY)
            }
        }
    }

# Root endpoint
@app.get("/api")
async def root():
    """API root endpoint"""
    return {
        "app": "SecuNik LogX",
        "version": settings.VERSION,
        "description": "Universal Security Log Parser and Analyzer",
        "documentation": "/docs",
        "health": "/health"
    }

# Development server
if __name__ == "__main__":
    # Run with uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
        access_log=True
    )