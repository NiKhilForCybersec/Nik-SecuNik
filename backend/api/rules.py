"""
Rules API - Rule management endpoints
Provides CRUD operations for detection rules via REST API
"""

from fastapi import APIRouter, HTTPException, Depends, Query, UploadFile, File, BackgroundTasks, Path
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator, validator, ConfigDict
from datetime import datetime
import json
import tempfile
import os

from rules.rule_manager import RuleManager, Rule
from rules.rule_validator import RuleValidator, ValidationResult
from config import settings

router = APIRouter(prefix="/api/rules", tags=["rules"])

# Pydantic models
class RuleCreate(BaseModel):
    """Rule creation request"""
    name: str = Field(..., min_length=3, max_length=100)
    type: str = Field(..., pattern="^(yara|sigma|custom)$")
    category: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=500)
    content: str = Field(..., min_length=10)
    author: Optional[str] = Field(None, max_length=100)
    tags: List[str] = Field(default_factory=list)
    severity: str = Field("medium", pattern="^(informational|low|medium|high|critical)$")
    enabled: bool = Field(True)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    references: List[str] = Field(default_factory=list)
    false_positive: List[str] = Field(default_factory=list)
    mitre_attack: List[str] = Field(default_factory=list)
    
    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v):
        return [tag.lower().strip() for tag in v if tag.strip()]

class RuleUpdate(BaseModel):
    """Rule update request"""
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    category: Optional[str] = Field(None, min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=500)
    content: Optional[str] = Field(None, min_length=10)
    tags: Optional[List[str]] = None
    severity: Optional[str] = Field(None, pattern="^(informational|low|medium|high|critical)$")
    enabled: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None
    references: Optional[List[str]] = None
    false_positive: Optional[List[str]] = None
    mitre_attack: Optional[List[str]] = None

class RuleResponse(BaseModel):
    """Rule response model"""
    id: str
    name: str
    type: str
    category: str
    description: str
    author: str
    created_at: datetime
    updated_at: datetime
    version: str
    tags: List[str]
    severity: str
    enabled: bool
    metadata: Dict[str, Any]
    references: List[str]
    false_positive: List[str]
    mitre_attack: List[str]
    
    model_config = ConfigDict(from_attributes=True)
class RuleListResponse(BaseModel):
    """Rule list response"""
    rules: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    has_more: bool

class RuleValidationResponse(BaseModel):
    """Rule validation response"""
    valid: bool
    errors: List[str]
    warnings: List[str]
    suggestions: List[str]
    metadata: Dict[str, Any]

class RuleTestRequest(BaseModel):
    """Rule test request"""
    content: Optional[str] = None
    logs: Optional[List[Dict[str, Any]]] = None
    file_path: Optional[str] = None

class RuleImportResponse(BaseModel):
    """Rule import response"""
    imported: int
    imported_ids: List[str]
    errors: List[Dict[str, str]]
    success: bool

class RuleStatsResponse(BaseModel):
    """Rule statistics response"""
    total_rules: int
    by_type: Dict[str, int]
    by_category: Dict[str, int]
    by_severity: Dict[str, int]
    enabled: int
    disabled: int
    recent_updates: List[Dict[str, Any]]

# Dependency injection
rule_manager: Optional[RuleManager] = None
rule_validator: RuleValidator = RuleValidator()

async def get_rule_manager() -> RuleManager:
    """Get rule manager instance"""
    global rule_manager
    if rule_manager is None:
        from ..rules.rule_manager import initialize_rule_manager
        settings = get_settings()
        rule_manager = await initialize_rule_manager(settings.dict())
    return rule_manager

# API Endpoints
@router.post("/", response_model=RuleResponse)
async def create_rule(
    rule_data: RuleCreate,
    background_tasks: BackgroundTasks,
    manager: RuleManager = Depends(get_rule_manager)
):
    """Create new detection rule"""
    try:
        # Validate rule syntax first
        validation = await rule_validator.validate_rule(
            rule_data.content,
            rule_data.type,
            rule_data.metadata
        )
        
        if not validation.valid:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Rule validation failed",
                    "errors": validation.errors,
                    "warnings": validation.warnings
                }
            )
            
        # Create rule
        rule = await manager.create_rule(rule_data.dict())
        
        # Background task to update rule index
        background_tasks.add_task(update_rule_index, manager)
        
        return RuleResponse(**rule.__dict__)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: str,
    manager: RuleManager = Depends(get_rule_manager)
):
    """Get rule by ID"""
    rule = await manager.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return RuleResponse(**rule.__dict__)

@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str,
    updates: RuleUpdate,
    background_tasks: BackgroundTasks,
    manager: RuleManager = Depends(get_rule_manager)
):
    """Update existing rule"""
    try:
        # Get existing rule
        existing = await manager.get_rule(rule_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Rule not found")
            
        # Validate content if being updated
        if updates.content:
            validation = await rule_validator.validate_rule(
                updates.content,
                existing.type,
                updates.metadata or existing.metadata
            )
            
            if not validation.valid:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": "Rule validation failed",
                        "errors": validation.errors,
                        "warnings": validation.warnings
                    }
                )
                
        # Update rule
        update_dict = updates.dict(exclude_unset=True)
        rule = await manager.update_rule(rule_id, update_dict)
        
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
            
        # Background task to update index
        background_tasks.add_task(update_rule_index, manager)
        
        return RuleResponse(**rule.__dict__)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{rule_id}")
async def delete_rule(
    rule_id: str,
    background_tasks: BackgroundTasks,
    manager: RuleManager = Depends(get_rule_manager)
):
    """Delete rule"""
    success = await manager.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    # Background task to update index
    background_tasks.add_task(update_rule_index, manager)
    
    return {"message": "Rule deleted successfully"}

@router.get("/", response_model=RuleListResponse)
async def list_rules(
    rule_type: Optional[str] = Query(None, pattern="^(yara|sigma|custom)$"),
    category: Optional[str] = None,
    enabled_only: bool = False,
    tags: Optional[str] = Query(None, description="Comma-separated tags"),
    severity: Optional[str] = Query(None, pattern="^(informational|low|medium|high|critical)$"),
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    manager: RuleManager = Depends(get_rule_manager)
):
    """List rules with filtering and pagination"""
    # Parse tags
    tag_list = None
    if tags:
        tag_list = [t.strip() for t in tags.split(',') if t.strip()]
        
    result = await manager.list_rules(
        rule_type=rule_type,
        category=category,
        enabled_only=enabled_only,
        tags=tag_list,
        severity=severity,
        search=search,
        limit=limit,
        offset=offset
    )
    
    return RuleListResponse(**result)

@router.post("/validate", response_model=RuleValidationResponse)
async def validate_rule(
    rule_type: str = Query(..., pattern="^(yara|sigma|custom)$"),
    content: str = Query(..., min_length=10),
    metadata: Optional[Dict[str, Any]] = None
):
    """Validate rule syntax without saving"""
    validation = await rule_validator.validate_rule(content, rule_type, metadata)
    return RuleValidationResponse(
        valid=validation.valid,
        errors=validation.errors,
        warnings=validation.warnings,
        suggestions=validation.suggestions,
        metadata=validation.metadata
    )

@router.post("/{rule_id}/test")
async def test_rule(
    rule_id: str,
    test_data: RuleTestRequest,
    manager: RuleManager = Depends(get_rule_manager)
):
    """Test rule against sample data"""
    try:
        # Prepare test data
        test_dict = {}
        if test_data.content:
            test_dict['content'] = test_data.content
        if test_data.logs:
            test_dict['logs'] = test_data.logs
        if test_data.file_path:
            # Read file content for testing
            with open(test_data.file_path, 'rb') as f:
                test_dict['content'] = f.read().decode('utf-8', errors='ignore')
                
        result = await manager.test_rule(rule_id, test_dict)
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/import", response_model=RuleImportResponse)
async def import_rules(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    rule_type: str = Query(..., pattern="^(yara|sigma|custom)$"),
    manager: RuleManager = Depends(get_rule_manager)
):
    """Import rules from file"""
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=file.filename) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file.flush()
            
        try:
            # Import rules
            result = await manager.import_rules(tmp_file.name, rule_type)
            
            # Background task to update index
            background_tasks.add_task(update_rule_index, manager)
            
            return RuleImportResponse(**result)
            
        finally:
            # Clean up temp file
            os.unlink(tmp_file.name)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/export/{format}")
async def export_rules(
    format: str = Path(..., pattern="^(json|yaml|raw)$"),
    rule_ids: Optional[str] = Query(None, description="Comma-separated rule IDs"),
    rule_type: Optional[str] = Query(None, pattern="^(yara|sigma|custom)$"),
    manager: RuleManager = Depends(get_rule_manager)
):
    """Export rules to file"""
    try:
        # Parse rule IDs
        id_list = None
        if rule_ids:
            id_list = [id.strip() for id in rule_ids.split(',') if id.strip()]
            
        export_path = await manager.export_rules(
            rule_ids=id_list,
            rule_type=rule_type,
            format=format
        )
        
        return {
            "export_path": export_path,
            "format": format,
            "message": "Rules exported successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats/summary", response_model=RuleStatsResponse)
async def get_rule_stats(manager: RuleManager = Depends(get_rule_manager)):
    """Get rule statistics"""
    stats = await manager.get_rule_stats()
    return RuleStatsResponse(**stats)

@router.get("/categories")
async def get_categories(
    rule_type: Optional[str] = Query(None, pattern="^(yara|sigma|custom)$"),
    manager: RuleManager = Depends(get_rule_manager)
):
    """Get available rule categories"""
    index = await manager.load_index()
    categories = index.get('categories', {})
    
    if rule_type:
        return categories.get(rule_type, [])
    return categories

@router.post("/templates/{rule_type}")
async def generate_template(
    rule_type: str = Path(..., pattern="^(yara|sigma|custom)$"),
    parameters: Optional[Dict[str, Any]] = None
):
    """Generate rule template"""
    try:
        template = await rule_validator.generate_rule_template(rule_type, parameters)
        return {
            "template": template,
            "type": rule_type,
            "content_type": "text/plain" if rule_type == "yara" else "application/json"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/bulk/validate")
async def validate_rule_set(rules: List[Dict[str, Any]]):
    """Validate multiple rules for conflicts"""
    try:
        result = await rule_validator.validate_rule_set(rules)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/bulk/enable")
async def bulk_enable_rules(
    rule_ids: List[str],
    background_tasks: BackgroundTasks,
    enabled: bool = True,
    manager: RuleManager = Depends(get_rule_manager)
):
    """Enable/disable multiple rules"""
    try:
        updated = 0
        errors = []
        
        for rule_id in rule_ids:
            try:
                rule = await manager.update_rule(rule_id, {"enabled": enabled})
                if rule:
                    updated += 1
            except Exception as e:
                errors.append({"rule_id": rule_id, "error": str(e)})
                
        # Background task to update index
        background_tasks.add_task(update_rule_index, manager)
        
        return {
            "updated": updated,
            "errors": errors,
            "success": len(errors) == 0
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Helper functions
async def update_rule_index(manager: RuleManager):
    """Background task to update rule index"""
    try:
        # Reload and optimize index
        index = await manager.load_index()
        index['metadata']['last_updated'] = datetime.now().isoformat()
        await manager.save_index(index)
    except Exception as e:
        print(f"Error updating rule index: {e}")

# WebSocket endpoint for real-time rule updates
from fastapi import WebSocket, WebSocketDisconnect
from api.websocket import ws_manager

@router.websocket("/ws")
async def rule_updates_websocket(websocket: WebSocket):
    """WebSocket for real-time rule updates"""
    await ws_manager.connect(websocket)
    
    try:
        while True:
            # Wait for messages
            data = await websocket.receive_json()
            
            if data.get("action") == "subscribe":
                # Subscribe to rule updates
                await ws_manager.subscribe(websocket, "rule_updates")
                
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)