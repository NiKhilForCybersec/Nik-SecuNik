"""
WebSocket API - Real-time updates for analysis progress and results

This module provides WebSocket endpoints for real-time communication
between the backend and frontend during file analysis.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
import json
import uuid
from fastapi import WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from collections import defaultdict
from dataclasses import dataclass, field
import time
from fastapi import APIRouter, FastAPI, WebSocket, Query

router = APIRouter()
logger = logging.getLogger(__name__)

# Security scheme for WebSocket authentication
security = HTTPBearer()

@dataclass
class ConnectionInfo:
    """Information about a WebSocket connection"""
    websocket: WebSocket
    client_id: str
    user_id: Optional[str]
    connected_at: datetime
    subscriptions: Set[str] = field(default_factory=set)
    last_ping: datetime = field(default_factory=datetime.utcnow)
    analysis_sessions: Set[str] = field(default_factory=set)

class WebSocketManager:
    """Manages WebSocket connections and message broadcasting"""
    
    def __init__(self):
        # Active connections
        self.active_connections: Dict[str, ConnectionInfo] = {}
        
        # Subscription management
        self.topic_subscribers: Dict[str, Set[str]] = defaultdict(set)
        
        # Analysis session tracking
        self.analysis_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Message queue for reliability
        self.message_queue: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.max_queue_size = 100
        
        # Metrics
        self.metrics = {
            "total_connections": 0,
            "messages_sent": 0,
            "messages_failed": 0,
            "active_analyses": 0
        }
        
        # Start background tasks
        self._start_background_tasks()
    
    def _start_background_tasks(self):
        """Start background maintenance tasks"""
        asyncio.create_task(self._ping_connections())
        asyncio.create_task(self._cleanup_stale_sessions())
    
    async def _ping_connections(self):
        """Periodically ping connections to keep them alive"""
        while True:
            await asyncio.sleep(30)  # Ping every 30 seconds
            
            disconnected = []
            for client_id, conn_info in self.active_connections.items():
                try:
                    await conn_info.websocket.send_json({
                        "type": "ping",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    conn_info.last_ping = datetime.utcnow()
                except Exception as e:
                    logger.debug(f"Ping failed for {client_id}: {e}")
                    disconnected.append(client_id)
            
            # Remove disconnected clients
            for client_id in disconnected:
                await self.disconnect(client_id)
    
    async def _cleanup_stale_sessions(self):
        """Clean up stale analysis sessions"""
        while True:
            await asyncio.sleep(300)  # Check every 5 minutes
            
            now = datetime.utcnow()
            stale_sessions = []
            
            for session_id, session in self.analysis_sessions.items():
                # Remove sessions older than 1 hour with no activity
                last_update = session.get("last_update", session.get("created_at"))
                if isinstance(last_update, str):
                    last_update = datetime.fromisoformat(last_update)
                
                if (now - last_update).total_seconds() > 3600:
                    stale_sessions.append(session_id)
            
            for session_id in stale_sessions:
                logger.info(f"Removing stale session: {session_id}")
                del self.analysis_sessions[session_id]
    
    async def connect(self, websocket: WebSocket, client_id: Optional[str] = None,
                     user_id: Optional[str] = None) -> str:
        """
        Accept a new WebSocket connection
        
        Args:
            websocket: The WebSocket connection
            client_id: Optional client ID (will generate if not provided)
            user_id: Optional authenticated user ID
            
        Returns:
            Client ID for the connection
        """
        await websocket.accept()
        
        # Generate client ID if not provided
        if not client_id:
            client_id = str(uuid.uuid4())
        
        # Create connection info
        conn_info = ConnectionInfo(
            websocket=websocket,
            client_id=client_id,
            user_id=user_id,
            connected_at=datetime.utcnow()
        )
        
        # Store connection
        self.active_connections[client_id] = conn_info
        self.metrics["total_connections"] += 1
        
        # Send welcome message
        await self.send_personal_message(client_id, {
            "type": "connected",
            "client_id": client_id,
            "timestamp": datetime.utcnow().isoformat(),
            "server_time": datetime.utcnow().isoformat()
        })
        
        # Send any queued messages
        if client_id in self.message_queue:
            for message in self.message_queue[client_id]:
                await self.send_personal_message(client_id, message)
            self.message_queue[client_id].clear()
        
        logger.info(f"WebSocket client connected: {client_id}")
        return client_id
    
    async def disconnect(self, client_id: str):
        """Disconnect a WebSocket client"""
        if client_id in self.active_connections:
            conn_info = self.active_connections[client_id]
            
            # Remove from all subscriptions
            for topic in conn_info.subscriptions:
                self.topic_subscribers[topic].discard(client_id)
            
            # Close connection
            try:
                await conn_info.websocket.close()
            except:
                pass
            
            # Remove connection
            del self.active_connections[client_id]
            
            logger.info(f"WebSocket client disconnected: {client_id}")
    
    async def send_personal_message(self, client_id: str, message: Dict[str, Any]) -> bool:
        """
        Send a message to a specific client
        
        Args:
            client_id: Target client ID
            message: Message to send
            
        Returns:
            True if sent successfully
        """
        if client_id not in self.active_connections:
            # Queue message for when client reconnects
            if len(self.message_queue[client_id]) < self.max_queue_size:
                self.message_queue[client_id].append(message)
            return False
        
        try:
            conn_info = self.active_connections[client_id]
            await conn_info.websocket.send_json(message)
            self.metrics["messages_sent"] += 1
            return True
            
        except Exception as e:
            logger.error(f"Error sending message to {client_id}: {e}")
            self.metrics["messages_failed"] += 1
            await self.disconnect(client_id)
            return False
    
    async def broadcast(self, message: Dict[str, Any], exclude: Optional[Set[str]] = None):
        """
        Broadcast a message to all connected clients
        
        Args:
            message: Message to broadcast
            exclude: Set of client IDs to exclude
        """
        exclude = exclude or set()
        
        disconnected = []
        for client_id in self.active_connections:
            if client_id not in exclude:
                success = await self.send_personal_message(client_id, message)
                if not success:
                    disconnected.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected:
            await self.disconnect(client_id)
    
    async def broadcast_to_topic(self, topic: str, message: Dict[str, Any]):
        """
        Broadcast a message to all subscribers of a topic
        
        Args:
            topic: Topic name
            message: Message to broadcast
        """
        # Add topic to message
        message["topic"] = topic
        
        subscribers = self.topic_subscribers.get(topic, set()).copy()
        for client_id in subscribers:
            await self.send_personal_message(client_id, message)
    
    async def subscribe(self, client_id: str, topic: str) -> bool:
        """
        Subscribe a client to a topic
        
        Args:
            client_id: Client ID
            topic: Topic to subscribe to
            
        Returns:
            True if subscribed successfully
        """
        if client_id not in self.active_connections:
            return False
        
        conn_info = self.active_connections[client_id]
        conn_info.subscriptions.add(topic)
        self.topic_subscribers[topic].add(client_id)
        
        # Send confirmation
        await self.send_personal_message(client_id, {
            "type": "subscribed",
            "topic": topic,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        logger.debug(f"Client {client_id} subscribed to {topic}")
        return True
    
    async def unsubscribe(self, client_id: str, topic: str) -> bool:
        """
        Unsubscribe a client from a topic
        
        Args:
            client_id: Client ID
            topic: Topic to unsubscribe from
            
        Returns:
            True if unsubscribed successfully
        """
        if client_id not in self.active_connections:
            return False
        
        conn_info = self.active_connections[client_id]
        conn_info.subscriptions.discard(topic)
        self.topic_subscribers[topic].discard(client_id)
        
        # Send confirmation
        await self.send_personal_message(client_id, {
            "type": "unsubscribed",
            "topic": topic,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return True
    
    async def create_analysis_session(self, analysis_id: str, 
                                    metadata: Dict[str, Any]) -> str:
        """
        Create a new analysis session
        
        Args:
            analysis_id: Unique analysis ID
            metadata: Session metadata
            
        Returns:
            Session ID
        """
        session = {
            "id": analysis_id,
            "created_at": datetime.utcnow(),
            "status": "created",
            "metadata": metadata,
            "progress": 0,
            "stages": [],
            "results": {},
            "errors": [],
            "last_update": datetime.utcnow()
        }
        
        self.analysis_sessions[analysis_id] = session
        self.metrics["active_analyses"] += 1
        
        # Notify subscribers
        await self.broadcast_to_topic(f"analysis:{analysis_id}", {
            "type": "analysis_session_created",
            "session_id": analysis_id,
            "metadata": metadata,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return analysis_id
    
    async def update_analysis_progress(self, analysis_id: str, 
                                     progress: int, stage: str,
                                     details: Optional[Dict[str, Any]] = None):
        """Update analysis progress"""
        if analysis_id not in self.analysis_sessions:
            logger.warning(f"Unknown analysis session: {analysis_id}")
            return
        
        session = self.analysis_sessions[analysis_id]
        session["progress"] = progress
        session["status"] = "in_progress"
        session["current_stage"] = stage
        session["last_update"] = datetime.utcnow()
        
        if stage not in session["stages"]:
            session["stages"].append(stage)
        
        # Broadcast update
        await self.broadcast_to_topic(f"analysis:{analysis_id}", {
            "type": "analysis_progress",
            "session_id": analysis_id,
            "progress": progress,
            "stage": stage,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def send_analysis_result(self, analysis_id: str, 
                                 result_type: str,
                                 result_data: Dict[str, Any]):
        """Send analysis result"""
        if analysis_id not in self.analysis_sessions:
            return
        
        session = self.analysis_sessions[analysis_id]
        session["results"][result_type] = result_data
        session["last_update"] = datetime.utcnow()
        
        # Broadcast result
        await self.broadcast_to_topic(f"analysis:{analysis_id}", {
            "type": "analysis_result",
            "session_id": analysis_id,
            "result_type": result_type,
            "data": result_data,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def complete_analysis(self, analysis_id: str, 
                              final_results: Dict[str, Any]):
        """Mark analysis as complete"""
        if analysis_id not in self.analysis_sessions:
            return
        
        session = self.analysis_sessions[analysis_id]
        session["status"] = "completed"
        session["progress"] = 100
        session["completed_at"] = datetime.utcnow()
        session["final_results"] = final_results
        
        self.metrics["active_analyses"] = max(0, self.metrics["active_analyses"] - 1)
        
        # Broadcast completion
        await self.broadcast_to_topic(f"analysis:{analysis_id}", {
            "type": "analysis_completed",
            "session_id": analysis_id,
            "results": final_results,
            "duration": (session["completed_at"] - session["created_at"]).total_seconds(),
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def send_error(self, analysis_id: str, error: str, 
                        severity: str = "error"):
        """Send error message for analysis"""
        if analysis_id not in self.analysis_sessions:
            return
        
        session = self.analysis_sessions[analysis_id]
        session["errors"].append({
            "error": error,
            "severity": severity,
            "timestamp": datetime.utcnow()
        })
        
        # Broadcast error
        await self.broadcast_to_topic(f"analysis:{analysis_id}", {
            "type": "analysis_error",
            "session_id": analysis_id,
            "error": error,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def send_update(self, update: Dict[str, Any]):
        """Send a general update to relevant clients"""
        update_type = update.get("type", "unknown")
        
        # Route based on update type
        if update_type == "analysis_started":
            analysis_id = update.get("analysis_id")
            if analysis_id:
                await self.create_analysis_session(analysis_id, update)
        
        elif update_type == "analysis_progress":
            analysis_id = update.get("analysis_id")
            if analysis_id:
                await self.update_analysis_progress(
                    analysis_id,
                    update.get("progress", 0),
                    update.get("stage", "unknown"),
                    update.get("details")
                )
        
        elif update_type == "analyzer_progress":
            analysis_id = update.get("analysis_id")
            if analysis_id:
                await self.broadcast_to_topic(f"analysis:{analysis_id}", update)
        
        elif update_type in ["analysis_completed", "analysis_error"]:
            analysis_id = update.get("analysis_id")
            if analysis_id:
                await self.broadcast_to_topic(f"analysis:{analysis_id}", update)
        
        else:
            # Broadcast to all for general updates
            await self.broadcast(update)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get WebSocket statistics"""
        return {
            "active_connections": len(self.active_connections),
            "total_connections": self.metrics["total_connections"],
            "messages_sent": self.metrics["messages_sent"],
            "messages_failed": self.metrics["messages_failed"],
            "active_analyses": self.metrics["active_analyses"],
            "topics": {
                topic: len(subscribers) 
                for topic, subscribers in self.topic_subscribers.items()
            }
        }
    
    async def handle_client_message(self, client_id: str, message: Dict[str, Any]):
        """Handle incoming message from client"""
        msg_type = message.get("type")
        
        if msg_type == "subscribe":
            topic = message.get("topic")
            if topic:
                await self.subscribe(client_id, topic)
        
        elif msg_type == "unsubscribe":
            topic = message.get("topic")
            if topic:
                await self.unsubscribe(client_id, topic)
        
        elif msg_type == "ping":
            # Respond with pong
            await self.send_personal_message(client_id, {
                "type": "pong",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        elif msg_type == "get_analysis_status":
            analysis_id = message.get("analysis_id")
            if analysis_id and analysis_id in self.analysis_sessions:
                session = self.analysis_sessions[analysis_id]
                await self.send_personal_message(client_id, {
                    "type": "analysis_status",
                    "session": {
                        "id": session["id"],
                        "status": session["status"],
                        "progress": session["progress"],
                        "current_stage": session.get("current_stage"),
                        "stages": session["stages"],
                        "errors": session["errors"]
                    },
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        else:
            logger.warning(f"Unknown message type from {client_id}: {msg_type}")

# Global WebSocket manager instance
ws_manager = WebSocketManager()

# WebSocket endpoint handler
async def websocket_endpoint(websocket: WebSocket, 
                           client_id: Optional[str] = None,
                           token: Optional[str] = None):
    """
    WebSocket endpoint for real-time updates
    
    Args:
        websocket: The WebSocket connection
        client_id: Optional client ID
        token: Optional authentication token
    """
    user_id = None
    
    # Validate token if provided
    if token:
        try:
            # Decode JWT token (implement based on your auth system)
            # payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            # user_id = payload.get("user_id")
            pass
        except Exception as e:
            logger.error(f"Invalid token: {e}")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    
    # Connect client
    client_id = await ws_manager.connect(websocket, client_id, user_id)
    
    try:
        # Handle incoming messages
        while True:
            # Receive message
            data = await websocket.receive_json()
            
            # Handle the message
            await ws_manager.handle_client_message(client_id, data)
            
    except WebSocketDisconnect:
        logger.info(f"Client {client_id} disconnected normally")
    except Exception as e:
        logger.error(f"WebSocket error for {client_id}: {e}")
    finally:
        # Disconnect client
        await ws_manager.disconnect(client_id)

# Utility functions for other modules to send updates
async def notify_analysis_start(analysis_id: str, file_path: str):
    """Notify clients that analysis has started"""
    await ws_manager.send_update({
        "type": "analysis_started",
        "analysis_id": analysis_id,
        "file": file_path,
        "timestamp": datetime.utcnow().isoformat()
    })

async def notify_analysis_progress(analysis_id: str, progress: int, 
                                 stage: str, details: Optional[Dict[str, Any]] = None):
    """Notify clients of analysis progress"""
    await ws_manager.send_update({
        "type": "analysis_progress",
        "analysis_id": analysis_id,
        "progress": progress,
        "stage": stage,
        "details": details or {},
        "timestamp": datetime.utcnow().isoformat()
    })

async def notify_analysis_complete(analysis_id: str, results: Dict[str, Any]):
    """Notify clients that analysis is complete"""
    await ws_manager.send_update({
        "type": "analysis_completed",
        "analysis_id": analysis_id,
        "results": results,
        "timestamp": datetime.utcnow().isoformat()
    })

async def notify_analysis_error(analysis_id: str, error: str):
    """Notify clients of analysis error"""
    await ws_manager.send_update({
        "type": "analysis_error",
        "analysis_id": analysis_id,
        "error": error,
        "timestamp": datetime.utcnow().isoformat()
    })
# WebSocket routes
@router.websocket("/analysis/{analysis_id}")
async def websocket_analysis_endpoint(
    websocket: WebSocket,
    analysis_id: str,
    token: Optional[str] = Query(None)
):
    """WebSocket endpoint for analysis updates"""
    await websocket_endpoint(
        websocket,
        client_id=f"analysis_{analysis_id}",
        token=token
    )
    
    # Auto-subscribe to analysis topic
    await ws_manager.subscribe(f"analysis_{analysis_id}", f"analysis:{analysis_id}")


@router.websocket("/connect")
async def websocket_connect_endpoint(
    websocket: WebSocket,
    client_id: Optional[str] = Query(None),
    token: Optional[str] = Query(None)
):
    """General WebSocket endpoint"""
    await websocket_endpoint(websocket, client_id, token)