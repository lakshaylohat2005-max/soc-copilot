import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from .db import Base, engine
from .routers import (
    health_router,
    logs_router,
    alerts_router,
    incidents_router,
    simulations_router,
)

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all database tables on application startup
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="SOC Copilot API",
    description="Mini Security Operations Center backend with MITRE ATT&CK correlation, LLM triage, and automated response.",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS Setup
origins_raw = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000")
origins = [origin.strip() for origin in origins_raw.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Health Endpoints (both root /health and /api/health)
app.include_router(health_router)
app.include_router(health_router, prefix="/api")

# Register CRUD Routers
app.include_router(logs_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(simulations_router)

# Real-time WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "PONG", "payload": data})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
