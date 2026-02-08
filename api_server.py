"""
api_server.py
NetSentinel Cortex v2.0 - FastAPI Data Sharing Layer

Provides REST API access to:
- Live packet statistics
- Recent alerts
- Active threats
- Plugin management

Run with: uvicorn api_server:app --host 0.0.0.0 --port 8081 --reload
"""

import os
import sys
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker


# === Pydantic Models ===

class AlertResponse(BaseModel):
    id: int
    timestamp: str
    alert_type: str
    source_ip: Optional[str]
    details: str
    severity: Optional[str]
    
    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    total_alerts: int
    alerts_last_hour: int
    critical_alerts: int
    high_alerts: int
    top_sources: List[dict]


class PluginInfoResponse(BaseModel):
    name: str
    version: str
    author: str
    description: str
    tags: List[str]
    enabled: bool
    packets_analyzed: int
    alerts_generated: int


# === Database Setup ===

DB_PATH = os.path.abspath("net_sentinel.db")
engine = create_engine(f'sqlite:///{DB_PATH}', connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# === FastAPI App ===

app = FastAPI(
    title="NetSentinel Cortex API",
    description="Data Sharing Layer for the NetSentinel IDS Engine",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS for dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# === Health Check ===

@app.get("/", tags=["Health"])
async def root():
    """API health check."""
    return {
        "status": "online",
        "service": "NetSentinel Cortex API",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Detailed health check."""
    db_exists = os.path.exists(DB_PATH)
    return {
        "status": "healthy" if db_exists else "degraded",
        "database": "connected" if db_exists else "not found",
        "database_path": DB_PATH
    }


# === Alerts Endpoints ===

@app.get("/alerts/latest", response_model=List[AlertResponse], tags=["Alerts"])
async def get_latest_alerts(
    limit: int = Query(50, ge=1, le=500, description="Number of alerts to return"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)")
):
    """
    Get the most recent alerts from the database.
    
    - **limit**: Maximum number of alerts to return (1-500)
    - **severity**: Optional severity filter
    """
    db = SessionLocal()
    try:
        from sqlalchemy import text
        
        query = "SELECT id, timestamp, alert_type, source_ip, details, severity FROM alert ORDER BY timestamp DESC"
        
        if severity:
            query = f"SELECT id, timestamp, alert_type, source_ip, details, severity FROM alert WHERE severity = '{severity.upper()}' ORDER BY timestamp DESC"
        
        query += f" LIMIT {limit}"
        
        result = db.execute(text(query))
        rows = result.fetchall()
        
        alerts = []
        for row in rows:
            alerts.append(AlertResponse(
                id=row[0],
                timestamp=str(row[1]) if row[1] else "",
                alert_type=row[2] or "UNKNOWN",
                source_ip=row[3],
                details=row[4] or "",
                severity=row[5]
            ))
        
        return alerts
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@app.get("/alerts/count", tags=["Alerts"])
async def get_alert_count():
    """Get count of alerts by severity."""
    db = SessionLocal()
    try:
        from sqlalchemy import text
        
        result = db.execute(text(
            "SELECT severity, COUNT(*) FROM alert GROUP BY severity"
        ))
        
        counts = {row[0] or "UNKNOWN": row[1] for row in result.fetchall()}
        total = sum(counts.values())
        
        return {
            "total": total,
            "by_severity": counts
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


# === Statistics Endpoints ===

@app.get("/stats", response_model=StatsResponse, tags=["Statistics"])
async def get_stats():
    """
    Get live statistics from the IDS engine.
    
    Returns packet counts, threat levels, and top attacking sources.
    """
    db = SessionLocal()
    try:
        from sqlalchemy import text
        from datetime import timedelta
        
        # Total alerts
        total = db.execute(text("SELECT COUNT(*) FROM alert")).scalar() or 0
        
        # Alerts last hour
        hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
        last_hour = db.execute(text(
            f"SELECT COUNT(*) FROM alert WHERE timestamp > '{hour_ago}'"
        )).scalar() or 0
        
        # Critical/High counts
        critical = db.execute(text(
            "SELECT COUNT(*) FROM alert WHERE severity = 'CRITICAL'"
        )).scalar() or 0
        
        high = db.execute(text(
            "SELECT COUNT(*) FROM alert WHERE severity = 'HIGH'"
        )).scalar() or 0
        
        # Top sources
        top_sources_result = db.execute(text(
            "SELECT source_ip, COUNT(*) as count FROM alert WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY count DESC LIMIT 10"
        ))
        top_sources = [{"ip": row[0], "count": row[1]} for row in top_sources_result.fetchall()]
        
        return StatsResponse(
            total_alerts=total,
            alerts_last_hour=last_hour,
            critical_alerts=critical,
            high_alerts=high,
            top_sources=top_sources
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


# === Threats Endpoints ===

@app.get("/threats/active", tags=["Threats"])
async def get_active_threats():
    """
    Get currently active threat sessions.
    
    Returns IPs with multiple recent alerts (last 5 minutes).
    """
    db = SessionLocal()
    try:
        from sqlalchemy import text
        from datetime import timedelta
        
        five_min_ago = (datetime.now() - timedelta(minutes=5)).isoformat()
        
        result = db.execute(text(f"""
            SELECT source_ip, COUNT(*) as alert_count, MAX(severity) as max_severity
            FROM alert 
            WHERE timestamp > '{five_min_ago}' AND source_ip IS NOT NULL
            GROUP BY source_ip
            HAVING alert_count >= 2
            ORDER BY alert_count DESC
        """))
        
        threats = []
        for row in result.fetchall():
            threats.append({
                "source_ip": row[0],
                "alert_count": row[1],
                "max_severity": row[2] or "UNKNOWN",
                "status": "ACTIVE"
            })
        
        return {
            "active_threats": len(threats),
            "threats": threats
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


# === Plugin Management (Placeholder) ===

@app.get("/plugins", tags=["Plugins"])
async def list_plugins():
    """
    List all loaded plugins.
    
    Note: This requires the IDS engine to be running and sharing state.
    Currently returns static list.
    """
    # In production, this would connect to the running engine via Redis/IPC
    return {
        "plugins": [
            {"name": "SYN Flood Detector", "version": "2.0.0", "enabled": True},
            {"name": "Plaintext Credential Detector", "version": "2.0.0", "enabled": True},
            {"name": "ARP Spoofing Detector", "version": "2.0.0", "enabled": True},
            {"name": "DPI Inspector", "version": "1.0.0", "enabled": True},
        ],
        "total": 4,
        "note": "Connect via Redis for real-time plugin state"
    }


@app.post("/config/reload", tags=["Config"])
async def reload_config():
    """
    Hot-reload plugins and configuration.
    
    Note: In production, this would signal the IDS engine to reload.
    """
    return {
        "status": "reload_requested",
        "message": "Plugin reload signal sent (IPC required for full functionality)"
    }


# === Main Entry Point ===

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("  NETSENTINEL CORTEX API v2.0")
    print("  Data Sharing Layer")
    print("="*60)
    print(f"  Database: {DB_PATH}")
    print(f"  Docs: http://localhost:8081/docs")
    print("="*60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8081)
