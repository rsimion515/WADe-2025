"""
ASC - Web Application Security Control

Main application entry point.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

from .config import get_settings
from .models.database import init_db, get_db, async_session_maker
from .models.category import SoftwareCategory, PREDEFINED_CATEGORIES
from .services.exploit_scraper import load_sample_exploits, ExploitScraper
from .services.sparql_service import get_sparql_service
from .services.pubsub import get_pubsub_service, publish_exploit_alert
from .services.websub import get_websub_hub
from .services.cache_proxy import get_cache_proxy
from .api import exploits_router, sparql_router, websub_router, subscriptions_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting ASC - Web Application Security Control")
    
    # Initialize database
    await init_db()
    logger.info("Database initialized")
    
    # Load predefined categories
    async with async_session_maker() as db:
        from sqlalchemy import select
        for cat_data in PREDEFINED_CATEGORIES:
            existing = await db.execute(
                select(SoftwareCategory).where(SoftwareCategory.slug == cat_data["slug"])
            )
            if not existing.scalar_one_or_none():
                db.add(SoftwareCategory(**cat_data))
        await db.commit()
    logger.info("Categories loaded")
    
    # Load sample exploits for demonstration
    async with async_session_maker() as db:
        exploits = await load_sample_exploits(db)
        if exploits:
            logger.info(f"Loaded {len(exploits)} sample exploits")
            
            # Add exploits to RDF graph
            sparql = get_sparql_service()
            sparql.add_exploits(exploits)
            
            # Publish alerts for new exploits
            for exploit in exploits:
                await publish_exploit_alert({
                    "id": exploit.id,
                    "title": exploit.title,
                    "severity": exploit.severity,
                    "software_type": exploit.software_type,
                    "exploit_type": exploit.exploit_type,
                    "platform": exploit.platform,
                    "cve_id": exploit.cve_id,
                })
    
    # Start WebSub hub
    websub = get_websub_hub()
    await websub.start()
    logger.info("WebSub hub started")
    
    # Initialize cache proxy
    cache = get_cache_proxy()
    logger.info("Cache proxy initialized")
    
    logger.info(f"ASC running at http://{settings.host}:{settings.port}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down ASC")
    await websub.stop()
    await cache.clear()


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
    ASC (Web Application Security Control)

    * REST API: `/api/exploits`
    * SPARQL: `/sparql`
    * WebSub: `/websub`
    * WebSocket: `/api/subscriptions/ws`
    """,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(exploits_router)
app.include_router(sparql_router)
app.include_router(websub_router)
app.include_router(subscriptions_router)

# Static files
static_path = Path(__file__).parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=static_path), name="static")


@app.get("/", response_class=HTMLResponse)
async def home():
    """Serve the main dashboard."""
    return get_dashboard_html()


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": settings.app_version,
    }


@app.get("/api/stats")
async def get_statistics():
    """Get system statistics."""
    sparql = get_sparql_service()
    pubsub = get_pubsub_service()
    cache = get_cache_proxy()
    
    return {
        "rdf_graph": sparql.get_statistics(),
        "pubsub": {
            "topics": list(pubsub.get_topics().keys()),
            "subscriber_counts": {
                topic: pubsub.get_subscriber_count(topic)
                for topic in pubsub.get_topics()
            },
        },
        "cache": cache.stats,
    }


@app.get("/api/categories")
async def list_categories():
    """List software categories."""
    async with async_session_maker() as db:
        from sqlalchemy import select
        result = await db.execute(select(SoftwareCategory))
        categories = result.scalars().all()
        return [
            {
                "id": c.id,
                "name": c.name,
                "slug": c.slug,
                "description": c.description,
                "examples": c.examples,
            }
            for c in categories
        ]


def get_dashboard_html() -> str:
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASC - Web Application Security Control</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #050508;
            --bg-gradient: linear-gradient(135deg, #050508 0%, #0a0a12 50%, #080810 100%);
            --surface: #0c0c14;
            --surface-2: #121220;
            --surface-3: #18182a;
            --border: #1e1e35;
            --border-glow: #2a2a50;
            --text: #f0f0f8;
            --text-muted: #7878a0;
            --accent: #f43f5e;
            --accent-glow: rgba(244, 63, 94, 0.3);
            --purple: #a855f7;
            --blue: #3b82f6;
            --green: #22c55e;
            --yellow: #eab308;
            --orange: #f97316;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
        }}
        
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        
        body {{
            font-family: 'Outfit', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
        }}
        
        /* Animated background */
        .bg-pattern {{
            position: fixed;
            inset: 0;
            background: 
                radial-gradient(ellipse 80% 50% at 50% -20%, rgba(168, 85, 247, 0.15), transparent),
                radial-gradient(ellipse 60% 40% at 100% 100%, rgba(244, 63, 94, 0.1), transparent),
                radial-gradient(ellipse 40% 60% at 0% 80%, rgba(59, 130, 246, 0.08), transparent);
            pointer-events: none;
            z-index: 0;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
            position: relative;
            z-index: 1;
        }}
        
        /* Header */
        header {{
            text-align: center;
            padding: 4rem 0 3rem;
            position: relative;
        }}
        
        .logo {{
            font-size: 4rem;
            margin-bottom: 1rem;
            filter: drop-shadow(0 0 30px var(--accent-glow));
        }}
        
        h1 {{
            font-size: 3rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            background: linear-gradient(135deg, var(--text) 0%, var(--accent) 50%, var(--purple) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 1rem;
        }}
        
        .tagline {{
            font-size: 1.25rem;
            color: var(--text-muted);
            font-weight: 300;
            max-width: 600px;
            margin: 0 auto;
        }}
        
        /* Stats bar */
        .stats-bar {{
            display: flex;
            justify-content: center;
            gap: 3rem;
            margin: 3rem 0;
            padding: 1.5rem 2rem;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            backdrop-filter: blur(10px);
        }}
        
        .stat {{
            text-align: center;
        }}
        
        .stat-value {{
            font-size: 2rem;
            font-weight: 600;
            color: var(--accent);
        }}
        
        .stat-label {{
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }}
        
        /* Grid layout */
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }}
        
        /* Cards */
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 2rem;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        
        .card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent), var(--purple));
            opacity: 0;
            transition: opacity 0.3s;
        }}
        
        .card:hover {{
            border-color: var(--border-glow);
            transform: translateY(-4px);
            box-shadow: 0 20px 40px -20px rgba(0, 0, 0, 0.5);
        }}
        
        .card:hover::before {{ opacity: 1; }}
        
        .card-icon {{
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }}
        
        .card h2 {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
        }}
        
        .card p {{
            color: var(--text-muted);
            font-size: 0.95rem;
            line-height: 1.6;
            margin-bottom: 1.5rem;
        }}
        
        .card-links {{
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }}
        
        .card-links a {{
            color: var(--accent);
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
            padding: 0.5rem 1rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            transition: all 0.2s;
        }}
        
        .card-links a:hover {{
            background: var(--accent);
            border-color: var(--accent);
            color: white;
        }}
        
        /* Live alerts section */
        .alerts-section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 3rem;
        }}
        
        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }}
        
        .section-header h2 {{
            font-size: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .live-dot {{
            width: 10px;
            height: 10px;
            background: var(--green);
            border-radius: 50%;
            animation: pulse 2s infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; transform: scale(1); }}
            50% {{ opacity: 0.5; transform: scale(1.2); }}
        }}
        
        .alerts-list {{
            max-height: 400px;
            overflow-y: auto;
        }}
        
        .alert-item {{
            display: flex;
            gap: 1rem;
            padding: 1rem;
            background: var(--surface-2);
            border-radius: 10px;
            margin-bottom: 0.75rem;
            transition: background 0.2s;
        }}
        
        .alert-item:hover {{ background: var(--surface-3); }}
        
        .alert-severity {{
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            white-space: nowrap;
        }}
        
        .severity-critical {{ background: var(--critical); color: white; }}
        .severity-high {{ background: var(--high); color: black; }}
        .severity-medium {{ background: var(--medium); color: black; }}
        .severity-low {{ background: var(--low); color: black; }}
        
        .alert-content {{ flex: 1; }}
        .alert-title {{ font-weight: 500; margin-bottom: 0.25rem; }}
        .alert-meta {{ font-size: 0.8rem; color: var(--text-muted); }}
        
        /* Footer */
        footer {{
            text-align: center;
            padding: 3rem 0;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}
        
        footer a {{ color: var(--accent); text-decoration: none; }}
        
        /* Scrollbar */
        ::-webkit-scrollbar {{ width: 8px; }}
        ::-webkit-scrollbar-track {{ background: var(--surface); }}
        ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: var(--border-glow); }}
    </style>
</head>
<body>
    <div class="bg-pattern"></div>
    
    <div class="container">
        <header>
            <div class="logo">🛡️</div>
            <h1>ASC</h1>
            <p class="tagline">Web Application Security Control — Real-time vulnerability intelligence powered by semantic web technologies</p>
        </header>
        
        <div class="stats-bar" id="stats">
            <div class="stat">
                <div class="stat-value" id="exploit-count">-</div>
                <div class="stat-label">Exploits</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="topic-count">-</div>
                <div class="stat-label">Topics</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="triple-count">-</div>
                <div class="stat-label">RDF Triples</div>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <div class="card-icon">📊</div>
                <h2>Exploit Database</h2>
                <p>Browse and search web application vulnerabilities from Exploit-DB and other sources. Filter by platform, software type, and severity.</p>
                <div class="card-links">
                    <a href="/api/exploits?format=html">Browse HTML</a>
                    <a href="/api/exploits?format=jsonld">JSON-LD</a>
                    <a href="/api/docs#/exploits">API Docs</a>
                </div>
            </div>
            
            <div class="card">
                <div class="card-icon">🔮</div>
                <h2>SPARQL Endpoint</h2>
                <p>Query the security knowledge graph using SPARQL. Access semantic data about vulnerabilities, solutions, and affected software.</p>
                <div class="card-links">
                    <a href="/sparql">Query Interface</a>
                    <a href="/sparql/examples">Examples</a>
                    <a href="/sparql/ontology">Ontology</a>
                </div>
            </div>
            
            <div class="card">
                <div class="card-icon">📡</div>
                <h2>WebSub Hub</h2>
                <p>Subscribe to real-time security alerts using the W3C WebSub protocol. Push notifications for new vulnerabilities.</p>
                <div class="card-links">
                    <a href="/websub">Hub Info</a>
                    <a href="/websub/topics">Topics</a>
                    <a href="/api/docs#/websub">API Docs</a>
                </div>
            </div>
            
            <div class="card">
                <div class="card-icon">⚡</div>
                <h2>Real-time Alerts</h2>
                <p>Connect via WebSocket for instant vulnerability notifications. Subscribe to specific categories or severity levels.</p>
                <div class="card-links">
                    <a href="#" onclick="connectWebSocket()">Connect</a>
                    <a href="/api/subscriptions/topics/list">Topics</a>
                </div>
            </div>
            
            <div class="card">
                <div class="card-icon">📄</div>
                <h2>Linked Data</h2>
                <p>Export vulnerability data in semantic web formats. Supports JSON-LD with schema.org, RDF/Turtle, and HTML+RDFa.</p>
                <div class="card-links">
                    <a href="/api/exploits?format=jsonld">JSON-LD</a>
                    <a href="/api/exploits/1?format=turtle">Turtle</a>
                    <a href="/api/exploits/1?format=html">RDFa</a>
                </div>
            </div>
            
            <div class="card">
                <div class="card-icon">📚</div>
                <h2>API Documentation</h2>
                <p>Complete REST API documentation with interactive examples. Test endpoints directly from your browser.</p>
                <div class="card-links">
                    <a href="/api/docs">Swagger UI</a>
                    <a href="/api/redoc">ReDoc</a>
                    <a href="/api/stats">Statistics</a>
                </div>
            </div>
        </div>
        
        <div class="alerts-section">
            <div class="section-header">
                <h2><span class="live-dot"></span> Live Security Alerts</h2>
                <span id="connection-status" style="color: var(--text-muted); font-size: 0.85rem;">Connecting...</span>
            </div>
            <div class="alerts-list" id="alerts-list">
                <div class="alert-item" style="justify-content: center; color: var(--text-muted);">
                    Waiting for alerts...
                </div>
            </div>
        </div>
        
        <footer>
            <p>ASC v{settings.app_version} • Built with FastAPI, RDFLib, and WebSub</p>
            <p style="margin-top: 0.5rem;">
                <a href="https://www.exploit-db.com" target="_blank">Exploit-DB</a> • 
                <a href="https://www.w3.org/TR/websub/" target="_blank">W3C WebSub</a> • 
                <a href="https://schema.org" target="_blank">Schema.org</a>
            </p>
        </footer>
    </div>
    
    <script>
        // Fetch and display stats
        async function loadStats() {{
            try {{
                const res = await fetch('/api/stats');
                const data = await res.json();
                
                document.getElementById('exploit-count').textContent = data.rdf_graph?.total_exploits || 0;
                document.getElementById('topic-count').textContent = Object.keys(data.pubsub?.topics || {{}}).length;
                document.getElementById('triple-count').textContent = data.rdf_graph?.total_triples || 0;
            }} catch (e) {{
                console.error('Failed to load stats:', e);
            }}
        }}
        
        // WebSocket connection for live alerts
        let ws = null;
        
        function connectWebSocket() {{
            const statusEl = document.getElementById('connection-status');
            const alertsList = document.getElementById('alerts-list');
            
            if (ws) {{
                ws.close();
            }}
            
            const wsUrl = `${{window.location.protocol === 'https:' ? 'wss:' : 'ws:'}}//` +
                         `${{window.location.host}}/api/subscriptions/ws?topics=alerts.all`;
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = () => {{
                statusEl.textContent = 'Connected';
                statusEl.style.color = 'var(--green)';
            }};
            
            ws.onclose = () => {{
                statusEl.textContent = 'Disconnected';
                statusEl.style.color = 'var(--text-muted)';
                // Reconnect after 5 seconds
                setTimeout(connectWebSocket, 5000);
            }};
            
            ws.onerror = () => {{
                statusEl.textContent = 'Connection error';
                statusEl.style.color = 'var(--critical)';
            }};
            
            ws.onmessage = (event) => {{
                const data = JSON.parse(event.data);
                
                if (data.type === 'heartbeat') return;
                if (data.type === 'connected') {{
                    alertsList.innerHTML = '<div class="alert-item" style="justify-content: center; color: var(--text-muted);">Listening for alerts...</div>';
                    return;
                }}
                
                // Add new alert to list
                const payload = data.payload || data;
                const severity = payload.severity || 'unknown';
                
                const alertHtml = `
                    <div class="alert-item">
                        <span class="alert-severity severity-${{severity}}">${{severity}}</span>
                        <div class="alert-content">
                            <div class="alert-title">${{payload.title || 'New Alert'}}</div>
                            <div class="alert-meta">
                                ${{payload.platform || ''}} • ${{payload.exploit_type || ''}} • ${{payload.software_type || ''}}
                            </div>
                        </div>
                    </div>
                `;
                
                // Remove placeholder if exists
                if (alertsList.querySelector('.alert-item[style]')) {{
                    alertsList.innerHTML = '';
                }}
                
                alertsList.insertAdjacentHTML('afterbegin', alertHtml);
                
                // Keep only last 20 alerts
                while (alertsList.children.length > 20) {{
                    alertsList.removeChild(alertsList.lastChild);
                }}
            }};
        }}
        
        // Initialize
        loadStats();
        connectWebSocket();
        
        // Refresh stats periodically
        setInterval(loadStats, 30000);
    </script>
</body>
</html>'''


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "asc.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
