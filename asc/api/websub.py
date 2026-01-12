"""
WebSub (W3C) Hub API routes.

Implements WebSub hub endpoints for publish/subscribe functionality
following the W3C WebSub specification.
"""

from typing import Optional
from fastapi import APIRouter, Request, Response, Form, HTTPException
from fastapi.responses import HTMLResponse

from ..services.websub import get_websub_hub, WebSubSubscription
from ..config import get_settings

router = APIRouter(prefix="/websub", tags=["websub"])
settings = get_settings()


@router.get("")
async def websub_info():
    """Get WebSub hub information and documentation."""
    hub = get_websub_hub()
    topics = hub.get_all_topics()
    
    return HTMLResponse(content=generate_websub_docs(topics))


@router.post("/hub")
async def websub_hub(
    request: Request,
    hub_callback: str = Form(None, alias="hub.callback"),
    hub_mode: str = Form(None, alias="hub.mode"),
    hub_topic: str = Form(None, alias="hub.topic"),
    hub_secret: Optional[str] = Form(None, alias="hub.secret"),
    hub_lease_seconds: Optional[int] = Form(None, alias="hub.lease_seconds"),
):
    """
    WebSub hub endpoint for subscription management.
    
    Supports:
    - hub.mode=subscribe: Subscribe to a topic
    - hub.mode=unsubscribe: Unsubscribe from a topic
    
    The hub will verify subscriptions by sending a GET request
    to the callback URL with a challenge parameter.
    """
    # Validate required parameters
    if not hub_callback:
        raise HTTPException(status_code=400, detail="Missing hub.callback parameter")
    if not hub_mode:
        raise HTTPException(status_code=400, detail="Missing hub.mode parameter")
    if not hub_topic:
        raise HTTPException(status_code=400, detail="Missing hub.topic parameter")
    
    hub = get_websub_hub()
    
    result = await hub.handle_subscription_request(
        hub_mode=hub_mode,
        hub_callback=hub_callback,
        hub_topic=hub_topic,
        hub_secret=hub_secret,
        hub_lease_seconds=hub_lease_seconds,
    )
    
    if not result["success"]:
        raise HTTPException(
            status_code=result.get("status_code", 400),
            detail=result.get("error", "Request failed")
        )
    
    return Response(status_code=202)


@router.get("/topic/{topic}")
async def get_topic_info(topic: str):
    """
    Get information about a WebSub topic.
    
    Returns topic metadata and subscriber count.
    """
    hub = get_websub_hub()
    
    # Handle topic path conversion (e.g., alerts/cms -> alerts.cms)
    topic = topic.replace("/", ".")
    
    info = hub.get_topic_info(topic)
    
    if not info:
        raise HTTPException(status_code=404, detail=f"Topic not found: {topic}")
    
    return {
        "topic": topic,
        "hub_url": settings.websub_hub_url,
        **info,
    }


@router.get("/topics")
async def list_topics():
    """List all available WebSub topics."""
    hub = get_websub_hub()
    return {
        "hub_url": settings.websub_hub_url,
        "topics": hub.get_all_topics(),
    }


@router.get("/discover/{path:path}")
async def topic_discovery(path: str, request: Request):
    """
    Topic discovery endpoint with Link headers.
    
    Returns HTML with WebSub discovery links.
    """
    topic = path.replace("/", ".")
    base_url = str(request.base_url).rstrip("/")
    topic_url = f"{base_url}/websub/topic/{topic}"
    
    headers = {
        "Link": f'<{settings.websub_hub_url}>; rel="hub", <{topic_url}>; rel="self"'
    }
    
    return Response(
        content=f'''<!DOCTYPE html>
<html>
<head>
    <link rel="hub" href="{settings.websub_hub_url}">
    <link rel="self" href="{topic_url}">
    <title>Topic: {topic}</title>
</head>
<body>
    <h1>WebSub Topic: {topic}</h1>
    <p>Hub URL: {settings.websub_hub_url}</p>
    <p>Self URL: {topic_url}</p>
</body>
</html>''',
        media_type="text/html",
        headers=headers,
    )


def generate_websub_docs(topics: dict) -> str:
    """Generate WebSub documentation HTML."""
    topics_html = ""
    for topic, info in topics.items():
        sub_count = info.get("subscriber_count", 0) if info else 0
        topics_html += f'''
        <div class="topic">
            <h3>{topic}</h3>
            <p class="meta">{sub_count} subscriber{"s" if sub_count != 1 else ""}</p>
            <code>POST /websub/hub
hub.mode=subscribe
hub.topic={topic}
hub.callback=YOUR_CALLBACK_URL</code>
        </div>
        '''
    
    return f'''<!DOCTYPE html>
<html>
<head>
    <title>WebSub Hub - ASC</title>
    <style>
        :root {{
            --bg: #0a0a10;
            --surface: #12121c;
            --surface-2: #1a1a28;
            --border: #252538;
            --text: #e8e8f0;
            --muted: #8080a0;
            --accent: #22c55e;
            --accent-2: #3b82f6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}
        .container {{ max-width: 900px; margin: 0 auto; padding: 3rem 2rem; }}
        h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
            color: var(--accent);
        }}
        .subtitle {{ color: var(--muted); margin-bottom: 3rem; }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
        }}
        .section h2 {{
            color: var(--accent-2);
            font-size: 1.1rem;
            margin-bottom: 1.5rem;
        }}
        .topic {{
            background: var(--surface-2);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }}
        .topic h3 {{ font-size: 1rem; margin-bottom: 0.5rem; }}
        .topic .meta {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 1rem; }}
        .topic code {{
            display: block;
            background: var(--bg);
            padding: 1rem;
            border-radius: 6px;
            font-size: 0.8rem;
            white-space: pre;
        }}
        .endpoint {{
            background: var(--surface-2);
            border-radius: 8px;
            padding: 1rem 1.5rem;
            margin-bottom: 1rem;
        }}
        .endpoint .method {{
            display: inline-block;
            background: var(--accent);
            color: black;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-right: 0.5rem;
        }}
        .endpoint .path {{ font-family: monospace; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            font-size: 0.9rem;
        }}
        th, td {{
            text-align: left;
            padding: 0.75rem;
            border-bottom: 1px solid var(--border);
        }}
        th {{ color: var(--muted); font-weight: 500; }}
        code {{ color: var(--accent); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📡 WebSub Hub</h1>
            <p class="subtitle">W3C WebSub compliant hub for real-time security alerts</p>
        </header>
        
        <section class="section">
            <h2>Hub Endpoint</h2>
            <div class="endpoint">
                <span class="method">POST</span>
                <span class="path">{settings.websub_hub_url}</span>
            </div>
            <table>
                <tr><th>Parameter</th><th>Description</th><th>Required</th></tr>
                <tr><td><code>hub.mode</code></td><td>"subscribe" or "unsubscribe"</td><td>Yes</td></tr>
                <tr><td><code>hub.topic</code></td><td>Topic URL to subscribe to</td><td>Yes</td></tr>
                <tr><td><code>hub.callback</code></td><td>Your callback URL</td><td>Yes</td></tr>
                <tr><td><code>hub.secret</code></td><td>Secret for HMAC signature</td><td>No</td></tr>
                <tr><td><code>hub.lease_seconds</code></td><td>Subscription duration</td><td>No</td></tr>
            </table>
        </section>
        
        <section class="section">
            <h2>Available Topics</h2>
            {topics_html}
        </section>
        
        <section class="section">
            <h2>How It Works</h2>
            <ol style="padding-left: 1.5rem; color: var(--muted);">
                <li style="margin-bottom: 0.5rem;">Send a POST request to the hub with your subscription details</li>
                <li style="margin-bottom: 0.5rem;">The hub verifies your subscription by sending a GET request to your callback</li>
                <li style="margin-bottom: 0.5rem;">Respond with the <code>hub.challenge</code> value to confirm</li>
                <li style="margin-bottom: 0.5rem;">Receive POST notifications when new content is published</li>
            </ol>
        </section>
    </div>
</body>
</html>'''
