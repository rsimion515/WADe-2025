"""
Subscription management API routes.

Provides endpoints for managing pub/sub subscriptions and
real-time WebSocket connections for alerts.
"""

import asyncio
import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..models.database import get_db
from ..models.subscription import Subscription, SubscriptionCreate, SubscriptionResponse
from ..services.pubsub import get_pubsub_service, Message
from ..config import get_settings

router = APIRouter(prefix="/api/subscriptions", tags=["subscriptions"])
settings = get_settings()

# Store active WebSocket connections
active_connections: dict[str, set[WebSocket]] = {}


@router.post("", response_model=SubscriptionResponse)
async def create_subscription(
    subscription: SubscriptionCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new subscription for security alerts.
    
    The callback URL will receive POST requests when new
    vulnerabilities matching the filters are published.
    """
    db_subscription = Subscription(
        callback_url=subscription.callback_url,
        topic=subscription.topic,
        hub_secret=subscription.hub_secret,
        lease_seconds=subscription.lease_seconds,
        platform_filter=subscription.platform_filter,
        software_type_filter=subscription.software_type_filter,
        severity_filter=subscription.severity_filter,
    )
    
    db.add(db_subscription)
    await db.commit()
    await db.refresh(db_subscription)
    
    # Register with pub/sub service
    pubsub = get_pubsub_service()
    
    filters = {}
    if subscription.platform_filter:
        filters["platform"] = subscription.platform_filter.split(",")
    if subscription.software_type_filter:
        filters["software_type"] = subscription.software_type_filter.split(",")
    if subscription.severity_filter:
        filters["severity"] = subscription.severity_filter.split(",")
    
    await pubsub.subscribe(
        subscriber_id=f"sub_{db_subscription.id}",
        topics=[subscription.topic],
        callback=lambda msg: None,  # HTTP callback handled separately
        filters=filters,
    )
    
    return db_subscription


@router.get("", response_model=List[SubscriptionResponse])
async def list_subscriptions(
    topic: Optional[str] = None,
    is_active: bool = True,
    db: AsyncSession = Depends(get_db),
):
    """List all subscriptions."""
    query = select(Subscription).where(Subscription.is_active == is_active)
    
    if topic:
        query = query.where(Subscription.topic == topic)
    
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{subscription_id}", response_model=SubscriptionResponse)
async def get_subscription(
    subscription_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get subscription details."""
    result = await db.execute(
        select(Subscription).where(Subscription.id == subscription_id)
    )
    subscription = result.scalar_one_or_none()
    
    if not subscription:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    return subscription


@router.delete("/{subscription_id}")
async def delete_subscription(
    subscription_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete a subscription."""
    result = await db.execute(
        select(Subscription).where(Subscription.id == subscription_id)
    )
    subscription = result.scalar_one_or_none()
    
    if not subscription:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    # Unsubscribe from pub/sub
    pubsub = get_pubsub_service()
    await pubsub.unsubscribe(f"sub_{subscription_id}")
    
    await db.delete(subscription)
    await db.commit()
    
    return {"message": "Subscription deleted"}


@router.get("/topics/list")
async def list_topics():
    """List all available subscription topics."""
    pubsub = get_pubsub_service()
    return {
        "topics": pubsub.get_topics(),
        "subscriber_counts": {
            topic: pubsub.get_subscriber_count(topic)
            for topic in pubsub.get_topics()
        }
    }


@router.websocket("/ws")
async def websocket_alerts(
    websocket: WebSocket,
    topics: str = Query("alerts.all"),
):
    """
    WebSocket endpoint for real-time security alerts.
    
    Connect to receive instant notifications about new vulnerabilities.
    
    Query parameters:
    - topics: Comma-separated list of topics to subscribe to
    """
    await websocket.accept()
    
    topic_list = [t.strip() for t in topics.split(",")]
    connection_id = f"ws_{id(websocket)}"
    
    # Register WebSocket connection
    for topic in topic_list:
        if topic not in active_connections:
            active_connections[topic] = set()
        active_connections[topic].add(websocket)
    
    # Subscribe to pub/sub
    pubsub = get_pubsub_service()
    
    async def ws_callback(message: Message):
        try:
            await websocket.send_json(message.to_dict())
        except Exception:
            pass
    
    await pubsub.subscribe(
        subscriber_id=connection_id,
        topics=topic_list,
        callback=ws_callback,
    )
    
    try:
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "topics": topic_list,
            "message": "Connected to ASC real-time alerts",
        })
        
        # Keep connection alive
        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                
                # Handle ping/pong
                if data == "ping":
                    await websocket.send_text("pong")
                    
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({"type": "heartbeat"})
                
    except WebSocketDisconnect:
        pass
    finally:
        # Cleanup
        await pubsub.unsubscribe(connection_id)
        for topic in topic_list:
            if topic in active_connections:
                active_connections[topic].discard(websocket)


@router.get("/history/{topic}")
async def get_alert_history(
    topic: str,
    limit: int = Query(50, ge=1, le=200),
):
    """Get recent alert history for a topic."""
    pubsub = get_pubsub_service()
    messages = await pubsub.get_history(topic=topic, limit=limit)
    
    return {
        "topic": topic,
        "count": len(messages),
        "messages": [m.to_dict() for m in messages],
    }
