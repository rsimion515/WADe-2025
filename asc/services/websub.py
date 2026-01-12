"""
WebSub (W3C Specification) implementation.

WebSub provides a common mechanism for communication between publishers
and subscribers of web content. It enables real-time push notifications
for web application security alerts.

W3C WebSub Specification: https://www.w3.org/TR/websub/
"""

import asyncio
import hashlib
import hmac
import secrets
import logging
import httpx
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlencode, parse_qs

from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class WebSubSubscription:
    """Represents a WebSub subscription."""
    callback_url: str
    topic: str
    secret: Optional[str] = None
    lease_seconds: int = 86400
    created_at: datetime = field(default_factory=datetime.now)
    verified: bool = False
    verification_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    
    @property
    def expires_at(self) -> datetime:
        """Get subscription expiration time."""
        return self.created_at + timedelta(seconds=self.lease_seconds)
    
    @property
    def is_expired(self) -> bool:
        """Check if subscription is expired."""
        return datetime.now() > self.expires_at
    
    def generate_signature(self, content: bytes) -> str:
        """Generate HMAC signature for content."""
        if not self.secret:
            return ""
        signature = hmac.new(
            self.secret.encode(),
            content,
            hashlib.sha256
        ).hexdigest()
        return f"sha256={signature}"


class WebSubHub:
    """
    WebSub Hub implementation for managing subscriptions and
    distributing content updates.
    
    Implements W3C WebSub specification for:
    - Subscription management
    - Subscription verification
    - Content distribution
    """
    
    def __init__(self):
        """Initialize the WebSub hub."""
        self._subscriptions: Dict[str, Dict[str, WebSubSubscription]] = {}
        self._topics: Dict[str, Dict] = {}
        self._lock = asyncio.Lock()
        self._http_client: Optional[httpx.AsyncClient] = None
    
    async def start(self):
        """Start the WebSub hub."""
        self._http_client = httpx.AsyncClient(timeout=30.0)
        logger.info("WebSub hub started")
    
    async def stop(self):
        """Stop the WebSub hub."""
        if self._http_client:
            await self._http_client.aclose()
        logger.info("WebSub hub stopped")
    
    def register_topic(self, topic: str, metadata: Optional[Dict] = None) -> None:
        """
        Register a topic for subscription.
        
        Args:
            topic: Topic URL/identifier
            metadata: Optional topic metadata
        """
        self._topics[topic] = {
            "created_at": datetime.now().isoformat(),
            "metadata": metadata or {},
            "subscriber_count": 0,
        }
        logger.info(f"Registered WebSub topic: {topic}")
    
    async def handle_subscription_request(
        self,
        hub_mode: str,
        hub_callback: str,
        hub_topic: str,
        hub_secret: Optional[str] = None,
        hub_lease_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Handle a subscription or unsubscription request.
        
        Args:
            hub_mode: "subscribe" or "unsubscribe"
            hub_callback: Subscriber's callback URL
            hub_topic: Topic to subscribe to
            hub_secret: Optional secret for HMAC signatures
            hub_lease_seconds: Optional lease duration
            
        Returns:
            Response dict with status and details
        """
        # Validate mode
        if hub_mode not in ["subscribe", "unsubscribe"]:
            return {
                "success": False,
                "error": f"Invalid hub.mode: {hub_mode}",
                "status_code": 400,
            }
        
        # Validate topic
        if hub_topic not in self._topics and not hub_topic.startswith("alerts."):
            # Auto-register alerts topics
            if hub_topic.startswith("alerts."):
                self.register_topic(hub_topic)
            else:
                return {
                    "success": False,
                    "error": f"Unknown topic: {hub_topic}",
                    "status_code": 404,
                }
        
        if hub_mode == "subscribe":
            return await self._handle_subscribe(
                hub_callback, hub_topic, hub_secret, hub_lease_seconds
            )
        else:
            return await self._handle_unsubscribe(hub_callback, hub_topic)
    
    async def _handle_subscribe(
        self,
        callback: str,
        topic: str,
        secret: Optional[str],
        lease_seconds: Optional[int],
    ) -> Dict[str, Any]:
        """Handle subscription request."""
        lease = lease_seconds or settings.websub_lease_seconds
        
        subscription = WebSubSubscription(
            callback_url=callback,
            topic=topic,
            secret=secret,
            lease_seconds=lease,
        )
        
        # Verify subscription asynchronously
        asyncio.create_task(self._verify_subscription(subscription, "subscribe"))
        
        return {
            "success": True,
            "message": "Subscription request accepted, verification pending",
            "status_code": 202,
        }
    
    async def _handle_unsubscribe(
        self,
        callback: str,
        topic: str,
    ) -> Dict[str, Any]:
        """Handle unsubscription request."""
        async with self._lock:
            topic_subs = self._subscriptions.get(topic, {})
            subscription = topic_subs.get(callback)
            
            if not subscription:
                return {
                    "success": False,
                    "error": "Subscription not found",
                    "status_code": 404,
                }
        
        # Verify unsubscription
        asyncio.create_task(self._verify_subscription(subscription, "unsubscribe"))
        
        return {
            "success": True,
            "message": "Unsubscription request accepted, verification pending",
            "status_code": 202,
        }
    
    async def _verify_subscription(
        self,
        subscription: WebSubSubscription,
        mode: str,
    ) -> bool:
        """
        Verify subscription with the subscriber.
        
        Sends a GET request to the callback URL with challenge.
        """
        challenge = secrets.token_urlsafe(32)
        
        params = {
            "hub.mode": mode,
            "hub.topic": subscription.topic,
            "hub.challenge": challenge,
            "hub.lease_seconds": str(subscription.lease_seconds),
        }
        
        try:
            url = f"{subscription.callback_url}?{urlencode(params)}"
            response = await self._http_client.get(url, timeout=10.0)
            
            if response.status_code == 200 and response.text.strip() == challenge:
                subscription.verified = True
                
                async with self._lock:
                    if mode == "subscribe":
                        if subscription.topic not in self._subscriptions:
                            self._subscriptions[subscription.topic] = {}
                        self._subscriptions[subscription.topic][subscription.callback_url] = subscription
                        
                        if subscription.topic in self._topics:
                            self._topics[subscription.topic]["subscriber_count"] = len(
                                self._subscriptions[subscription.topic]
                            )
                        
                        logger.info(f"Verified subscription: {subscription.callback_url} -> {subscription.topic}")
                    else:
                        if subscription.topic in self._subscriptions:
                            self._subscriptions[subscription.topic].pop(subscription.callback_url, None)
                        logger.info(f"Verified unsubscription: {subscription.callback_url} -> {subscription.topic}")
                
                return True
            else:
                logger.warning(f"Subscription verification failed for {subscription.callback_url}")
                return False
                
        except Exception as e:
            logger.error(f"Error verifying subscription: {e}")
            return False
    
    async def publish(self, topic: str, content: Dict[str, Any]) -> int:
        """
        Publish content to all subscribers of a topic.
        
        Args:
            topic: Topic to publish to
            content: Content to distribute
            
        Returns:
            Number of successful deliveries
        """
        topic_subs = self._subscriptions.get(topic, {})
        successful = 0
        
        content_bytes = str(content).encode() if isinstance(content, dict) else content
        if isinstance(content, dict):
            import json
            content_bytes = json.dumps(content).encode()
        
        for subscription in list(topic_subs.values()):
            if subscription.is_expired:
                async with self._lock:
                    topic_subs.pop(subscription.callback_url, None)
                continue
            
            if await self._deliver_content(subscription, content_bytes):
                successful += 1
        
        logger.info(f"Published to {successful}/{len(topic_subs)} subscribers of {topic}")
        return successful
    
    async def _deliver_content(
        self,
        subscription: WebSubSubscription,
        content: bytes,
    ) -> bool:
        """Deliver content to a subscriber."""
        headers = {
            "Content-Type": "application/json",
            "Link": f'<{settings.websub_hub_url}>; rel="hub", <{subscription.topic}>; rel="self"',
        }
        
        # Add HMAC signature if secret is configured
        if subscription.secret:
            signature = subscription.generate_signature(content)
            headers["X-Hub-Signature-256"] = signature
        
        try:
            response = await self._http_client.post(
                subscription.callback_url,
                content=content,
                headers=headers,
                timeout=10.0,
            )
            
            return response.status_code in [200, 201, 202, 204]
            
        except Exception as e:
            logger.error(f"Error delivering to {subscription.callback_url}: {e}")
            return False
    
    def get_topic_info(self, topic: str) -> Optional[Dict]:
        """Get information about a topic."""
        if topic in self._topics:
            info = self._topics[topic].copy()
            info["subscriber_count"] = len(self._subscriptions.get(topic, {}))
            return info
        return None
    
    def get_all_topics(self) -> Dict[str, Dict]:
        """Get all registered topics."""
        return {
            topic: self.get_topic_info(topic)
            for topic in self._topics
        }


# Global WebSub hub instance
_websub_hub: Optional[WebSubHub] = None


def get_websub_hub() -> WebSubHub:
    """Get the global WebSub hub instance."""
    global _websub_hub
    if _websub_hub is None:
        _websub_hub = WebSubHub()
        # Register default topics
        for topic in [
            "alerts.all",
            "alerts.critical",
            "alerts.high",
            "alerts.cms",
            "alerts.framework",
            "alerts.plugin",
            "alerts.shopping_cart",
        ]:
            _websub_hub.register_topic(topic)
    return _websub_hub

async def publish_exploit_alert(exploit_data: Dict) -> None:
    """
    Publish an exploit alert to relevant topics.
    
    Args:
        exploit_data: Exploit information dictionary
    """
    pubsub = get_websub_hub()
    
    # Prepare alert payload
    payload = {
        "type": "new_exploit",
        "exploit_id": exploit_data.get("id") or exploit_data.get("exploit_db_id"),
        "title": exploit_data.get("title"),
        "severity": exploit_data.get("severity", "unknown"),
        "software_type": exploit_data.get("software_type"),
        "exploit_type": exploit_data.get("exploit_type"),
        "platform": exploit_data.get("platform"),
        "cve_id": exploit_data.get("cve_id"),
        "source_url": exploit_data.get("source_url"),
        "timestamp": datetime.now().isoformat(),
    }
    
    # Publish to general topic
    await pubsub.publish("alerts.all", payload)
    
    # Publish to severity-specific topic
    severity = exploit_data.get("severity", "").lower()
    if severity in ["critical", "high"]:
        await pubsub.publish(f"alerts.{severity}", payload)
    
    # Publish to software type topic
    software_type = exploit_data.get("software_type", "").lower()
    if software_type and software_type in ["cms", "framework", "plugin", "shopping_cart", "forum"]:
        await pubsub.publish(f"alerts.{software_type}", payload)
    
    # Publish to exploit type topic
    exploit_type = exploit_data.get("exploit_type", "").lower()
    if exploit_type in ["sqli", "xss", "rce"]:
        await pubsub.publish(f"alerts.{exploit_type}", payload)
