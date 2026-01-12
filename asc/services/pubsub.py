"""
DDS (Data Distribution Service) Publish/Subscribe system.

Implements a publish/subscribe pattern for real-time security alerts
with support for topic-based filtering.
"""

import asyncio
import json
import logging
import hashlib
import hmac
from datetime import datetime
from typing import Dict, List, Set, Callable, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
from weakref import WeakSet

logger = logging.getLogger(__name__)


@dataclass
class Message:
    """Represents a pub/sub message."""
    topic: str
    payload: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    message_id: str = field(default="")
    
    def __post_init__(self):
        if not self.message_id:
            content = f"{self.topic}:{json.dumps(self.payload)}:{self.timestamp.isoformat()}"
            self.message_id = hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict:
        """Convert message to dictionary."""
        return {
            "message_id": self.message_id,
            "topic": self.topic,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Subscriber:
    """Represents a subscriber."""
    subscriber_id: str
    callback: Callable
    topics: Set[str] = field(default_factory=set)
    filters: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)


class PubSubService:
    """
    In-memory DDS Publish/Subscribe service.
    
    Features:
    - Topic-based message routing
    - Pattern matching for topic subscriptions
    - Message filtering based on payload attributes
    - Async message delivery
    - Message history/replay
    """
    
    # Predefined topics for security alerts
    TOPICS = {
        "alerts.all": "All security alerts",
        "alerts.critical": "Critical severity alerts",
        "alerts.high": "High severity alerts",
        "alerts.cms": "CMS vulnerabilities",
        "alerts.framework": "Framework vulnerabilities",
        "alerts.plugin": "Plugin/Module vulnerabilities",
        "alerts.shopping_cart": "Shopping cart vulnerabilities",
        "alerts.forum": "Forum software vulnerabilities",
        "alerts.sqli": "SQL Injection vulnerabilities",
        "alerts.xss": "Cross-Site Scripting vulnerabilities",
        "alerts.rce": "Remote Code Execution vulnerabilities",
    }
    
    def __init__(self, max_history: int = 1000):
        """
        Initialize the pub/sub service.
        
        Args:
            max_history: Maximum number of messages to keep in history
        """
        self._subscribers: Dict[str, Subscriber] = {}
        self._topic_subscribers: Dict[str, Set[str]] = defaultdict(set)
        self._message_history: List[Message] = []
        self._max_history = max_history
        self._lock = asyncio.Lock()
        self._websocket_connections: Dict[str, Set] = defaultdict(WeakSet)
    
    async def subscribe(
        self,
        subscriber_id: str,
        topics: List[str],
        callback: Callable,
        filters: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Subscribe to topics.
        
        Args:
            subscriber_id: Unique identifier for the subscriber
            topics: List of topics to subscribe to
            callback: Async callback function to receive messages
            filters: Optional filters for message payload
            
        Returns:
            True if subscription successful
        """
        async with self._lock:
            subscriber = Subscriber(
                subscriber_id=subscriber_id,
                callback=callback,
                topics=set(topics),
                filters=filters or {},
            )
            
            self._subscribers[subscriber_id] = subscriber
            
            for topic in topics:
                self._topic_subscribers[topic].add(subscriber_id)
                # Also subscribe to pattern-matched topics
                if topic.endswith(".*"):
                    base_topic = topic[:-2]
                    for existing_topic in self.TOPICS.keys():
                        if existing_topic.startswith(base_topic):
                            self._topic_subscribers[existing_topic].add(subscriber_id)
            
            logger.info(f"Subscriber {subscriber_id} subscribed to topics: {topics}")
            return True
    
    async def unsubscribe(self, subscriber_id: str, topics: Optional[List[str]] = None) -> bool:
        """
        Unsubscribe from topics.
        
        Args:
            subscriber_id: Subscriber identifier
            topics: Optional list of topics (unsubscribes from all if None)
            
        Returns:
            True if unsubscription successful
        """
        async with self._lock:
            if subscriber_id not in self._subscribers:
                return False
            
            subscriber = self._subscribers[subscriber_id]
            
            if topics is None:
                topics = list(subscriber.topics)
            
            for topic in topics:
                subscriber.topics.discard(topic)
                self._topic_subscribers[topic].discard(subscriber_id)
            
            if not subscriber.topics:
                del self._subscribers[subscriber_id]
            
            logger.info(f"Subscriber {subscriber_id} unsubscribed from topics: {topics}")
            return True
    
    async def publish(self, topic: str, payload: Dict[str, Any]) -> Message:
        """
        Publish a message to a topic.
        
        Args:
            topic: Topic to publish to
            payload: Message payload
            
        Returns:
            Published message object
        """
        message = Message(topic=topic, payload=payload)
        
        async with self._lock:
            # Store in history
            self._message_history.append(message)
            if len(self._message_history) > self._max_history:
                self._message_history.pop(0)
        
        # Deliver to subscribers
        await self._deliver_message(message)
        
        logger.debug(f"Published message {message.message_id} to topic: {topic}")
        return message
    
    async def _deliver_message(self, message: Message) -> None:
        """Deliver message to all matching subscribers."""
        subscriber_ids = self._topic_subscribers.get(message.topic, set()).copy()
        
        # Also check for wildcard subscribers
        parts = message.topic.split(".")
        for i in range(len(parts)):
            pattern = ".".join(parts[:i+1]) + ".*"
            subscriber_ids.update(self._topic_subscribers.get(pattern, set()))
        
        # Also deliver to "alerts.all" subscribers
        if message.topic.startswith("alerts."):
            subscriber_ids.update(self._topic_subscribers.get("alerts.all", set()))
        
        for subscriber_id in subscriber_ids:
            subscriber = self._subscribers.get(subscriber_id)
            if subscriber and self._matches_filters(message.payload, subscriber.filters):
                try:
                    if asyncio.iscoroutinefunction(subscriber.callback):
                        await subscriber.callback(message)
                    else:
                        subscriber.callback(message)
                except Exception as e:
                    logger.error(f"Error delivering message to {subscriber_id}: {e}")
    
    def _matches_filters(self, payload: Dict, filters: Dict) -> bool:
        """Check if payload matches subscriber filters."""
        for key, value in filters.items():
            if key not in payload:
                return False
            
            if isinstance(value, list):
                if payload[key] not in value:
                    return False
            elif payload[key] != value:
                return False
        
        return True
    
    async def get_history(
        self,
        topic: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Message]:
        """
        Get message history.
        
        Args:
            topic: Optional topic filter
            since: Optional datetime filter
            limit: Maximum number of messages to return
            
        Returns:
            List of messages
        """
        messages = self._message_history.copy()
        
        if topic:
            messages = [m for m in messages if m.topic == topic or topic == "alerts.all"]
        
        if since:
            messages = [m for m in messages if m.timestamp >= since]
        
        return messages[-limit:]
    
    def get_topics(self) -> Dict[str, str]:
        """Get all available topics."""
        return self.TOPICS.copy()
    
    def get_subscriber_count(self, topic: str) -> int:
        """Get number of subscribers for a topic."""
        return len(self._topic_subscribers.get(topic, set()))


# Global pub/sub instance
_pubsub_service: Optional[PubSubService] = None


def get_pubsub_service() -> PubSubService:
    """Get the global pub/sub service instance."""
    global _pubsub_service
    if _pubsub_service is None:
        _pubsub_service = PubSubService()
    return _pubsub_service


async def publish_exploit_alert(exploit_data: Dict) -> None:
    """
    Publish an exploit alert to relevant topics.
    
    Args:
        exploit_data: Exploit information dictionary
    """
    pubsub = get_pubsub_service()
    
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
