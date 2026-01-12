"""
Subscription models for pub/sub system.
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.sql import func
from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime
from typing import Optional, List

from .database import Base


class Subscription(Base):
    """Database model for subscriptions."""
    
    __tablename__ = "subscriptions"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Subscriber information
    callback_url = Column(String(500), nullable=False)
    topic = Column(String(200), nullable=False, index=True)
    
    # WebSub fields
    hub_mode = Column(String(50), default="subscribe")
    hub_secret = Column(String(200))
    lease_seconds = Column(Integer, default=86400)
    
    # Filters
    platform_filter = Column(String(200))  # Comma-separated platforms
    software_type_filter = Column(String(200))  # Comma-separated types
    severity_filter = Column(String(100))  # Minimum severity level
    
    # Status
    is_active = Column(Boolean, default=True)
    verified = Column(Boolean, default=False)
    verification_token = Column(String(100))
    
    # Metadata
    created_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime)
    last_notification = Column(DateTime)


# Pydantic models
class SubscriptionBase(BaseModel):
    """Base subscription schema."""
    callback_url: str
    topic: str
    platform_filter: Optional[str] = None
    software_type_filter: Optional[str] = None
    severity_filter: Optional[str] = None


class SubscriptionCreate(SubscriptionBase):
    """Schema for creating subscriptions."""
    hub_secret: Optional[str] = None
    lease_seconds: Optional[int] = 86400


class SubscriptionResponse(SubscriptionBase):
    """Schema for subscription responses."""
    id: int
    is_active: bool
    verified: bool
    created_at: datetime
    expires_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class WebSubRequest(BaseModel):
    """WebSub subscription request."""
    hub_callback: str = Field(..., alias="hub.callback")
    hub_mode: str = Field(..., alias="hub.mode")
    hub_topic: str = Field(..., alias="hub.topic")
    hub_secret: Optional[str] = Field(None, alias="hub.secret")
    hub_lease_seconds: Optional[int] = Field(None, alias="hub.lease_seconds")
    
    class Config:
        populate_by_name = True
