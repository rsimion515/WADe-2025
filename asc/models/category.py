"""
Software category models.
"""

from sqlalchemy import Column, Integer, String, Text
from pydantic import BaseModel
from typing import Optional, List

from .database import Base


class SoftwareCategory(Base):
    """Database model for software categories."""
    
    __tablename__ = "software_categories"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    parent_id = Column(Integer, nullable=True)
    
    # Example software in this category
    examples = Column(Text)  # JSON array


# Predefined categories
PREDEFINED_CATEGORIES = [
    {
        "name": "Content Management Systems",
        "slug": "cms",
        "description": "Web-based platforms for creating and managing digital content",
        "examples": '["WordPress", "Drupal", "Joomla", "Magento", "PrestaShop"]'
    },
    {
        "name": "Web Frameworks",
        "slug": "framework",
        "description": "Software frameworks for building web applications",
        "examples": '["Laravel", "Django", "Ruby on Rails", "Spring", "Express.js"]'
    },
    {
        "name": "Modules & Plugins",
        "slug": "module",
        "description": "Extensions and add-ons for web platforms",
        "examples": '["WordPress Plugins", "Drupal Modules", "Joomla Extensions"]'
    },
    {
        "name": "Shopping Carts",
        "slug": "shopping_cart",
        "description": "E-commerce shopping cart software",
        "examples": '["WooCommerce", "OpenCart", "Zen Cart", "osCommerce"]'
    },
    {
        "name": "Forums",
        "slug": "forum",
        "description": "Online discussion board software",
        "examples": '["phpBB", "vBulletin", "MyBB", "Discourse"]'
    },
    {
        "name": "Wikis",
        "slug": "wiki",
        "description": "Collaborative documentation platforms",
        "examples": '["MediaWiki", "DokuWiki", "TikiWiki"]'
    },
    {
        "name": "Blogs",
        "slug": "blog",
        "description": "Blogging platforms and software",
        "examples": '["WordPress", "Ghost", "Jekyll"]'
    },
    {
        "name": "E-Commerce Platforms",
        "slug": "e_commerce",
        "description": "Full e-commerce solutions",
        "examples": '["Magento", "Shopify", "BigCommerce", "PrestaShop"]'
    },
]


# Pydantic models
class CategoryResponse(BaseModel):
    """Schema for category response."""
    id: int
    name: str
    slug: str
    description: Optional[str] = None
    examples: Optional[str] = None
    
    class Config:
        from_attributes = True
