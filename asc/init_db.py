"""
Database initialization script.

Run this script to initialize the database and load initial data.
"""

import asyncio
import logging
from .models.database import init_db, async_session_maker
from .models.category import SoftwareCategory, PREDEFINED_CATEGORIES
from .services.exploit_scraper import load_sample_exploits

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def main():
    """Initialize the database with default data."""
    logger.info("Initializing ASC database...")
    
    # Create tables
    await init_db()
    logger.info("Database tables created")
    
    async with async_session_maker() as db:
        # Load categories
        from sqlalchemy import select
        
        for cat_data in PREDEFINED_CATEGORIES:
            existing = await db.execute(
                select(SoftwareCategory).where(SoftwareCategory.slug == cat_data["slug"])
            )
            if not existing.scalar_one_or_none():
                db.add(SoftwareCategory(**cat_data))
                logger.info(f"Added category: {cat_data['name']}")
        
        await db.commit()
        
        # Load sample exploits
        exploits = await load_sample_exploits(db)
        logger.info(f"Loaded {len(exploits)} sample exploits")
    
    logger.info("Database initialization complete!")


if __name__ == "__main__":
    asyncio.run(main())
