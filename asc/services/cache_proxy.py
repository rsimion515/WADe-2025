"""
Smart Caching Proxy Service.

Implements an intelligent caching proxy for efficient data retrieval
with support for cache invalidation, TTL management, and cache warming.
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, Callable, List, TypeVar, Generic
from dataclasses import dataclass, field
from collections import OrderedDict
from functools import wraps

from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

T = TypeVar("T")


@dataclass
class CacheEntry(Generic[T]):
    """Represents a cached item."""
    key: str
    value: T
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    hit_count: int = 0
    last_accessed: datetime = field(default_factory=datetime.now)
    etag: Optional[str] = None
    content_type: Optional[str] = None
    
    @property
    def is_expired(self) -> bool:
        """Check if entry is expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at
    
    @property
    def age(self) -> int:
        """Get age in seconds."""
        return int((datetime.now() - self.created_at).total_seconds())
    
    def touch(self):
        """Update last accessed time and increment hit count."""
        self.last_accessed = datetime.now()
        self.hit_count += 1


class LRUCache(Generic[T]):
    """
    Least Recently Used cache implementation.
    
    Features:
    - TTL-based expiration
    - LRU eviction policy
    - Maximum size limit
    - Hit/miss statistics
    """
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        """
        Initialize LRU cache.
        
        Args:
            max_size: Maximum number of entries
            default_ttl: Default TTL in seconds
        """
        self._cache: OrderedDict[str, CacheEntry[T]] = OrderedDict()
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._hits = 0
        self._misses = 0
        self._lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[T]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None
        """
        async with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None
            
            entry = self._cache[key]
            
            if entry.is_expired:
                del self._cache[key]
                self._misses += 1
                return None
            
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            entry.touch()
            self._hits += 1
            
            return entry.value
    
    async def set(
        self,
        key: str,
        value: T,
        ttl: Optional[int] = None,
        etag: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            etag: ETag for conditional requests
            content_type: Content type of cached data
        """
        async with self._lock:
            # Evict if at capacity
            while len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)
            
            ttl = ttl or self._default_ttl
            expires_at = datetime.now() + timedelta(seconds=ttl) if ttl else None
            
            entry = CacheEntry(
                key=key,
                value=value,
                expires_at=expires_at,
                etag=etag,
                content_type=content_type,
            )
            
            self._cache[key] = entry
    
    async def delete(self, key: str) -> bool:
        """
        Delete entry from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if entry was deleted
        """
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self._cache.clear()
    
    async def get_entry(self, key: str) -> Optional[CacheEntry[T]]:
        """Get full cache entry with metadata."""
        async with self._lock:
            return self._cache.get(key)
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        
        return {
            "size": len(self._cache),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{hit_rate:.2f}%",
        }


class SmartCacheProxy:
    """
    Smart caching proxy with intelligent caching strategies.
    
    Features:
    - Multiple cache tiers (memory, persistent)
    - Cache warming for popular resources
    - Conditional caching with ETags
    - Automatic cache invalidation
    - Request deduplication
    """
    
    def __init__(
        self,
        max_size: int = 1000,
        default_ttl: int = None,
    ):
        """
        Initialize the smart cache proxy.
        
        Args:
            max_size: Maximum cache size
            default_ttl: Default TTL in seconds
        """
        self._ttl = default_ttl or settings.proxy_cache_ttl
        self._cache = LRUCache[Any](max_size=max_size, default_ttl=self._ttl)
        self._pending_requests: Dict[str, asyncio.Future] = {}
        self._popular_keys: Dict[str, int] = {}
        self._lock = asyncio.Lock()
    
    def _generate_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments."""
        key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    async def get(
        self,
        key: str,
        fetcher: Optional[Callable] = None,
        ttl: Optional[int] = None,
    ) -> Optional[Any]:
        """
        Get value from cache or fetch if not present.
        
        Args:
            key: Cache key
            fetcher: Optional async function to fetch data if not cached
            ttl: Optional TTL override
            
        Returns:
            Cached or fetched value
        """
        # Track popularity
        self._popular_keys[key] = self._popular_keys.get(key, 0) + 1
        
        # Try cache first
        cached = await self._cache.get(key)
        if cached is not None:
            return cached
        
        # If no fetcher, return None
        if fetcher is None:
            return None
        
        # Request deduplication
        async with self._lock:
            if key in self._pending_requests:
                return await self._pending_requests[key]
            
            future = asyncio.get_event_loop().create_future()
            self._pending_requests[key] = future
        
        try:
            # Fetch data
            if asyncio.iscoroutinefunction(fetcher):
                value = await fetcher()
            else:
                value = fetcher()
            
            # Cache the result
            await self._cache.set(key, value, ttl=ttl)
            
            # Resolve pending requests
            future.set_result(value)
            
            return value
            
        except Exception as e:
            future.set_exception(e)
            raise
        finally:
            async with self._lock:
                self._pending_requests.pop(key, None)
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        etag: Optional[str] = None,
    ) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: TTL in seconds
            etag: ETag for conditional requests
        """
        await self._cache.set(key, value, ttl=ttl, etag=etag)
    
    async def invalidate(self, key: str) -> bool:
        """
        Invalidate a cache entry.
        
        Args:
            key: Cache key
            
        Returns:
            True if entry was invalidated
        """
        return await self._cache.delete(key)
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """
        Invalidate entries matching a pattern.
        
        Args:
            pattern: Key pattern (prefix match)
            
        Returns:
            Number of entries invalidated
        """
        count = 0
        keys_to_delete = []
        
        async with self._cache._lock:
            for key in self._cache._cache.keys():
                if key.startswith(pattern):
                    keys_to_delete.append(key)
        
        for key in keys_to_delete:
            if await self._cache.delete(key):
                count += 1
        
        return count
    
    async def warm_cache(self, fetchers: Dict[str, Callable]) -> Dict[str, bool]:
        """
        Pre-populate cache with data.
        
        Args:
            fetchers: Dict of key -> fetcher function pairs
            
        Returns:
            Dict of key -> success status
        """
        results = {}
        
        async def warm_single(key: str, fetcher: Callable):
            try:
                value = await fetcher() if asyncio.iscoroutinefunction(fetcher) else fetcher()
                await self.set(key, value)
                results[key] = True
            except Exception as e:
                logger.error(f"Cache warming failed for {key}: {e}")
                results[key] = False
        
        await asyncio.gather(*[
            warm_single(key, fetcher)
            for key, fetcher in fetchers.items()
        ])
        
        return results
    
    async def get_popular_keys(self, limit: int = 10) -> List[tuple]:
        """Get most frequently accessed keys."""
        sorted_keys = sorted(
            self._popular_keys.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_keys[:limit]
    
    async def conditional_get(
        self,
        key: str,
        if_none_match: Optional[str] = None,
    ) -> tuple[Optional[Any], Optional[str], bool]:
        """
        Conditional GET with ETag support.
        
        Args:
            key: Cache key
            if_none_match: Client's ETag for conditional request
            
        Returns:
            Tuple of (value, etag, not_modified)
        """
        entry = await self._cache.get_entry(key)
        
        if entry is None:
            return None, None, False
        
        if entry.is_expired:
            await self._cache.delete(key)
            return None, None, False
        
        # Check ETag
        if if_none_match and entry.etag and if_none_match == entry.etag:
            entry.touch()
            return None, entry.etag, True
        
        entry.touch()
        return entry.value, entry.etag, False
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Get proxy statistics."""
        return {
            **self._cache.stats,
            "pending_requests": len(self._pending_requests),
            "tracked_keys": len(self._popular_keys),
        }
    
    async def clear(self) -> None:
        """Clear all cached data."""
        await self._cache.clear()
        self._popular_keys.clear()


def cached(
    ttl: int = None,
    key_prefix: str = "",
):
    """
    Decorator for caching function results.
    
    Args:
        ttl: Cache TTL in seconds
        key_prefix: Prefix for cache keys
    """
    def decorator(func: Callable):
        cache = SmartCacheProxy()
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            key_data = f"{key_prefix}:{func.__name__}:{args}:{kwargs}"
            key = hashlib.sha256(key_data.encode()).hexdigest()
            
            # Try cache
            cached_value = await cache.get(key)
            if cached_value is not None:
                return cached_value
            
            # Call function
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            # Cache result
            await cache.set(key, result, ttl=ttl)
            
            return result
        
        wrapper.cache = cache
        return wrapper
    
    return decorator


# Global cache proxy instance
_cache_proxy: Optional[SmartCacheProxy] = None


def get_cache_proxy() -> SmartCacheProxy:
    """Get the global cache proxy instance."""
    global _cache_proxy
    if _cache_proxy is None:
        _cache_proxy = SmartCacheProxy(
            max_size=5000,
            default_ttl=settings.cache_ttl,
        )
    return _cache_proxy
