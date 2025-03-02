import os
import pickle
import hashlib
import functools
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar, cast

# Type variable for the return type of the decorated function
T = TypeVar('T')

class Cache:
    """Cache for AWS Log Parser to avoid unnecessary data pulls"""
    
    def __init__(self, cache_dir: Optional[str] = None, ttl: int = 3600):
        """
        Initialize the cache.
        
        Args:
            cache_dir: Directory to store cache files. Defaults to ~/.aws_log_parser_cache
            ttl: Time to live for cache entries in seconds. Defaults to 1 hour.
        """
        if cache_dir is None:
            self.cache_dir = Path.home() / '.aws_log_parser_cache'
        else:
            self.cache_dir = Path(cache_dir)
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
    
    def _get_cache_key(self, *args: Any, **kwargs: Any) -> str:
        """Generate a unique cache key based on function arguments"""
        # Create a string representation of args and kwargs
        key_parts = [str(arg) for arg in args]
        key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
        key_str = ":".join(key_parts)
        
        # Create a hash of the key string
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def _get_cache_path(self, key: str) -> Path:
        """Get the path to the cache file for the given key"""
        return self.cache_dir / f"{key}.pickle"
    
    def get(self, key: str) -> Tuple[bool, Any]:
        """
        Get a value from the cache.
        
        Args:
            key: Cache key
            
        Returns:
            Tuple of (hit, value) where hit is True if the key was found in the cache
            and value is the cached value (or None if not found)
        """
        cache_path = self._get_cache_path(key)
        
        if not cache_path.exists():
            return False, None
        
        # Check if cache entry has expired
        if time.time() - cache_path.stat().st_mtime > self.ttl:
            return False, None
        
        try:
            with open(cache_path, 'rb') as f:
                return True, pickle.load(f)
        except (pickle.PickleError, EOFError):
            # If there's an error loading the cache, treat it as a miss
            return False, None
    
    def set(self, key: str, value: Any) -> None:
        """
        Set a value in the cache.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        cache_path = self._get_cache_path(key)
        
        with open(cache_path, 'wb') as f:
            pickle.dump(value, f)
    
    def clear(self) -> None:
        """Clear all cache entries"""
        for cache_file in self.cache_dir.glob('*.pickle'):
            cache_file.unlink()
    
    def clear_expired(self) -> None:
        """Clear expired cache entries"""
        for cache_file in self.cache_dir.glob('*.pickle'):
            if time.time() - cache_file.stat().st_mtime > self.ttl:
                cache_file.unlink()


def cached(ttl: int = 3600, cache_dir: Optional[str] = None) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to cache function results.
    
    Args:
        ttl: Time to live for cache entries in seconds. Defaults to 1 hour.
        cache_dir: Directory to store cache files. Defaults to ~/.aws_log_parser_cache
        
    Returns:
        Decorated function that uses caching
    """
    cache = Cache(cache_dir=cache_dir, ttl=ttl)
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            # Check if force_refresh is in kwargs and remove it
            force_refresh = kwargs.pop('force_refresh', False)
            
            # Generate cache key
            cache_key = cache._get_cache_key(func.__name__, *args, **kwargs)
            
            if not force_refresh:
                # Try to get from cache
                hit, value = cache.get(cache_key)
                if hit:
                    if args and hasattr(args[0], 'verbose') and args[0].verbose:
                        print(f"Using cached data for {func.__name__}")
                    return value
            
            # Call the function and cache the result
            result = func(*args, **kwargs)
            
            # For generators, we need to materialize the results
            if hasattr(result, '__iter__') and not isinstance(result, (list, tuple, dict)):
                result = list(result)
            
            cache.set(cache_key, result)
            return result
        
        return wrapper
    
    return decorator 