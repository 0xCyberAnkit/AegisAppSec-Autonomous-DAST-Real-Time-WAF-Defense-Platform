import time
from collections import defaultdict
from fastapi import Request, HTTPException, status
from app.core.config import settings

class InMemoryRateLimiter:
    """Sliding-window in-memory rate limiter to protect the platform against flood/DoS attacks."""
    def __init__(self, limit: int = 120, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
    
    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        # Clean timestamps older than window
        timestamps = [t for t in self.requests[client_ip] if now - t < self.window_seconds]
        self.requests[client_ip] = timestamps
        
        if len(timestamps) >= self.limit:
            return False
        
        self.requests[client_ip].append(now)
        return True

rate_limiter = InMemoryRateLimiter(
    limit=settings.RATE_LIMIT_PER_MINUTE,
    window_seconds=60
)

async def check_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Platform self-defense active. Please slow down requests.",
            headers={"Retry-After": "60"}
        )
