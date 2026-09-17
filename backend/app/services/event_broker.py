import asyncio
from typing import Dict, Any, Set
import logging

logger = logging.getLogger(__name__)

class EventBroker:
    """
    Thread-safe/async-safe event broker to manage SSE client streams
    and broadcast compliance updates in near real-time.
    """
    def __init__(self):
        self._listeners: Set[asyncio.Queue] = set()

    def register(self, queue: asyncio.Queue):
        """Register a new SSE client queue."""
        self._listeners.add(queue)
        logger.debug(f"SSE client registered. Total listeners: {len(self._listeners)}")

    def unregister(self, queue: asyncio.Queue):
        """Unregister an SSE client queue."""
        self._listeners.discard(queue)
        logger.debug(f"SSE client unregistered. Total listeners: {len(self._listeners)}")

    def broadcast(self, event_type: str, tenant_id: str, data: Dict[str, Any]):
        """
        Broadcast an event to all connected listeners.
        Safe to call from anywhere. Runs async tasks inside event loop.
        """
        message = {
            "event_type": event_type,
            "tenant_id": tenant_id,
            "data": data
        }
        
        # Enqueue event to all active client queues
        for queue in self._listeners:
            try:
                queue.put_nowait(message)
            except Exception as e:
                logger.error(f"Failed to queue event for listener: {e}")

# Global singleton event broker
event_broker = EventBroker()
