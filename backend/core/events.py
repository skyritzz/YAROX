from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List
import asyncio

class EventBus(ABC):
    @abstractmethod
    def subscribe(self, topic: str, callback: Callable):
        pass

    @abstractmethod
    async def publish(self, topic: str, data: Any):
        pass

class InMemoryEventBus(EventBus):
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        # A queue for decoupling publisher and consumers
        self._queue = asyncio.Queue()
        self._worker_task = None

    def subscribe(self, topic: str, callback: Callable):
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        self._subscribers[topic].append(callback)

    async def publish(self, topic: str, data: Any):
        await self._queue.put((topic, data))

    async def _worker(self):
        while True:
            topic, data = await self._queue.get()
            if topic in self._subscribers:
                for callback in self._subscribers[topic]:
                    try:
                        # Allow both async and sync callbacks
                        if asyncio.iscoroutinefunction(callback):
                            await callback(data)
                        else:
                            callback(data)
                    except Exception as e:
                        print(f"Error in subscriber for {topic}: {e}")
            self._queue.task_done()

    def start(self):
        if not self._worker_task:
            self._worker_task = asyncio.create_task(self._worker())

    def stop(self):
        if self._worker_task:
            self._worker_task.cancel()
            self._worker_task = None

# Global instance for the application
event_bus = InMemoryEventBus()
