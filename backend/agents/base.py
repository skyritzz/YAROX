from abc import ABC, abstractmethod
from typing import Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase, AgentAction
import json

class BaseAgent(ABC):
    def __init__(self, name: str, role: str, goal: str):
        self.name = name
        self.role = role
        self.goal = goal

    async def _log_action(self, db: AsyncSession, case_id: str, thought: str, action_taken: str, input_data: Any, output_data: Any):
        action = AgentAction(
            case_id=case_id,
            agent_name=self.name,
            thought=thought,
            action_taken=action_taken,
            input_data=input_data,
            output_data=output_data
        )
        db.add(action)
        await db.commit()
        
        from websocket.investigation_ws import manager as ws_manager
        await ws_manager.broadcast({
            "event": "AGENT_THINKING", 
            "case_id": str(case_id), 
            "agent": self.name, 
            "thought": thought
        })

    @abstractmethod
    async def analyze(self, db: AsyncSession, case: InvestigationCase, **kwargs) -> Dict[str, Any]:
        """Main entry point for agent logic."""
        pass
