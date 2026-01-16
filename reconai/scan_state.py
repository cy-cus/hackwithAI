"""
Scan State Manager - Handles pause/resume and step-by-step scanning

Enables:
- Pause/Resume functionality
- Crash recovery
- Step-by-step manual progression
- State persistence
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ScanPhase(str, Enum):
    """Scan phases for step-by-step progression"""
    INIT = "initialization"
    SUBDOMAIN_ENUM = "subdomain_enumeration"
    HTTP_PROBE = "http_probing"
    WEB_CRAWL = "web_crawling"
    JS_DISCOVERY = "javascript_discovery"
    JS_ANALYSIS = "javascript_analysis"
    VULN_SCAN = "vulnerability_scanning"
    PARAM_FUZZ = "parameter_fuzzing"
    NUCLEI = "nuclei_scanning"
    COMPLETE = "completed"


class ScanState(str, Enum):
    """Scan execution states"""
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_USER = "waiting_for_user_input"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanStateManager:
    """
    Manages scan state for pause/resume and step-by-step execution.
    """
    
    def __init__(self, scan_id: str, output_dir: Path):
        self.scan_id = scan_id
        self.output_dir = Path(output_dir)
        self.state_file = self.output_dir / "scan_state.json"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize or load state
        self.state = self._load_state()
    
    def _load_state(self) -> Dict[str, Any]:
        """Load existing state or create new"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                logger.info(f"Loaded existing state for scan {self.scan_id}")
                return state
            except Exception as e:
                logger.error(f"Failed to load state: {e}")
        
        # Create new state
        return {
            "scan_id": self.scan_id,
            "status": ScanState.QUEUED,
            "current_phase": ScanPhase.INIT,
            "completed_phases": [],
            "phase_data": {},
            "user_selections": {},
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "paused_at": None,
            "resumed_at": None
        }
    
    def save_state(self):
        """Persist state to disk"""
        try:
            self.state["updated_at"] = datetime.now().isoformat()
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2)
            logger.debug(f"Saved state for scan {self.scan_id}")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    def set_status(self, status: ScanState):
        """Update scan status"""
        self.state["status"] = status
        if status == ScanState.PAUSED:
            self.state["paused_at"] = datetime.now().isoformat()
        elif status == ScanState.RUNNING and self.state.get("paused_at"):
            self.state["resumed_at"] = datetime.now().isoformat()
        self.save_state()
    
    def set_phase(self, phase: ScanPhase):
        """Update current phase"""
        self.state["current_phase"] = phase
        self.save_state()
    
    def complete_phase(self, phase: ScanPhase, data: Dict[str, Any]):
        """Mark phase as complete and store results"""
        if phase not in self.state["completed_phases"]:
            self.state["completed_phases"].append(phase)
        
        self.state["phase_data"][phase] = {
            "completed_at": datetime.now().isoformat(),
            "data": data
        }
        self.save_state()
    
    def get_phase_data(self, phase: ScanPhase) -> Optional[Dict[str, Any]]:
        """Get data from completed phase"""
        return self.state["phase_data"].get(phase, {}).get("data")
    
    def set_user_selection(self, phase: ScanPhase, selection: Any):
        """Store user selection for a phase"""
        self.state["user_selections"][phase] = selection
        self.save_state()
    
    def get_user_selection(self, phase: ScanPhase) -> Optional[Any]:
        """Get user selection for a phase"""
        return self.state["user_selections"].get(phase)
    
    def is_phase_complete(self, phase: ScanPhase) -> bool:
        """Check if phase is completed"""
        return phase in self.state["completed_phases"]
    
    def can_resume(self) -> bool:
        """Check if scan can be resumed"""
        return self.state["status"] in [ScanState.PAUSED, ScanState.WAITING_USER, ScanState.FAILED]
    
    def get_next_phase(self) -> Optional[ScanPhase]:
        """Get next phase to execute"""
        phases = list(ScanPhase)
        current_idx = phases.index(self.state["current_phase"])
        
        if current_idx < len(phases) - 1:
            return phases[current_idx + 1]
        return None
    
    def get_progress(self) -> int:
        """Calculate scan progress (0-100)"""
        phases = list(ScanPhase)
        total = len(phases)
        completed = len(self.state["completed_phases"])
        return int((completed / total) * 100)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan state summary"""
        return {
            "scan_id": self.scan_id,
            "status": self.state["status"],
            "current_phase": self.state["current_phase"],
            "progress": self.get_progress(),
            "completed_phases": self.state["completed_phases"],
            "paused": self.state["status"] == ScanState.PAUSED,
            "can_resume": self.can_resume(),
            "created_at": self.state["created_at"],
            "updated_at": self.state["updated_at"]
        }


def load_scan_state(scan_id: str, output_dir: Path) -> ScanStateManager:
    """Load existing scan state"""
    return ScanStateManager(scan_id, output_dir)


def create_scan_state(scan_id: str, output_dir: Path) -> ScanStateManager:
    """Create new scan state"""
    return ScanStateManager(scan_id, output_dir)
