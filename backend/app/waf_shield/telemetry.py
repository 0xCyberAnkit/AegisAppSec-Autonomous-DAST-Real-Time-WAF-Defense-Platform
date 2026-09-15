import threading
import time
from typing import Dict, Any, List
from collections import deque

class WAFTelemetry:
    """
    Thread-safe live telemetry and event hub for Aegis-Shield WAF.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(WAFTelemetry, cls).__new__(cls)
                cls._instance._init_state()
            return cls._instance

    def _init_state(self):
        # Operational mode: 'OFF', 'DETECT', 'BLOCK', 'SANITIZE'
        self.mode = "OFF"
        self.total_inspected = 0
        self.total_blocked = 0
        self.total_detected = 0
        self.total_sanitized = 0
        self.evasions_defeated = 0
        
        self.attack_counters = {
            "SQL Injection (SQLi)": 0,
            "Cross-Site Scripting (XSS)": 0,
            "Server-Side Request Forgery (SSRF)": 0,
            "Cross-Site Request Forgery (CSRF)": 0,
            "Path Traversal / LFI": 0,
            "Other / Heuristic": 0,
        }
        
        # Keep last 150 live security events
        self.events = deque(maxlen=150)
        self.state_lock = threading.Lock()

    def set_mode(self, new_mode: str) -> str:
        valid_modes = {"OFF", "DETECT", "BLOCK", "SANITIZE"}
        upper = new_mode.upper()
        if upper in valid_modes:
            with self.state_lock:
                self.mode = upper
        return self.mode

    def get_mode(self) -> str:
        with self.state_lock:
            return self.mode

    def record_inspection(self):
        with self.state_lock:
            self.total_inspected += 1

    def record_attack(self, attack_data: Dict[str, Any], action: str, client_ip: str, endpoint: str):
        with self.state_lock:
            attack_type = attack_data.get("attack_type", "Other / Heuristic")
            rule = attack_data.get("rule", "Custom Rule")
            evasions = attack_data.get("evasions", [])
            
            if attack_type in self.attack_counters:
                self.attack_counters[attack_type] += 1
            else:
                self.attack_counters["Other / Heuristic"] += 1

            if evasions:
                self.evasions_defeated += len(evasions)

            if action == "BLOCKED":
                self.total_blocked += 1
            elif action == "DETECTED":
                self.total_detected += 1
            elif action == "SANITIZED":
                self.total_sanitized += 1

            event = {
                "id": f"evt-{int(time.time() * 1000)}-{len(self.events) + 1}",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "time_epoch": time.time(),
                "client_ip": client_ip,
                "endpoint": endpoint,
                "attack_type": attack_type,
                "rule": rule,
                "cwe": attack_data.get("cwe", "CWE-Unknown"),
                "owasp": attack_data.get("owasp", "OWASP-Top10"),
                "evasions": evasions,
                "action": action,
                "mode": self.mode
            }
            self.events.appendleft(event)

    def get_metrics(self) -> Dict[str, Any]:
        with self.state_lock:
            return {
                "mode": self.mode,
                "total_inspected": self.total_inspected,
                "total_blocked": self.total_blocked,
                "total_detected": self.total_detected,
                "total_sanitized": self.total_sanitized,
                "evasions_defeated": self.evasions_defeated,
                "attack_counters": dict(self.attack_counters),
                "recent_events": list(self.events)[:30],
                "active_threat_level": self._calculate_threat_level()
            }

    def _calculate_threat_level(self) -> str:
        recent_attacks = sum(self.attack_counters.values())
        if recent_attacks == 0:
            return "LOW"
        elif recent_attacks < 10:
            return "ELEVATED"
        elif recent_attacks < 30:
            return "HIGH"
        else:
            return "CRITICAL"

    def clear_metrics(self):
        with self.state_lock:
            self._init_state()

waf_telemetry = WAFTelemetry()
