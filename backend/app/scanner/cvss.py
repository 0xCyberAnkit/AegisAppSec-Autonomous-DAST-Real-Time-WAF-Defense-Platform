import math
from typing import Dict, Any, Tuple

class CVSSv31Calculator:
    """
    Standard CVSS v3.1 Base Metric Calculator.
    Computes Base Score, Exploitability, Impact, Severity Rating, and Vector String.
    """

    METRIC_VALUES = {
        # Attack Vector (AV)
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        # Attack Complexity (AC)
        "AC": {"L": 0.77, "H": 0.44},
        # Privileges Required (PR) - Scope Unchanged
        "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
        # Privileges Required (PR) - Scope Changed
        "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},
        # User Interaction (UI)
        "UI": {"N": 0.85, "R": 0.62},
        # Scope (S)
        "S": {"U": False, "C": True},
        # Confidentiality (C)
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        # Integrity (I)
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        # Availability (A)
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }

    @staticmethod
    def roundup(value: float) -> float:
        int_round = round(value * 100000)
        if (int_round % 10000) == 0:
            return int_round / 100000.0
        else:
            return (math.floor(int_round / 10000) + 1) / 10.0

    @classmethod
    def calculate(
        cls,
        av: str = "N",
        ac: str = "L",
        pr: str = "N",
        ui: str = "N",
        s: str = "U",
        c: str = "H",
        i: str = "H",
        a: str = "H",
    ) -> Dict[str, Any]:
        """
        Calculates CVSS 3.1 Base Score and sub-metrics.
        """
        av_val = cls.METRIC_VALUES["AV"].get(av, 0.85)
        ac_val = cls.METRIC_VALUES["AC"].get(ac, 0.77)
        scope_changed = (s == "C")
        
        pr_table = cls.METRIC_VALUES["PR_C"] if scope_changed else cls.METRIC_VALUES["PR_U"]
        pr_val = pr_table.get(pr, 0.85)
        ui_val = cls.METRIC_VALUES["UI"].get(ui, 0.85)
        
        c_val = cls.METRIC_VALUES["C"].get(c, 0.56)
        i_val = cls.METRIC_VALUES["I"].get(i, 0.56)
        a_val = cls.METRIC_VALUES["A"].get(a, 0.56)

        # Exploitability
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        # Impact
        iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))
        
        if not scope_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

        if impact <= 0:
            base_score = 0.0
        else:
            if not scope_changed:
                base_score = min(cls.roundup(impact + exploitability), 10.0)
            else:
                base_score = min(cls.roundup(1.08 * (impact + exploitability)), 10.0)

        # Severity
        if base_score == 0.0:
            severity = "NONE"
        elif base_score < 4.0:
            severity = "LOW"
        elif base_score < 7.0:
            severity = "MEDIUM"
        elif base_score < 9.0:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        return {
            "base_score": round(base_score, 1),
            "severity": severity,
            "impact_subscore": round(impact, 1),
            "exploitability_subscore": round(exploitability, 1),
            "vector_string": vector,
        }
