import datetime
from typing import Dict, Any, Tuple

SEVERITY_BASE_SCORES = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.5,
    "LOW": 2.0,
    "INFO": 0.5
}

CONFIDENCE_MULTIPLIER = {
    "HIGH": 1.0,
    "MEDIUM": 0.85,
    "LOW": 0.65
}

ASSET_CRITICALITY_MODIFIER = {
    "TIER_1_MISSION_CRITICAL": 1.3,
    "TIER_2_BUSINESS_CRITICAL": 1.1,
    "TIER_3_INTERNAL": 0.9,
    "TIER_4_DEV": 0.7
}

SLA_DAYS_MAP = {
    "CRITICAL": 7,   # 7 days max SLA for critical
    "HIGH": 30,     # 30 days for high
    "MEDIUM": 60,   # 60 days for medium
    "LOW": 90       # 90 days for low
}

class RiskEngine:
    """
    Deterministic enterprise risk evaluation engine.
    Calculates multidimensional risk score, SLA target, and prioritization.
    """

    def calculate_risk(
        self,
        scanner_severity: str,
        confidence: str = "HIGH",
        asset_criticality: str = "TIER_2_BUSINESS_CRITICAL",
        is_production: bool = True,
        is_internet_exposed: bool = False,
        known_exploitation: bool = False,
        first_seen_at: datetime.datetime = None
    ) -> Dict[str, Any]:
        sev_upper = scanner_severity.upper() if scanner_severity else "MEDIUM"
        base_score = SEVERITY_BASE_SCORES.get(sev_upper, 4.0)
        conf_mult = CONFIDENCE_MULTIPLIER.get(confidence.upper(), 0.85)
        asset_mult = ASSET_CRITICALITY_MODIFIER.get(asset_criticality.upper(), 1.0)
        
        # Start calculation
        score = base_score * conf_mult * asset_mult
        
        # Environmental and threat exposure modifiers
        if is_production:
            score += 1.0
        if is_internet_exposed:
            score += 1.5
        if known_exploitation:
            score += 2.0 # KEV addition
            
        # Cap score between 0.1 and 10.0
        final_score = min(max(round(score, 1), 0.1), 10.0)
        
        # Determine risk level
        if final_score >= 8.5:
            risk_level = "CRITICAL"
            priority = "P1"
        elif final_score >= 7.0:
            risk_level = "HIGH"
            priority = "P2"
        elif final_score >= 4.0:
            risk_level = "MEDIUM"
            priority = "P3"
        else:
            risk_level = "LOW"
            priority = "P4"

        # Calculate SLA target
        sla_days = SLA_DAYS_MAP.get(risk_level, 60)
        start_date = first_seen_at or datetime.datetime.now(datetime.timezone.utc)
        if start_date.tzinfo is None:
            start_date = start_date.replace(tzinfo=datetime.timezone.utc)
            
        due_date = start_date + datetime.timedelta(days=sla_days)
        now = datetime.datetime.now(datetime.timezone.utc)
        
        if now > due_date:
            sla_status = "EXCEEDED_SLA"
        elif (due_date - now).days <= 3:
            sla_status = "APPROACHING_SLA"
        else:
            sla_status = "WITHIN_SLA"

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "priority": priority,
            "remediation_due_at": due_date,
            "sla_days": sla_days,
            "sla_status": sla_status
        }
