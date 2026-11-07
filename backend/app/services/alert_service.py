"""
Alert Decision Engine and Lifecycle Service.
Combines ML anomaly detection scores and Rule Engine findings according to an explicit policy,
assigns project-defined severity levels, and enforces deduplication via alert fingerprinting and cooldown.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import and_, desc, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import logger
from app.models.detection import (
    Alert,
    AlertSeverity,
    AlertStatus,
    DetectionSource,
    PredictionStatus,
)
from app.rules.rule_engine import RuleFinding


def generate_alert_fingerprint(
    rule_id: Optional[str],
    src_ip: Optional[str],
    dst_ip: Optional[str],
    dst_port: Optional[int],
    protocol: Optional[str],
) -> str:
    """
    Constructs a deterministic fingerprint for deduplicating repeated alerts
    between identical endpoints and behavioral triggers.
    """
    r_id = rule_id or "ML_ANOMALY"
    s_ip = src_ip or "0.0.0.0"
    d_ip = dst_ip or "0.0.0.0"
    d_port = dst_port or 0
    proto = (protocol or "UNKNOWN").upper()
    return f"{r_id}:{s_ip}->{d_ip}:{d_port}:{proto}"


def elevate_severity(base: AlertSeverity) -> AlertSeverity:
    """Elevates alert severity when corroborated by both ML anomaly and behavioral rules."""
    if base == AlertSeverity.LOW:
        return AlertSeverity.MEDIUM
    elif base == AlertSeverity.MEDIUM:
        return AlertSeverity.HIGH
    elif base in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
        return AlertSeverity.CRITICAL
    return AlertSeverity.MEDIUM


class AlertService:
    """
    Correlates ML inference and rule engine outputs into security alerts
    with intelligent deduplication and lifecycle management.
    """

    @staticmethod
    def evaluate_and_alert(
        db: Session,
        flow: Any,
        ml_status: PredictionStatus,
        ml_score: Optional[float],
        model_version: Optional[str],
        rule_findings: List[RuleFinding],
        cooldown_seconds: Optional[int] = None,
    ) -> List[Alert]:
        """
        Executes the alert decision policy for a flow:
          - ML anomaly only
          - Rule finding only
          - ML + Rule corroboration
          - No alert
        Deduplicates against open alerts within the cooldown period.
        """
        cooldown = (
            cooldown_seconds
            if cooldown_seconds is not None
            else getattr(settings, "ALERT_COOLDOWN_SECONDS", 300)
        )
        now = datetime.now(timezone.utc)
        generated_alerts: List[Alert] = []

        is_ml_anomaly = (ml_status == PredictionStatus.ANOMALY)
        has_rules = len(rule_findings) > 0

        # Scenario 1 & 3: Rule findings present (either Rule-only or Corroborated)
        if has_rules:
            for finding in rule_findings:
                if is_ml_anomaly:
                    source = DetectionSource.COMBINED.value
                    sev = elevate_severity(finding.severity).value
                    title = f"Corroborated Anomaly: {finding.title}"
                    desc = (
                        f"{finding.description} Corroborated by Isolation Forest anomaly "
                        f"(model {model_version or 'unknown'}, isolation score={ml_score})."
                    )
                else:
                    source = DetectionSource.RULE.value
                    sev = finding.severity.value
                    title = finding.title
                    desc = finding.description

                evidence = dict(finding.evidence)
                if ml_score is not None:
                    evidence["ml_score"] = ml_score

                fingerprint = generate_alert_fingerprint(
                    rule_id=finding.rule_id,
                    src_ip=getattr(flow, "src_ip", None),
                    dst_ip=getattr(flow, "dst_ip", None),
                    dst_port=getattr(flow, "dst_port", None),
                    protocol=getattr(flow, "protocol", None),
                )

                alert = AlertService._deduplicate_or_create(
                    db=db,
                    flow=flow,
                    source=source,
                    model_version=model_version,
                    rule_id=finding.rule_id,
                    evidence=evidence,
                    severity=sev,
                    title=title,
                    description=desc,
                    fingerprint=fingerprint,
                    cooldown_seconds=cooldown,
                    now=now,
                )
                generated_alerts.append(alert)

        # Scenario 2: ML anomaly only (no rule findings)
        elif is_ml_anomaly:
            source = DetectionSource.ML.value
            # Derive severity based on isolation depth score
            # Strongly negative score (< -0.15) indicates high statistical divergence
            score_val = ml_score or 0.0
            if score_val < -0.15:
                sev = AlertSeverity.MEDIUM.value
            else:
                sev = AlertSeverity.LOW.value

            title = "Statistical Flow Anomaly Detected"
            desc = (
                f"Flow features diverged significantly from baseline traffic profile "
                f"(isolation score={ml_score}, model={model_version or 'unknown'}). "
                "No heuristic behavioral rules triggered; flagged purely by statistical density estimation."
            )

            fingerprint = generate_alert_fingerprint(
                rule_id=None,
                src_ip=getattr(flow, "src_ip", None),
                dst_ip=getattr(flow, "dst_ip", None),
                dst_port=getattr(flow, "dst_port", None),
                protocol=getattr(flow, "protocol", None),
            )

            alert = AlertService._deduplicate_or_create(
                db=db,
                flow=flow,
                source=source,
                model_version=model_version,
                rule_id=None,
                evidence={"ml_score": ml_score, "ml_status": ml_status.value},
                severity=sev,
                title=title,
                description=desc,
                fingerprint=fingerprint,
                cooldown_seconds=cooldown,
                now=now,
            )
            generated_alerts.append(alert)

        # Scenario 4: Neither ML nor rules triggered -> No alert created
        return generated_alerts

    @staticmethod
    def _deduplicate_or_create(
        db: Session,
        flow: Any,
        source: str,
        model_version: Optional[str],
        rule_id: Optional[str],
        evidence: Dict[str, Any],
        severity: str,
        title: str,
        description: str,
        fingerprint: str,
        cooldown_seconds: int,
        now: datetime,
    ) -> Alert:
        """
        Looks for an active OPEN alert with the same fingerprint.
        If found within the cooldown period, increments occurrence count and updates last_seen.
        Otherwise creates a new alert record.
        """
        cooldown_cutoff = now - timedelta(seconds=cooldown_seconds)

        stmt = (
            select(Alert)
            .where(
                and_(
                    Alert.fingerprint == fingerprint,
                    Alert.status == AlertStatus.OPEN.value,
                    Alert.last_seen >= cooldown_cutoff,
                )
            )
            .order_by(desc(Alert.last_seen))
            .limit(1)
        )
        existing = db.execute(stmt).scalar_one_or_none()

        if existing:
            existing.occurrence_count += 1
            existing.last_seen = now
            # Update flow reference to most recent occurrence
            existing.flow_id = getattr(flow, "id", existing.flow_id)
            existing.rule_evidence = evidence
            db.commit()
            db.refresh(existing)
            logger.info(
                f"Deduplicated alert '{fingerprint}': occurrence count updated to {existing.occurrence_count}"
            )
            return existing

        # Create new alert
        new_alert = Alert(
            id=uuid.uuid4(),
            flow_id=getattr(flow, "id", None),
            session_id=getattr(flow, "session_id", None),
            detection_source=source,
            model_version=model_version,
            rule_id=rule_id,
            rule_evidence=evidence,
            severity=severity,
            title=title,
            description=description,
            fingerprint=fingerprint,
            occurrence_count=1,
            first_seen=now,
            last_seen=now,
            status=AlertStatus.OPEN.value,
            resolved_at=None,
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        logger.info(
            f"Created new {severity} alert: '{title}' (source={source}, id={new_alert.id})"
        )
        return new_alert

    @staticmethod
    def resolve_alert(db: Session, alert_id: uuid.UUID) -> Optional[Alert]:
        """Resolves an active alert."""
        stmt = select(Alert).where(Alert.id == alert_id)
        alert = db.execute(stmt).scalar_one_or_none()
        if not alert:
            return None

        alert.status = AlertStatus.RESOLVED.value
        alert.resolved_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(alert)
        logger.info(f"Resolved alert {alert_id}")
        return alert
