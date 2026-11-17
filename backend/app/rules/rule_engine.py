"""
Configurable, explicit Rule Engine for detecting suspicious network flow patterns.
Provides single-flow rules and multi-flow historical correlation rules.
All findings are classified as suspicious patterns, not confirmed attacks.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set
import numpy as np

from app.core.config import settings
from app.models.detection import AlertSeverity


@dataclass
class RuleFinding:
    rule_id: str
    title: str
    description: str
    severity: AlertSeverity
    evidence: Dict[str, Any] = field(default_factory=dict)


# Common suspicious / high-risk destination ports (Metasploit, trojans, IRC bots, backdoor shells)
HIGH_RISK_PORTS: Set[int] = {
    1337,   # Elite / backdoor
    31337,  # Back Orifice
    4444,   # Metasploit default listener
    5555,   # Freeciv / Android ADB exposed / malware
    6667,   # IRC default (often botnets)
    9999,   # Urchin / Trojan listener
    12345,  # NetBus
    27374,  # SubSeven
    65535,  # Edge port test
}


class RuleEngine:
    """
    Evaluates individual network flow records and multi-flow historical context
    against configurable heuristic behavioral rules.
    """

    def __init__(
        self,
        syn_ratio_threshold: Optional[float] = None,
        syn_min_packets: Optional[int] = None,
        high_pps_threshold: Optional[float] = None,
        high_bps_threshold: Optional[float] = None,
        high_rst_count_threshold: Optional[int] = None,
        high_dns_query_threshold: Optional[int] = None,
        port_scan_distinct_ports: Optional[int] = None,
        port_scan_window_seconds: Optional[int] = None,
        beacon_min_intervals: Optional[int] = None,
        beacon_max_packets_per_flow: Optional[int] = None,
        beacon_max_jitter_seconds: Optional[float] = None,
        beacon_max_cv: Optional[float] = None,
    ) -> None:
        self.syn_ratio_threshold = (
            syn_ratio_threshold
            if syn_ratio_threshold is not None
            else getattr(settings, "RULE_SYN_RATIO_THRESHOLD", 5.0)
        )
        self.syn_min_packets = (
            syn_min_packets
            if syn_min_packets is not None
            else getattr(settings, "RULE_SYN_MIN_PACKETS", 10)
        )
        self.high_pps_threshold = (
            high_pps_threshold
            if high_pps_threshold is not None
            else getattr(settings, "RULE_HIGH_PPS_THRESHOLD", 500.0)
        )
        self.high_bps_threshold = (
            high_bps_threshold
            if high_bps_threshold is not None
            else getattr(settings, "RULE_HIGH_BPS_THRESHOLD", 5_000_000.0)
        )
        self.high_rst_count_threshold = (
            high_rst_count_threshold
            if high_rst_count_threshold is not None
            else getattr(settings, "RULE_HIGH_RST_THRESHOLD", 5)
        )
        self.high_dns_query_threshold = (
            high_dns_query_threshold
            if high_dns_query_threshold is not None
            else getattr(settings, "RULE_HIGH_DNS_THRESHOLD", 25)
        )
        self.port_scan_distinct_ports = (
            port_scan_distinct_ports
            if port_scan_distinct_ports is not None
            else getattr(settings, "RULE_PORT_SCAN_DISTINCT_PORTS", 10)
        )
        self.port_scan_window_seconds = (
            port_scan_window_seconds
            if port_scan_window_seconds is not None
            else getattr(settings, "RULE_PORT_SCAN_WINDOW_SECONDS", 60)
        )
        self.beacon_min_intervals = (
            beacon_min_intervals
            if beacon_min_intervals is not None
            else getattr(settings, "RULE_BEACON_MIN_INTERVALS", 4)
        )
        self.beacon_max_packets_per_flow = (
            beacon_max_packets_per_flow
            if beacon_max_packets_per_flow is not None
            else getattr(settings, "RULE_BEACON_MAX_PACKETS_PER_FLOW", 10)
        )
        self.beacon_max_jitter_seconds = (
            beacon_max_jitter_seconds
            if beacon_max_jitter_seconds is not None
            else getattr(settings, "RULE_BEACON_MAX_JITTER_SECONDS", 3.0)
        )
        self.beacon_max_cv = (
            beacon_max_cv
            if beacon_max_cv is not None
            else getattr(settings, "RULE_BEACON_MAX_CV", 0.25)
        )

    def evaluate_flow(
        self,
        flow: Any,
        flow_history: Optional[List[Any]] = None,
    ) -> List[RuleFinding]:
        """
        Evaluates a flow record against all single-flow and historical multi-flow rules.
        Returns a list of RuleFinding instances.
        """
        findings: List[RuleFinding] = []

        # 1. SYN-heavy connection attempts
        f1 = self._check_syn_heavy(flow)
        if f1:
            findings.append(f1)

        # 2. High packet / byte rates
        f2 = self._check_high_rate(flow)
        if f2:
            findings.append(f2)

        # 3. Excessive TCP resets
        f3 = self._check_excessive_rst(flow)
        if f3:
            findings.append(f3)

        # 4. High DNS activity
        f4 = self._check_high_dns(flow)
        if f4:
            findings.append(f4)

        # 5. Uncommon / high-risk destination port
        f5 = self._check_uncommon_port(flow)
        if f5:
            findings.append(f5)

        # 6. High broadcast / multicast activity
        f6 = self._check_broadcast_multicast(flow)
        if f6:
            findings.append(f6)

        # 7. Multi-flow: Port-scan-like behavior
        if flow_history:
            f7 = self._check_port_scan(flow, flow_history)
            if f7:
                findings.append(f7)

            # 8. Multi-flow: Beaconing-like repeated connections
            f8 = self._check_beaconing(flow, flow_history)
            if f8:
                findings.append(f8)

        return findings

    # -------------------------------------------------------------------------
    # Single-flow rules
    # -------------------------------------------------------------------------

    def _check_syn_heavy(self, flow: Any) -> Optional[RuleFinding]:
        proto = (getattr(flow, "protocol", "") or "").upper()
        if proto != "TCP":
            return None

        syn = getattr(flow, "tcp_syn_count", 0)
        ack = getattr(flow, "tcp_ack_count", 0)

        # Case A: syn_min_packets or more SYNs with 0 ACKs
        # Case B: 15 or more SYNs with SYN/ACK ratio > syn_ratio_threshold
        is_syn_heavy = False
        if syn >= self.syn_min_packets and ack == 0:
            is_syn_heavy = True
        elif syn >= max(15, self.syn_min_packets) and (ack == 0 or (syn / max(1, ack)) >= self.syn_ratio_threshold):
            is_syn_heavy = True

        if is_syn_heavy:
            return RuleFinding(
                rule_id="RULE_SYN_HEAVY",
                title="Suspicious SYN-Heavy Connection Pattern",
                description=(
                    f"Flow recorded {syn} TCP SYN attempts with only {ack} ACK responses, "
                    "resembling potential half-open connection flooding or host discovery probing."
                ),
                severity=AlertSeverity.MEDIUM,
                evidence={
                    "tcp_syn_count": syn,
                    "tcp_ack_count": ack,
                    "protocol": proto,
                    "threshold_syn": self.syn_min_packets,
                },
            )
        return None

    def _check_high_rate(self, flow: Any) -> Optional[RuleFinding]:
        pps = float(getattr(flow, "packets_per_second", 0.0) or 0.0)
        bps = float(getattr(flow, "bytes_per_second", 0.0) or 0.0)

        if pps >= self.high_pps_threshold or bps >= self.high_bps_threshold:
            return RuleFinding(
                rule_id="RULE_HIGH_RATE",
                title="Abnormal Volumetric Transmission Rate",
                description=(
                    f"Flow exhibited high rates ({pps:.1f} pps, {bps:.1f} Bps) exceeding "
                    f"normal operational baseline thresholds ({self.high_pps_threshold} pps, {self.high_bps_threshold} Bps)."
                ),
                severity=AlertSeverity.MEDIUM,
                evidence={
                    "packets_per_second": pps,
                    "bytes_per_second": bps,
                    "threshold_pps": self.high_pps_threshold,
                    "threshold_bps": self.high_bps_threshold,
                    "duration_seconds": getattr(flow, "duration_seconds", 0.0) or 0.0,
                },
            )
        return None

    def _check_excessive_rst(self, flow: Any) -> Optional[RuleFinding]:
        proto = (getattr(flow, "protocol", "") or "").upper()
        if proto != "TCP":
            return None

        rst = getattr(flow, "tcp_rst_count", 0) or 0
        total_pkts = getattr(flow, "packet_count", 0) or 0

        if rst >= self.high_rst_count_threshold and (rst / max(1, total_pkts) >= 0.25 or rst >= 10):
            return RuleFinding(
                rule_id="RULE_EXCESSIVE_RST",
                title="Excessive TCP Reset Packets Observed",
                description=(
                    f"Flow recorded {rst} TCP RST flags ({rst}/{total_pkts} packets), "
                    "which may indicate connection rejection, active teardown, or port probing."
                ),
                severity=AlertSeverity.LOW,
                evidence={
                    "tcp_rst_count": rst,
                    "packet_count": total_pkts,
                    "threshold_rst": self.high_rst_count_threshold,
                },
            )
        return None

    def _check_high_dns(self, flow: Any) -> Optional[RuleFinding]:
        q_count = getattr(flow, "dns_query_count", 0) or 0
        uq_count = getattr(flow, "dns_unique_query_count", 0) or 0

        if q_count >= self.high_dns_query_threshold or uq_count >= (self.high_dns_query_threshold // 2):
            return RuleFinding(
                rule_id="RULE_HIGH_DNS",
                title="High-Volume DNS Query Activity",
                description=(
                    f"Flow contains {q_count} DNS queries ({uq_count} unique) in a single window, "
                    "exceeding typical user traffic patterns and suggesting potential tunneling or discovery."
                ),
                severity=AlertSeverity.MEDIUM,
                evidence={
                    "dns_query_count": q_count,
                    "dns_unique_query_count": uq_count,
                    "threshold_dns": self.high_dns_query_threshold,
                },
            )
        return None

    def _check_uncommon_port(self, flow: Any) -> Optional[RuleFinding]:
        dst_port = getattr(flow, "dst_port", None)
        if dst_port is not None and dst_port in HIGH_RISK_PORTS:
            return RuleFinding(
                rule_id="RULE_UNCOMMON_PORT",
                title="Connection to High-Risk Destination Port",
                description=(
                    f"Flow contacted destination port {dst_port}, which is commonly associated "
                    "with remote administrative tools, backdoor shells, or botnet command channels."
                ),
                severity=AlertSeverity.MEDIUM,
                evidence={
                    "dst_port": dst_port,
                    "protocol": getattr(flow, "protocol", ""),
                    "known_high_risk": True,
                },
            )
        return None

    def _check_broadcast_multicast(self, flow: Any) -> Optional[RuleFinding]:
        is_bcast = bool(getattr(flow, "is_broadcast", False))
        is_mcast = bool(getattr(flow, "is_multicast", False))
        pkts = getattr(flow, "packet_count", 0) or 0
        pps = float(getattr(flow, "packets_per_second", 0.0) or 0.0)

        if (is_bcast or is_mcast) and (pkts >= 50 or pps >= 50.0):
            kind = "Broadcast" if is_bcast else "Multicast"
            return RuleFinding(
                rule_id="RULE_HIGH_BROADCAST_MULTICAST",
                title=f"Elevated {kind} Traffic Volume",
                description=(
                    f"Observed high volume of {kind.lower()} packets ({pkts} packets, {pps:.1f} pps), "
                    "which may signify layer-2 storming or aggressive service enumeration."
                ),
                severity=AlertSeverity.LOW,
                evidence={
                    "is_broadcast": is_bcast,
                    "is_multicast": is_mcast,
                    "packet_count": pkts,
                    "packets_per_second": pps,
                },
            )
        return None

    # -------------------------------------------------------------------------
    # Multi-flow historical rules
    # -------------------------------------------------------------------------

    def _check_port_scan(
        self,
        current_flow: Any,
        history: List[Any],
    ) -> Optional[RuleFinding]:
        """
        Detects port scanning by analyzing distinct destination ports targeted
        by the current flow's source IP across the recent time window.
        """
        src_ip = getattr(current_flow, "src_ip", None)
        if not src_ip:
            return None

        now = getattr(current_flow, "last_seen", None) or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        cutoff = now - timedelta(seconds=self.port_scan_window_seconds)

        distinct_ports: Set[int] = set()
        matched_flows_count = 0

        # Combine history with current flow
        candidate_flows = list(history) + [current_flow]
        for f in candidate_flows:
            if getattr(f, "src_ip", None) == src_ip:
                f_time = getattr(f, "last_seen", None)
                if f_time:
                    if f_time.tzinfo is None:
                        f_time = f_time.replace(tzinfo=timezone.utc)
                    if f_time >= cutoff:
                        dport = getattr(f, "dst_port", None)
                        if dport is not None:
                            distinct_ports.add(dport)
                            matched_flows_count += 1

        if len(distinct_ports) >= self.port_scan_distinct_ports:
            return RuleFinding(
                rule_id="RULE_PORT_SCAN",
                title="Suspected Port Scanning Activity",
                description=(
                    f"Host {src_ip} targeted {len(distinct_ports)} distinct destination ports "
                    f"across {matched_flows_count} flows within a {self.port_scan_window_seconds}s window, "
                    "characteristic of systematic port discovery."
                ),
                severity=AlertSeverity.HIGH,
                evidence={
                    "src_ip": src_ip,
                    "distinct_ports_count": len(distinct_ports),
                    "sampled_ports": sorted(list(distinct_ports))[:20],
                    "window_seconds": self.port_scan_window_seconds,
                    "threshold_ports": self.port_scan_distinct_ports,
                },
            )
        return None

    def _check_beaconing(
        self,
        current_flow: Any,
        history: List[Any],
    ) -> Optional[RuleFinding]:
        """
        Detects periodic outbound beaconing by checking for regularly-spaced,
        low-volume connections between the same endpoint pair across multiple windows.
        """
        src_ip = getattr(current_flow, "src_ip", None)
        dst_ip = getattr(current_flow, "dst_ip", None)
        dst_port = getattr(current_flow, "dst_port", None)

        if not (src_ip and dst_ip and dst_port):
            return None

        # Collect matching flows between this exact pair
        matching = [
            f for f in (list(history) + [current_flow])
            if getattr(f, "src_ip", None) == src_ip
            and getattr(f, "dst_ip", None) == dst_ip
            and getattr(f, "dst_port", None) == dst_port
        ]

        if len(matching) < self.beacon_min_intervals:
            return None

        # Verify low packet volume per flow (beacons are typically lightweight check-ins)
        for f in matching:
            if getattr(f, "packet_count", 0) > self.beacon_max_packets_per_flow:
                return None

        # Calculate timestamps and intervals
        timestamps = sorted([
            getattr(f, "window_start", getattr(f, "first_seen", None))
            for f in matching
            if getattr(f, "window_start", getattr(f, "first_seen", None)) is not None
        ])

        if len(timestamps) < self.beacon_min_intervals:
            return None

        intervals: List[float] = []
        for i in range(1, len(timestamps)):
            diff = (timestamps[i] - timestamps[i - 1]).total_seconds()
            intervals.append(diff)

        if not intervals:
            return None

        mean_interval = float(np.mean(intervals))
        std_interval = float(np.std(intervals))

        # Check for regular timing: standard deviation within max_jitter or coefficient of variation <= max_cv
        is_periodic = (std_interval <= self.beacon_max_jitter_seconds) or (
            mean_interval > 0 and (std_interval / mean_interval) <= self.beacon_max_cv
        )

        if is_periodic and mean_interval >= 5.0:
            return RuleFinding(
                rule_id="RULE_BEACONING",
                title="Suspicious Periodic Beaconing Pattern",
                description=(
                    f"Detected {len(matching)} periodic connections between {src_ip} and {dst_ip}:{dst_port} "
                    f"with an average interval of {mean_interval:.1f}s (std={std_interval:.2f}s), "
                    "resembling automated heartbeat or C2 polling."
                ),
                severity=AlertSeverity.HIGH,
                evidence={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flow_count": len(matching),
                    "mean_interval_seconds": round(mean_interval, 2),
                    "std_interval_seconds": round(std_interval, 2),
                    "threshold_min_flows": self.beacon_min_intervals,
                },
            )
        return None


# Global singleton rule engine instance
rule_engine = RuleEngine()
