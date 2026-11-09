"""
Feature schema and extraction pipeline for ML-based Network Intrusion Detection.
Defines a stable, versioned set of numerical features extracted from FlowRecord instances.
"""
from typing import Any, Dict, List, Optional
import numpy as np

# Canonical feature schema version
FEATURE_SCHEMA_VERSION = "1.0"

# Stable, ordered list of numeric flow features used for training and inference
FEATURE_NAMES: List[str] = [
    "duration_seconds",
    "packet_count",
    "byte_count",
    "fwd_packets",
    "rev_packets",
    "fwd_bytes",
    "rev_bytes",
    "packets_per_second",
    "bytes_per_second",
    "min_packet_size",
    "max_packet_size",
    "avg_packet_size",
    "tcp_syn_count",
    "tcp_ack_count",
    "tcp_fin_count",
    "tcp_rst_count",
    "tcp_psh_count",
    "dns_query_count",
    "dns_unique_query_count",
    "upload_bytes",
    "download_bytes",
    "upload_ratio",
]


def extract_features_from_dict(features_dict: Dict[str, Any]) -> List[float]:
    """
    Extracts an ordered numeric vector from a flow's features dictionary or model attributes.
    Missing or non-finite numerical values (None, NaN, +Inf, -Inf) are returned as np.nan
    so the scikit-learn SimpleImputer in the pipeline handles them statistically
    rather than relying on arbitrary defaults.
    """
    vector: List[float] = []
    for name in FEATURE_NAMES:
        val = features_dict.get(name)
        if val is None:
            vector.append(float("nan"))
        else:
            try:
                num = float(val)
                if np.isnan(num) or np.isinf(num):
                    vector.append(float("nan"))
                else:
                    vector.append(num)
            except (ValueError, TypeError):
                vector.append(float("nan"))
    return vector


def extract_features_from_flow(flow: Any) -> List[float]:
    """
    Extracts ordered feature vector directly from a FlowRecord model instance.
    """
    data = {
        "duration_seconds": getattr(flow, "duration_seconds", None),
        "packet_count": getattr(flow, "packet_count", None),
        "byte_count": getattr(flow, "byte_count", None),
        "fwd_packets": getattr(flow, "fwd_packets", None),
        "rev_packets": getattr(flow, "rev_packets", None),
        "fwd_bytes": getattr(flow, "fwd_bytes", None),
        "rev_bytes": getattr(flow, "rev_bytes", None),
        "packets_per_second": getattr(flow, "packets_per_second", None),
        "bytes_per_second": getattr(flow, "bytes_per_second", None),
        "min_packet_size": getattr(flow, "min_packet_size", None),
        "max_packet_size": getattr(flow, "max_packet_size", None),
        "avg_packet_size": getattr(flow, "avg_packet_size", None),
        "tcp_syn_count": getattr(flow, "tcp_syn_count", None),
        "tcp_ack_count": getattr(flow, "tcp_ack_count", None),
        "tcp_fin_count": getattr(flow, "tcp_fin_count", None),
        "tcp_rst_count": getattr(flow, "tcp_rst_count", None),
        "tcp_psh_count": getattr(flow, "tcp_psh_count", None),
        "dns_query_count": getattr(flow, "dns_query_count", None),
        "dns_unique_query_count": getattr(flow, "dns_unique_query_count", None),
        "upload_bytes": getattr(flow, "upload_bytes", None),
        "download_bytes": getattr(flow, "download_bytes", None),
        "upload_ratio": getattr(flow, "upload_ratio", None),
    }
    return extract_features_from_dict(data)


def flows_to_feature_matrix(flows: List[Any]) -> np.ndarray:
    """
    Converts a collection of FlowRecord objects into a 2D NumPy feature matrix (N, D).
    """
    if not flows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)
    rows = [extract_features_from_flow(f) for f in flows]
    return np.array(rows, dtype=np.float64)
