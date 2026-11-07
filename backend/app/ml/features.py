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
    Missing or None numerical values are imputed with 0.0 (or 0.5 for upload_ratio).
    """
    vector: List[float] = []
    for name in FEATURE_NAMES:
        val = features_dict.get(name)
        if val is None:
            if name == "upload_ratio":
                vector.append(0.5)
            else:
                vector.append(0.0)
        else:
            try:
                vector.append(float(val))
            except (ValueError, TypeError):
                vector.append(0.0)
    return vector


def extract_features_from_flow(flow: Any) -> List[float]:
    """
    Extracts ordered feature vector directly from a FlowRecord model instance.
    """
    data = {
        "duration_seconds": getattr(flow, "duration_seconds", 0.0),
        "packet_count": getattr(flow, "packet_count", 0),
        "byte_count": getattr(flow, "byte_count", 0),
        "fwd_packets": getattr(flow, "fwd_packets", 0),
        "rev_packets": getattr(flow, "rev_packets", 0),
        "fwd_bytes": getattr(flow, "fwd_bytes", 0),
        "rev_bytes": getattr(flow, "rev_bytes", 0),
        "packets_per_second": getattr(flow, "packets_per_second", 0.0),
        "bytes_per_second": getattr(flow, "bytes_per_second", 0.0),
        "min_packet_size": getattr(flow, "min_packet_size", 0),
        "max_packet_size": getattr(flow, "max_packet_size", 0),
        "avg_packet_size": getattr(flow, "avg_packet_size", 0.0),
        "tcp_syn_count": getattr(flow, "tcp_syn_count", 0),
        "tcp_ack_count": getattr(flow, "tcp_ack_count", 0),
        "tcp_fin_count": getattr(flow, "tcp_fin_count", 0),
        "tcp_rst_count": getattr(flow, "tcp_rst_count", 0),
        "tcp_psh_count": getattr(flow, "tcp_psh_count", 0),
        "dns_query_count": getattr(flow, "dns_query_count", 0),
        "dns_unique_query_count": getattr(flow, "dns_unique_query_count", 0),
        "upload_bytes": getattr(flow, "upload_bytes", 0),
        "download_bytes": getattr(flow, "download_bytes", 0),
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
