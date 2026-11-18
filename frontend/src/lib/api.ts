// src/lib/api.ts
// Axios client wired to the FastAPI backend.
// All API calls go through this module — no credentials are stored here.

import axios, { AxiosError, type AxiosInstance } from 'axios'

const configuredBaseUrl = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/+$/, '')
const apiBaseUrl = configuredBaseUrl
  ? `${configuredBaseUrl.replace(/\/api\/v1$/, '')}/api/v1`
  : '/api/v1'

export const api: AxiosInstance = axios.create({
  baseURL: apiBaseUrl,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})

api.interceptors.response.use(
  response => response,
  (error: AxiosError<{ detail?: unknown; message?: string }>) => {
    const detail = error.response?.data?.detail
    if (typeof detail === 'string') error.message = detail
    else if (error.response?.data?.message) error.message = error.response.data.message
    return Promise.reject(error)
  },
)

// ─── Types mirroring FastAPI schemas ────────────────────────────────────────

export interface InterfaceInfo {
  id: string
  name: string
  description: string | null
  mac_address: string | null
  ip_addresses: string[]
  status: string
  is_loopback: boolean
}

export interface CaptureStatusResponse {
  is_running: boolean
  active_session_id: string | null
  interface_id: string | null
  session_mode: 'BASELINE' | 'MONITORING' | null
  started_at: string | null
  packets_seen: number
  packets_enqueued: number
  packets_dropped: number
  queue_size: number
  queue_capacity: number
  preview_count: number
  active_flows: number | null
  flows_persisted: number | null
  error_summary: string | null
}

export interface CaptureSessionResponse {
  id: string
  interface_id: string
  session_mode: string
  status: string
  started_at: string
  stopped_at: string | null
  packets_seen: number
  packets_enqueued: number
  packets_dropped: number
  error_summary: string | null
  created_at: string
}

export interface CaptureStartRequest {
  interface_id: string
  session_mode: 'BASELINE' | 'MONITORING'
  bpf_filter?: string
}

export interface FlowRecord {
  id: string
  flow_key: string
  src_ip: string
  dst_ip: string
  src_port: number | null
  dst_port: number | null
  protocol: string
  first_seen: string
  last_seen: string
  window_start: string
  window_end: string
  packet_count: number
  byte_count: number
  fwd_packets: number
  rev_packets: number
  fwd_bytes: number
  rev_bytes: number
  duration_seconds: number | null
  packets_per_second: number | null
  bytes_per_second: number | null
  min_packet_size: number | null
  max_packet_size: number | null
  avg_packet_size: number | null
  tcp_syn_count: number
  tcp_ack_count: number
  tcp_fin_count: number
  tcp_rst_count: number
  tcp_psh_count: number
  dns_query_count: number
  dns_unique_query_count: number
  upload_bytes: number
  download_bytes: number
  upload_ratio: number | null
  is_local: boolean
  is_broadcast: boolean
  is_multicast: boolean
  session_id: string
  features: Record<string, number> | null
}

export interface TopTalker {
  ip: string
  packets: number
  bytes: number
  bytes_sent: number
  bytes_recv: number
}

export interface AlertSummary {
  total_open: number
  critical: number
  high: number
  medium: number
  low: number
  false_positives_7d: number
}

export interface DetectionWorkerSummary {
  is_running: boolean
  pending_jobs: number
  processing_jobs: number
  completed_jobs: number
  failed_jobs: number
  total_processed: number
}

export interface DashboardSummary {
  capture_status: CaptureStatusResponse
  total_sessions: number
  total_flows: number
  total_packets: number
  total_bytes: number
  protocol_distribution: Record<string, number>
  top_talkers: TopTalker[]
  recent_flows: FlowRecord[]
  alert_summary: AlertSummary
  detection_worker: DetectionWorkerSummary
}

export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE'

export interface AlertResponse {
  id: string
  fingerprint: string
  severity: AlertSeverity
  status: AlertStatus
  detection_source: 'ML' | 'RULE' | 'COMBINED'
  title: string
  description: string
  flow_id: string | null
  rule_id: string | null
  rule_evidence: Record<string, unknown>
  model_version: string | null
  session_id: string | null
  first_seen: string
  last_seen: string
  resolved_at: string | null
  occurrence_count: number
  created_at: string
}

export interface PredictionResponse {
  id: string
  flow_id: string
  model_id: string | null
  model_version: string | null
  status: string
  raw_score: number | null
  raw_prediction: number | null
  alerts_generated: number
  created_at: string
}

export interface ModelStatus {
  active_model: ModelRegistryResponse | null
  is_ready: boolean
  total_registered_models: number
}

export interface ModelRegistryResponse {
  id: string
  name: string
  version: string
  algorithm: string
  status: string
  feature_names: string[]
  feature_schema_version: string
  training_session_id: string | null
  training_sample_count: number
  training_params: Record<string, unknown>
  artifact_path: string | null
  artifact_checksum: string | null
  evaluation_info: Record<string, unknown>
  error_message: string | null
  created_at: string
}

export interface PaginatedResponse<T> {
  total: number
  items: T[]
  skip: number
  limit: number
}

// ─── API functions ───────────────────────────────────────────────────────────

export const getInterfaces = () =>
  api.get<InterfaceInfo[]>('/capture/interfaces').then(r => r.data)

export const getCaptureStatus = () =>
  api.get<CaptureStatusResponse>('/capture/status').then(r => r.data)

export const startCapture = (body: CaptureStartRequest) =>
  api.post<CaptureStatusResponse>('/capture/start', body).then(r => r.data)

export const stopCapture = () =>
  api.post<{ message: string; session: CaptureSessionResponse | null }>('/capture/stop').then(r => r.data)

export const getCapturePreview = () =>
  api.get<{ count: number; packets: unknown[] }>('/capture/preview').then(r => r.data)

export const getSessions = (skip = 0, limit = 20) =>
  api.get<CaptureSessionResponse[]>('/capture/sessions', { params: { skip, limit } }).then(r => r.data)

export const getDashboard = () =>
  api.get<DashboardSummary>('/dashboard/summary').then(r => r.data)

export const getDashboardSummary = getDashboard

export const getFlows = (params: Record<string, unknown> = {}) =>
  api.get<PaginatedResponse<FlowRecord>>('/flows', { params }).then(r => r.data.items)

export const getFlowById = (flowId: string) =>
  api.get<FlowRecord>(`/flows/${encodeURIComponent(flowId)}`).then(r => r.data)

export const getAlerts = (params: Record<string, unknown> = {}) =>
  api.get<PaginatedResponse<AlertResponse>>('/alerts', { params }).then(r => r.data.items)

export const updateAlertStatus = (id: string, status: AlertStatus, notes?: string) =>
  api.patch<AlertResponse>(`/alerts/${id}/status`, { status, notes }).then(r => r.data)

export const resolveAlert = (id: string, notes?: string) =>
  api.patch<AlertResponse>(`/alerts/${id}/resolve`, { notes }).then(r => r.data)

export const getPredictions = (params: Record<string, unknown> = {}) =>
  api.get<PaginatedResponse<PredictionResponse>>('/predictions', { params }).then(r => r.data.items)

export const getModelStatus = () =>
  api.get<ModelStatus>('/models/status').then(r => r.data)

export const trainBaseline = (session_id: string) =>
  api.post<ModelRegistryResponse>('/models/train-baseline', { session_id }).then(r => r.data)

export const getHealthLive = () =>
  api.get<{ status: string }>('/health/live').then(r => r.data)
