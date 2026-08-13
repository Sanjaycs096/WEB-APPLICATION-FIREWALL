import axios from 'axios';

// API base URL from environment or intelligent default
const isProd = window.location.hostname === 'transformer-waf.onrender.com';
const defaultApiUrl = isProd ? 'https://transformer-waf-api.onrender.com' : 'http://127.0.0.1:8000';
const API_BASE_URL = (import.meta as any).env?.VITE_API_URL || defaultApiUrl;

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for auth tokens (future)
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('waf_api_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized
      localStorage.removeItem('waf_api_token');
    }
    return Promise.reject(error);
  }
);

export interface HealthResponse {
  status: string;
  model_loaded: boolean;
  version: string;
  uptime_seconds: number;
}

export interface ScanRequest {
  method: string;
  path: string;
  query_string?: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface ScanResponse {
  anomaly_score: number;
  is_anomalous: boolean;
  threshold: number;
  reconstruction_error: number;
  perplexity: number;
  timestamp: string;
  confidence?: number;
}

export interface StatsResponse {
  total_requests: number;
  anomalous_requests: number;
  average_score: number;
  cache_hit_rate: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
}

export interface MetricsResponse {
  total_requests: number;
  anomalous_requests: number;
  critical_threats: number;
  avg_anomaly_score: number;
  detection_rate: number;
  latency_p95: number;
  last_updated: string;
}

export interface TimeseriesResponse {
  score_trend: Array<{ time: string; score: number }>;
  volume_trend: Array<{ time: string; benign: number; anomalous: number }>;
  data_points: number;
  is_live: boolean;
}

export interface AnalyticsResponse {
  total_requests: number;
  total_anomalous: number;
  attack_distribution: { [key: string]: number };
  severity_distribution: { low: number; medium: number; high: number; critical: number };
  hourly_trend: Array<{ hour: string; count: number; anomalous: number }>;
  detection_rate: number;
  avg_anomaly_score: number;
  time_range?: string;
  data_source?: string;
}

export const wafApi = {
  // Health check
  health: async (): Promise<HealthResponse> => {
    const response = await api.get('/health');
    return response.data;
  },

  // Scan single request
  scan: async (request: ScanRequest): Promise<ScanResponse> => {
    const response = await api.post('/scan', request);
    return response.data;
  },

  // Get performance stats
  stats: async (): Promise<StatsResponse> => {
    const response = await api.get('/stats');
    return response.data;
  },

  // Get real-time metrics
  metrics: async (): Promise<MetricsResponse> => {
    const response = await api.get('/metrics');
    return response.data;
  },

  // Get time-series metrics for charts
  timeseriesMetrics: async (minutes: number = 20): Promise<TimeseriesResponse> => {
    const response = await api.get(`/metrics/timeseries?minutes=${minutes}`);
    return response.data;
  },

  // Get analytics data
  analytics: async (range: string = '24h'): Promise<AnalyticsResponse> => {
    const response = await api.get(`/analytics?range=${range}`);
    return response.data;
  },

  // Update anomaly threshold
  updateThreshold: async (threshold: number): Promise<{ threshold: number }> => {
    const response = await api.post('/threshold', { threshold });
    return response.data;
  },

  // Get system config
  getConfig: async (): Promise<any> => {
    const response = await api.get('/config');
    return response.data;
  },

  // Save system config
  saveConfig: async (config: any): Promise<any> => {
    const response = await api.post('/config', config);
    return response.data;
  },

  // Reset demo mode
  resetDemo: async (): Promise<any> => {
    const response = await api.post('/config/reset-demo');
    return response.data;
  },
};

export default api;
