import { useEffect, useState } from 'react';
import { wafApi, HealthResponse, StatsResponse, MetricsResponse, TimeseriesResponse } from '../services/api';
import { Shield, AlertTriangle, CheckCircle, Activity, Clock, Zap, Settings } from 'lucide-react';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Link } from 'react-router-dom';

interface SystemConfig {
  detection_mode: string;
  demo_mode: boolean;
  demo_request_count: number;
  demo_total_requests: number;
  anomaly_threshold: number;
}

const Dashboard = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [timeseries, setTimeseries] = useState<TimeseriesResponse | null>(null);
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setError(null);
      const [healthData, statsData, metricsData, timeseriesData, configData] = await Promise.all([
        wafApi.health(),
        wafApi.stats().catch(() => null),
        wafApi.metrics(),
        wafApi.timeseriesMetrics(20),
        wafApi.getConfig().catch(() => null),
      ]);
      setHealth(healthData);
      setStats(statsData);
      setMetrics(metricsData);
      setTimeseries(timeseriesData);
      setConfig(configData);
      setError(null);
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || err.message || 'Failed to connect to WAF API';
      setError(errorMsg);
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000); // Refresh every 5s
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading WAF Dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center p-8 bg-red-50 rounded-lg max-w-md">
          <AlertTriangle className="mx-auto mb-4 text-red-600" size={48} />
          <h2 className="text-xl font-bold text-red-900 mb-2">Connection Error</h2>
          <p className="text-red-700 mb-4">{error}</p>
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              fetchData();
            }}
            className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
          >
            Retry Connection
          </button>
          <p className="text-sm text-gray-600 mt-4">
            Make sure the backend API is running on {(import.meta as any).env?.VITE_API_URL || (window.location.hostname === 'transformer-waf.onrender.com' ? 'https://transformer-waf-api.onrender.com' : 'http://127.0.0.1:8000')}
          </p>
        </div>
      </div>
    );
  }

  const anomalyRate = metrics && metrics.total_requests > 0 
    ? ((metrics.anomalous_requests / metrics.total_requests) * 100).toFixed(1) 
    : '0.0';
  const detectionRate = metrics?.detection_rate?.toFixed(1) || '100.0';

  // Use metrics data (real-time) with fallback to stats
  const totalRequests = metrics?.total_requests || stats?.total_requests || 0;
  const anomalousRequests = metrics?.anomalous_requests || stats?.anomalous_requests || 0;
  const avgLatency = metrics?.latency_p95 || stats?.p95_latency_ms || 0;
  const p50Latency = stats?.p50_latency_ms || 0;
  const p99Latency = stats?.p99_latency_ms || 0;
  const avgScore = metrics?.avg_anomaly_score || stats?.average_score || 0;
  const cacheHitRate = stats?.cache_hit_rate || 0;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="text-gray-600 mt-1">Real-time Transformer-based WAF monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          {config && (
            <div className="flex items-center gap-2">
              <div className={`px-3 py-1 rounded-lg text-sm font-semibold ${
                config.detection_mode === 'block' 
                  ? 'bg-red-100 text-red-800' 
                  : config.detection_mode === 'detect'
                  ? 'bg-yellow-100 text-yellow-800'
                  : 'bg-blue-100 text-blue-800'
              }`}>
                {config.detection_mode === 'block' && '🛡️ Block Mode'}
                {config.detection_mode === 'detect' && '⚠️ Detect & Alert'}
                {config.detection_mode === 'monitor' && '👁️ Monitor Only'}
              </div>
              {config.demo_mode && (
                <div className="px-3 py-1 rounded-lg text-sm font-semibold bg-purple-100 text-purple-800">
                  🎮 Demo: {config.demo_request_count}/{config.demo_total_requests}
                </div>
              )}
              <Link 
                to="/settings"
                className="p-2 rounded-lg bg-gray-100 hover:bg-gray-200 transition-colors"
                title="Configure Settings"
              >
                <Settings size={20} className="text-gray-700" />
              </Link>
            </div>
          )}
          {health && (
            <div className={`flex items-center gap-2 px-4 py-2 rounded-lg ${health.model_loaded ? 'bg-success-100 text-success-800' : 'bg-danger-100 text-danger-800'}`}>
              {health.model_loaded ? <CheckCircle size={20} /> : <AlertTriangle size={20} />}
              <span className="font-semibold">{health.status.toUpperCase()}</span>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="bg-danger-50 border border-danger-200 text-danger-800 px-4 py-3 rounded-lg">
          <div className="flex items-center gap-2">
            <AlertTriangle size={20} />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Requests"
          value={totalRequests.toLocaleString()}
          icon={Activity}
          color="blue"
        />
        <StatCard
          title="Anomalies Detected"
          value={anomalousRequests.toLocaleString()}
          icon={AlertTriangle}
          color="red"
          subtitle={`${anomalyRate}% of traffic`}
        />
        <StatCard
          title="Detection Rate"
          value={`${detectionRate}%`}
          icon={Shield}
          color="green"
          subtitle="Benign traffic"
        />
        <StatCard
          title="Avg Latency (P95)"
          value={`${avgLatency.toFixed(0)}ms`}
          icon={Zap}
          color="yellow"
          subtitle={`P50: ${p50Latency.toFixed(0)}ms`}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Anomaly Score Distribution */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">
            Anomaly Score Trend 
            {timeseries?.is_live && (
              <span className="text-xs text-success-600 ml-2 inline-flex items-center">
                <span className="live-pulse mr-1">●</span> LIVE
              </span>
            )}
          </h3>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={timeseries?.score_trend || []}>
              <defs>
                <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis domain={[0, 1]} />
              <Tooltip />
              <Area type="monotone" dataKey="score" stroke="#ef4444" fillOpacity={1} fill="url(#colorScore)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Request Volume */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">
            Request Volume 
            {timeseries?.is_live && (
              <span className="text-xs text-success-600 ml-2 inline-flex items-center">
                <span className="live-pulse mr-1">●</span> LIVE
              </span>
            )}
          </h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={timeseries?.volume_trend || []}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="benign" stroke="#22c55e" strokeWidth={2} />
              <Line type="monotone" dataKey="anomalous" stroke="#ef4444" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Performance Metrics */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Performance Metrics</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <MetricItem label="Cache Hit Rate" value={`${(cacheHitRate * 100).toFixed(1)}%`} />
          <MetricItem label="Avg Score" value={avgScore.toFixed(3)} />
          <MetricItem label="P99 Latency" value={`${p99Latency.toFixed(0)}ms`} />
        </div>
      </div>

      {/* Model Info */}
      {health && (
        <div className="card bg-gradient-to-r from-primary-50 to-blue-50 border-primary-200">
          <div className="flex items-start gap-4">
            <Shield className="text-primary-600" size={40} />
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-gray-900 mb-2">Transformer Model Status</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-gray-600">Model:</span>
                  <p className="font-semibold">DistilBERT-based</p>
                </div>
                <div>
                  <span className="text-gray-600">Parameters:</span>
                  <p className="font-semibold">90.7M</p>
                </div>
                <div>
                  <span className="text-gray-600">Uptime:</span>
                  <p className="font-semibold">{formatUptime(health.uptime_seconds)}</p>
                </div>
                <div>
                  <span className="text-gray-600">Version:</span>
                  <p className="font-semibold">{health.version}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Security Principles */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Architecture</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <SecurityPrinciple
            icon={Shield}
            title="Defense in Depth"
            description="Multiple security layers: validation, rate limiting, ML detection"
          />
          <SecurityPrinciple
            icon={CheckCircle}
            title="Zero Trust"
            description="All requests validated and analyzed, no implicit trust"
          />
          <SecurityPrinciple
            icon={Activity}
            title="Real-time Detection"
            description="Async ML-based anomaly detection on all traffic"
          />
        </div>
      </div>
    </div>
  );
};

// Helper Components
interface StatCardProps {
  title: string;
  value: string;
  icon: any;
  color: 'blue' | 'red' | 'green' | 'yellow';
  subtitle?: string;
}

const StatCard = ({ title, value, icon: Icon, color, subtitle }: StatCardProps) => {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-600',
    red: 'bg-red-100 text-red-600',
    green: 'bg-green-100 text-green-600',
    yellow: 'bg-yellow-100 text-yellow-600',
  };

  return (
    <div className="card">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm text-gray-600">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
          {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
          <Icon size={24} />
        </div>
      </div>
    </div>
  );
};

const MetricItem = ({ label, value }: { label: string; value: string }) => (
  <div className="text-center">
    <p className="text-sm text-gray-600">{label}</p>
    <p className="text-xl font-bold text-gray-900 mt-1">{value}</p>
  </div>
);

const SecurityPrinciple = ({ icon: Icon, title, description }: { icon: any; title: string; description: string }) => (
  <div className="flex gap-3 p-4 bg-gray-50 rounded-lg">
    <Icon className="text-primary-600 flex-shrink-0" size={24} />
    <div>
      <h4 className="font-semibold text-gray-900">{title}</h4>
      <p className="text-sm text-gray-600 mt-1">{description}</p>
    </div>
  </div>
);

// Utility Functions
const formatUptime = (seconds: number): string => {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
};

export default Dashboard;
