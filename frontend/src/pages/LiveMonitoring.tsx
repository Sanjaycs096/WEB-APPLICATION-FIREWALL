import { useState, useEffect, useRef } from 'react';
import { Activity, AlertTriangle, Shield, Zap, Wifi, WifiOff, Settings } from 'lucide-react';
import { Link } from 'react-router-dom';

interface DetectionEvent {
  type: string;
  timestamp: string;
  request: {
    ip: string;
    method: string;
    path: string;
    query: string;
    userAgent: string;
    statusCode: number;
  };
  detection: {
    anomalyScore: number;
    isAnomalous: boolean;
    confidence: number;
    threshold: number;
    severity: 'low' | 'medium' | 'high' | 'critical';
  };
  metadata: {
    latency: number;
    modelVersion: string;
  };
}

const LiveMonitoring = () => {
  const [events, setEvents] = useState<DetectionEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [stats, setStats] = useState({
    totalRequests: 0,
    anomalousRequests: 0,
    avgScore: 0,
    criticalCount: 0
  });
  
  const wsRef = useRef<WebSocket | null>(null);
  const maxEvents = 100; // Keep last 100 events

  useEffect(() => {
    connectWebSocket();
    
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const connectWebSocket = () => {
    try {
      const wsBaseUrl = (import.meta as any).env?.VITE_WS_URL || 'ws://localhost:8000';
      const ws = new WebSocket(`${wsBaseUrl}/ws/live`);
      
      ws.onopen = () => {
        console.log('WebSocket connected');
        setIsConnected(true);
        setConnectionError(null);
      };
      
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          if (data.type === 'detection') {
            const detectionEvent = data as DetectionEvent;
            
            setEvents(prev => {
              const newEvents = [detectionEvent, ...prev].slice(0, maxEvents);
              return newEvents;
            });
            
            // Update stats
            setStats(prev => ({
              totalRequests: prev.totalRequests + 1,
              anomalousRequests: prev.anomalousRequests + (detectionEvent.detection.isAnomalous ? 1 : 0),
              avgScore: ((prev.avgScore * prev.totalRequests) + detectionEvent.detection.anomalyScore) / (prev.totalRequests + 1),
              criticalCount: prev.criticalCount + (detectionEvent.detection.severity === 'critical' ? 1 : 0)
            }));
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setConnectionError('Connection error');
      };
      
      ws.onclose = () => {
        console.log('WebSocket disconnected');
        setIsConnected(false);
        
        // Attempt to reconnect after 3 seconds
        setTimeout(() => {
          if (wsRef.current?.readyState === WebSocket.CLOSED) {
            connectWebSocket();
          }
        }, 3000);
      };
      
      wsRef.current = ws;
      
    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
      setConnectionError('Failed to connect');
    }
  };

  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-300';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-300';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      case 'low':
      default:
        return 'bg-green-100 text-green-800 border-green-300';
    }
  };

  const getScoreColor = (score: number): string => {
    if (score >= 0.85) return 'text-red-600 font-bold';
    if (score >= 0.6) return 'text-orange-600 font-semibold';
    if (score >= 0.3) return 'text-yellow-600';
    return 'text-green-600';
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Live Traffic Monitoring</h1>
        <p className="text-gray-600 mt-2">
          Real-time HTTP request stream and ML-based anomaly detection (trained on benign traffic)
        </p>
      </div>

      {/* Architecture Info Banner */}
      <div className="bg-blue-50 border-l-4 border-blue-400 p-4 rounded-lg">
        <div className="flex items-start gap-3">
          <Shield className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="text-blue-900 font-semibold">Anomaly-Based Detection (Not Rule-Based)</p>
            <p className="text-blue-700 mt-1">
              The ML model detects deviations from learned benign patterns. 
              "BLOCKED" indicates high anomaly score (configurable threshold in Settings). 
              Actual blocking policy is determined by your deployment configuration.
            </p>
          </div>
        </div>
      </div>

      {/* Connection Status */}
      <div className={`card transition-all duration-300 ${
        isConnected ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
      }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {isConnected ? (
              <>
                <Wifi className="w-5 h-5 text-green-600" />
                <span className="font-semibold text-green-800 inline-flex items-center">
                  <span className="live-pulse mr-2">●</span>
                  WebSocket Connected
                </span>
              </>
            ) : (
              <>
                <WifiOff className="w-5 h-5 text-red-600" />
                <span className="font-semibold text-red-800">
                  {connectionError || 'Disconnected - Reconnecting...'}
                </span>
              </>
            )}
          </div>
          <button
            onClick={connectWebSocket}
            className="btn-secondary text-sm"
            disabled={isConnected}
          >
            Reconnect
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Total Requests</p>
              <p className="text-2xl font-bold text-gray-900">{stats.totalRequests}</p>
            </div>
            <Activity className="w-8 h-8 text-blue-600" />
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Anomalous</p>
              <p className="text-2xl font-bold text-orange-600">{stats.anomalousRequests}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-orange-600" />
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Avg Score</p>
              <p className={`text-2xl font-bold ${getScoreColor(stats.avgScore)}`}>
                {stats.avgScore.toFixed(3)}
              </p>
            </div>
            <Zap className="w-8 h-8 text-yellow-600" />
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Critical Threats</p>
              <p className="text-2xl font-bold text-red-600">{stats.criticalCount}</p>
            </div>
            <Shield className="w-8 h-8 text-red-600" />
          </div>
        </div>
      </div>

      {/* Live Events Table */}
      <div className="card">
        <h2 className="text-xl font-bold text-gray-900 mb-4">Live Detection Stream</h2>
        
        {events.length === 0 ? (
          <div className="text-center py-12">
            <Shield className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-600 font-medium mb-2">
              {isConnected ? 'Waiting for traffic...' : 'Connect to view live traffic'}
            </p>
            <p className="text-sm text-gray-500 mb-4">
              Enable Demo Mode in Settings to generate synthetic traffic, or send real requests to /scan endpoint
            </p>
            <Link 
              to="/settings" 
              className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              <Settings className="w-4 h-4" />
              Go to Settings
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Method</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Path</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Score</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {events.map((event, idx) => (
                  <tr
                    key={`${event.timestamp}-${idx}`}
                    className={`transition-colors duration-150 ${
                      event.detection.isAnomalous ? 'bg-red-50 hover:bg-red-100' : 'hover:bg-gray-50'
                    }`}
                  >
                    <td className="px-4 py-3 text-sm text-gray-600">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3 text-sm font-mono">
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${
                        event.request.method === 'GET' ? 'bg-blue-100 text-blue-800' :
                        event.request.method === 'POST' ? 'bg-green-100 text-green-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {event.request.method}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm font-mono text-gray-900 max-w-xs truncate">
                      {event.request.path}{event.request.query}
                    </td>
                    <td className="px-4 py-3 text-sm font-mono text-gray-600">
                      {event.request.ip}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span className={getScoreColor(event.detection.anomalyScore)}>
                        {event.detection.anomalyScore.toFixed(4)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span className={`px-2 py-1 rounded text-xs font-semibold border ${getSeverityColor(event.detection.severity)}`}>
                        {event.detection.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {event.detection.isAnomalous ? (
                        <span className="text-red-600 font-semibold">🚨 BLOCKED</span>
                      ) : (
                        <span className="text-green-600">✓ Allowed</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default LiveMonitoring;

