import { useState, useEffect } from 'react';
import axios from 'axios';
import { Save, RefreshCw, Shield, Sliders, Bell, Code } from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000';

interface SystemConfig {
  anomaly_threshold: number;
  detection_mode: 'monitor' | 'detect' | 'block';
  protected_app_url: string;
  demo_mode: boolean;
  demo_request_count: number;
  demo_total_requests: number;
  severity_thresholds: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  logging_level: 'debug' | 'info' | 'warning' | 'error';
  enable_notifications: boolean;
}

const DEFAULT_CONFIG: SystemConfig = {
  anomaly_threshold: 0.5,
  detection_mode: 'detect',
  protected_app_url: '',
  demo_mode: false,
  demo_request_count: 0,
  demo_total_requests: 100,
  severity_thresholds: {
    low: 0.3,
    medium: 0.6,
    high: 0.85,
    critical: 0.95
  },
  logging_level: 'info',
  enable_notifications: true
};

const normalizeConfig = (data: Partial<SystemConfig> | null | undefined): SystemConfig => {
  return {
    ...DEFAULT_CONFIG,
    ...(data || {}),
    severity_thresholds: {
      ...DEFAULT_CONFIG.severity_thresholds,
      ...((data && data.severity_thresholds) || {})
    }
  };
};

const Settings = () => {
  const [config, setConfig] = useState<SystemConfig>(DEFAULT_CONFIG);

  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    fetchConfig();
    
    // Auto-refresh config every 2 seconds when demo mode is active
    const interval = setInterval(() => {
      if (config.demo_mode && config.demo_request_count < config.demo_total_requests) {
        fetchConfig();
      }
    }, 2000);
    
    return () => clearInterval(interval);
  }, [config.demo_mode, config.demo_request_count, config.demo_total_requests]);

  const fetchConfig = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/config`);
      setConfig(normalizeConfig(response.data));
    } catch (error) {
      console.error('Failed to fetch config:', error);
      // Use defaults if backend not ready
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveMessage(null);

    try {
      await axios.post(`${API_BASE_URL}/config`, config);
      setSaveMessage({ type: 'success', text: 'Configuration saved successfully!' });
      
      // Also update threshold via existing endpoint
      await axios.post(`${API_BASE_URL}/threshold?threshold=${config.anomaly_threshold}`);
    } catch (error: any) {
      setSaveMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || 'Failed to save configuration' 
      });
    } finally {
      setSaving(false);
      setTimeout(() => setSaveMessage(null), 5000);
    }
  };

  const handleDemoToggle = async (enabled: boolean) => {
    // Update local state immediately for responsive UI
    const updatedConfig = { ...config, demo_mode: enabled };
    setConfig(updatedConfig);
    
    // Save to backend immediately
    try {
      await axios.post(`${API_BASE_URL}/config`, updatedConfig);
      setSaveMessage({ 
        type: 'success', 
        text: enabled ? 'Demo mode enabled! Generating 100 requests...' : 'Demo mode disabled' 
      });
      setTimeout(() => setSaveMessage(null), 3000);
    } catch (error: any) {
      setSaveMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || 'Failed to update demo mode' 
      });
      // Revert local state on error
      setConfig(config);
      setTimeout(() => setSaveMessage(null), 5000);
    }
  };

  const handleReset = () => {
    setConfig(DEFAULT_CONFIG);
    setSaveMessage({ type: 'success', text: 'Configuration reset to defaults' });
    setTimeout(() => setSaveMessage(null), 3000);
  };

  const handleResetDemo = async () => {
    try {
      await axios.post(`${API_BASE_URL}/config/reset-demo`);
      await fetchConfig(); // Refresh config
      setSaveMessage({ type: 'success', text: 'Demo mode reset! Generating 100 new requests...' });
      setTimeout(() => setSaveMessage(null), 5000);
    } catch (error: any) {
      setSaveMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || 'Failed to reset demo mode' 
      });
      setTimeout(() => setSaveMessage(null), 5000);
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">System Configuration</h1>
        <p className="text-gray-600 mt-2">Adjust detection thresholds and system parameters</p>
      </div>

      {/* Save Message */}
      {saveMessage && (
        <div className={`p-4 rounded-lg ${
          saveMessage.type === 'success' 
            ? 'bg-green-50 border border-green-200 text-green-800' 
            : 'bg-red-50 border border-red-200 text-red-800'
        }`}>
          {saveMessage.text}
        </div>
      )}

      {/* Detection Settings */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <Shield className="w-6 h-6 text-blue-600" />
          <h2 className="text-xl font-bold text-gray-900">Detection Settings</h2>
        </div>

        <div className="space-y-6">
          {/* Anomaly Threshold */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Anomaly Threshold
              <span className="ml-2 text-gray-500">({config.anomaly_threshold.toFixed(2)})</span>
            </label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={config.anomaly_threshold}
              onChange={(e) => setConfig({ ...config, anomaly_threshold: parseFloat(e.target.value) })}
              className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
            />
            <div className="flex justify-between text-xs text-gray-500 mt-1">
              <span>Low Sensitivity (0.0)</span>
              <span>High Sensitivity (1.0)</span>
            </div>
            <p className="text-sm text-gray-600 mt-2">
              Requests with anomaly scores above this threshold will be flagged as suspicious.
            </p>
          </div>

          {/* Detection Mode */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Detection Mode
            </label>
            <select
              value={config.detection_mode}
              onChange={(e) => setConfig({ ...config, detection_mode: e.target.value as any })}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
            >
              <option value="monitor">Monitor Only (Log but don't block)</option>
              <option value="detect">Detect & Alert (Log and alert)</option>
              <option value="block">Block Mode (Log, alert, and block)</option>
            </select>
            <p className="text-sm text-gray-600 mt-2">
              {config.detection_mode === 'monitor' && 'Passive monitoring mode - no blocking'}
              {config.detection_mode === 'detect' && 'Active detection with alerting'}
              {config.detection_mode === 'block' && 'Full protection mode - blocks malicious requests'}
            </p>
          </div>

          {/* Demo Mode */}
          <div className="bg-gradient-to-r from-blue-50 to-purple-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div>
                <p className="font-medium text-gray-900">Demo Mode</p>
                <p className="text-sm text-gray-600">Generate 100 simulated requests for testing</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.demo_mode}
                  onChange={(e) => handleDemoToggle(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
              </label>
            </div>
            
            {config.demo_mode && (
              <div className="mt-3 space-y-2 animate-fadeIn">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-700">Progress:</span>
                  <span className="font-semibold text-blue-600">
                    {config.demo_request_count} / {config.demo_total_requests} requests
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2.5">
                  <div 
                    className="bg-blue-600 h-2.5 rounded-full transition-all duration-500"
                    style={{ width: `${(config.demo_request_count / config.demo_total_requests) * 100}%` }}
                  ></div>
                </div>
                {config.demo_request_count >= config.demo_total_requests && (
                  <div className="flex items-center justify-between pt-2">
                    <p className="text-sm text-green-600 font-medium">✓ Demo complete!</p>
                    <button
                      onClick={handleResetDemo}
                      className="btn-secondary text-xs py-1 px-3 hover:scale-105 transition-transform"
                    >
                      Reset & Restart
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Severity Thresholds */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <Sliders className="w-6 h-6 text-purple-600" />
          <h2 className="text-xl font-bold text-gray-900">Severity Thresholds</h2>
        </div>

        <div className="space-y-4">
          {Object.entries(config.severity_thresholds).map(([severity, value]) => (
            <div key={severity}>
              <label className="block text-sm font-medium text-gray-700 mb-2 capitalize">
                {severity} ({value.toFixed(2)})
              </label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={value}
                onChange={(e) => setConfig({
                  ...config,
                  severity_thresholds: {
                    ...config.severity_thresholds,
                    [severity]: parseFloat(e.target.value)
                  }
                })}
                className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
              />
            </div>
          ))}
        </div>
      </div>

      {/* System Settings */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <Code className="w-6 h-6 text-green-600" />
          <h2 className="text-xl font-bold text-gray-900">System Settings</h2>
        </div>

        <div className="space-y-6">
          {/* Protected App URL */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Protected App URL (Origin)
            </label>
            <input
              type="url"
              placeholder="https://app.example.com or http://127.0.0.1:3000"
              value={config.protected_app_url}
              onChange={(e) => setConfig({ ...config, protected_app_url: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
            />
            <p className="text-sm text-gray-600 mt-2">
              Use your application origin (the backend or static site host). This is informational and does not change routing by itself.
            </p>
          </div>

          {/* Logging Level */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Logging Level
            </label>
            <select
              value={config.logging_level}
              onChange={(e) => setConfig({ ...config, logging_level: e.target.value as any })}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
            >
              <option value="debug">Debug (Most verbose)</option>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="error">Error (Least verbose)</option>
            </select>
          </div>

          {/* Notifications */}
          <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center gap-3">
              <Bell className="w-5 h-5 text-gray-600" />
              <div>
                <p className="font-medium text-gray-900">Enable Notifications</p>
                <p className="text-sm text-gray-600">Receive alerts for critical threats</p>
              </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={config.enable_notifications}
                onChange={(e) => setConfig({ ...config, enable_notifications: e.target.checked })}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex items-center justify-end gap-3">
        <button
          onClick={handleReset}
          disabled={saving}
          className="btn-secondary flex items-center gap-2 hover:scale-105 active:scale-95 transition-transform disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <RefreshCw className="w-4 h-4" />
          Reset to Defaults
        </button>
        <button
          onClick={handleSave}
          disabled={saving}
          className="btn-primary flex items-center gap-2 hover:scale-105 active:scale-95 transition-transform disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Save className="w-4 h-4" />
          {saving ? (
            <>
              <span className="inline-block animate-spin">⏳</span>
              Saving...
            </>
          ) : (
            'Save Configuration'
          )}
        </button>
      </div>
    </div>
  );
};

export default Settings;

