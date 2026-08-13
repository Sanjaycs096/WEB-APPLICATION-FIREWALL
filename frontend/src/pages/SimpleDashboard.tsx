import { useEffect, useState } from 'react';

const SimpleDashboard = () => {
  const [message, setMessage] = useState('Loading...');

  useEffect(() => {
    console.log('SimpleDashboard mounted');
    setMessage('Dashboard is working!');
    
    // Test API
    const isProd = window.location.hostname === 'transformer-waf.onrender.com';
    const defaultApiUrl = isProd ? 'https://transformer-waf-api.onrender.com' : 'http://127.0.0.1:8000';
    const baseUrl = (import.meta as any).env?.VITE_API_URL || defaultApiUrl;
    fetch(`${baseUrl}/health`)
      .then(res => res.json())
      .then(data => {
        console.log('API Response:', data);
        setMessage(`API Connected! Status: ${data.status}`);
      })
      .catch(err => {
        console.error('API Error:', err);
        setMessage(`API Error: ${err.message}`);
      });
  }, []);

  return (
    <div style={{ padding: '50px', backgroundColor: '#f0f0f0', minHeight: '100vh' }}>
      <h1 style={{ fontSize: '32px', color: '#333', marginBottom: '20px' }}>
        Transformer WAF Dashboard
      </h1>
      <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px' }}>
        <p style={{ fontSize: '18px', color: '#666' }}>{message}</p>
      </div>
    </div>
  );
};

export default SimpleDashboard;
