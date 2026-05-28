#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Start the Transformer WAF Application
    
.DESCRIPTION
    Starts the WAF API server with proper environment configuration
    
.EXAMPLE
    .\start_waf.ps1
    
.NOTES
    Ensure virtual environment is activated before running
#>

Write-Host "=== Transformer WAF Startup ===" -ForegroundColor Cyan
Write-Host ""

# Set device to CPU (change to "cuda" if GPU available)
$env:WAF_DEVICE = "cpu"
Write-Host "✓ Device set to: $env:WAF_DEVICE" -ForegroundColor Green

# Check if venv is activated
if ($env:VIRTUAL_ENV) {
    Write-Host "✓ Virtual environment active" -ForegroundColor Green
} else {
    Write-Host "⚠ Virtual environment not active" -ForegroundColor Yellow
    Write-Host "  Activating venv..." -ForegroundColor Yellow
    .\venv\Scripts\Activate.ps1
}

Write-Host ""
Write-Host "Starting WAF API Server..." -ForegroundColor Cyan
Write-Host "  - Endpoint: http://localhost:8000" -ForegroundColor White
Write-Host "  - Health: http://localhost:8000/health" -ForegroundColor White
Write-Host "  - Docs: http://localhost:8000/docs" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Start the server
py -m api.waf_api
