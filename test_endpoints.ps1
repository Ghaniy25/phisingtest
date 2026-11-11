# PowerShell Endpoints Verification Script
# Test all FastAPI endpoints with colored terminal output

$baseUrl = "http://127.0.0.1:8000/api/v1"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Testing Smart Phishing Detection API Endpoints" -ForegroundColor Cyan
Write-Host " Base URL: $baseUrl" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Method,
        [string]$Uri,
        [object]$Body = $null
    )

    Write-Host "`n[*] Testing: $Name ($Method $Uri)" -ForegroundColor Yellow
    try {
        $params = @{
            Uri = $Uri
            Method = $Method
            ContentType = "application/json"
            ErrorAction = "Stop"
        }
        if ($Body) {
            $params.Body = ($Body | ConvertTo-Json -Depth 5)
        }

        $response = Invoke-RestMethod @params
        Write-Host "[✓] SUCCESS" -ForegroundColor Green
        Write-Host ($response | ConvertTo-Json -Depth 3) -ForegroundColor Gray
    }
    catch {
        Write-Host "[✗] FAILED: $_" -ForegroundColor Red
    }
}

# 1. Health Check
Test-Endpoint -Name "Health Check" -Method "GET" -Uri "$baseUrl/health"

# 2. Statistics Check
Test-Endpoint -Name "Aggregate Statistics" -Method "GET" -Uri "$baseUrl/statistics"

# 3. Analyze Legitimate URL (Safe)
Test-Endpoint -Name "Analyze Safe URL" -Method "POST" -Uri "$baseUrl/analyze" -Body @{ url = "https://www.google.com" }

# 4. Analyze Suspicious URL
Test-Endpoint -Name "Analyze Suspicious URL" -Method "POST" -Uri "$baseUrl/analyze" -Body @{ url = "http://promo-update-bank.com/verify" }

# 5. Analyze Phishing URL
Test-Endpoint -Name "Analyze Phishing URL (IP + Keywords)" -Method "POST" -Uri "$baseUrl/analyze" -Body @{ url = "http://192.168.1.100/login-account-verify.php" }

# 6. Get Recent History
Test-Endpoint -Name "Get Scan History (Limit 3)" -Method "GET" -Uri "$baseUrl/history?limit=3"

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host " All endpoint checks finished." -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
