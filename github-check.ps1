# GitHub Pre-Flight Check
Write-Host "GitHub Pre-Flight Check" -ForegroundColor Cyan
Write-Host "======================="
Write-Host ""

$pass = $true

# Test 1
Write-Host "[1/5] .gitignore files..." -NoNewline
if ((Test-Path .gitignore) -and (Test-Path frontend/.gitignore)) {
    Write-Host " PASS" -ForegroundColor Green
} else {
    Write-Host " FAIL" -ForegroundColor Red
    $pass = $false
}

# Test 2
Write-Host "[2/5] .env.example files..." -NoNewline
if ((Test-Path .env.example) -and (Test-Path frontend/.env.example)) {
    Write-Host " PASS" -ForegroundColor Green
} else {
    Write-Host " FAIL" -ForegroundColor Red
    $pass = $false
}

# Test 3  
Write-Host "[3/5] Documentation..." -NoNewline
$docs = @("README.md", "LICENSE", "CONTRIBUTING.md", "SECURITY.md")
$found = $true
foreach ($d in $docs) { if (!(Test-Path $d)) { $found = $false } }
if ($found) {
    Write-Host " PASS" -ForegroundColor Green
} else {
    Write-Host " FAIL" -ForegroundColor Red
    $pass = $false
}

# Test 4
Write-Host "[4/5] package.json..." -NoNewline
$pkg = Get-Content package.json | ConvertFrom-Json
if ($pkg.name -eq "vulnforge") {
    Write-Host " PASS" -ForegroundColor Green
} else {
    Write-Host " FAIL" -ForegroundColor Red
    $pass = $false
}

# Test 5
Write-Host "[5/5] No secrets in .env.example..." -NoNewline
$env = Get-Content .env.example -Raw
if ($env -notmatch "AIzaSy[A-Za-z0-9_-]{33}") {
    Write-Host " PASS" -ForegroundColor Green
} else {
    Write-Host " FAIL" -ForegroundColor Red
    $pass = $false
}

Write-Host ""
if ($pass) {
    Write-Host "Ready for GitHub!" -ForegroundColor Green
} else {
    Write-Host "Fix issues above first" -ForegroundColor Red
}
