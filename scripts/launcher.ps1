$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

function Log($msg) { Write-Host "[SDA Pathfinder] $msg" }
function Die($msg) {
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    [System.Windows.Forms.MessageBox]::Show($msg, "SDA Pathfinder", "OK", "Error") | Out-Null
    Write-Error $msg
    exit 1
}

# Find Python 3.12+. Try the launcher first, then bare python on PATH.
$pyCmd = $null
foreach ($try in @(@("py","-3.12"), @("py","-3"), @("python"), @("python3"))) {
    try {
        $exe = $try[0]
        $args = if ($try.Count -gt 1) { $try[1..($try.Count-1)] } else { @() }
        $ver = & $exe @args -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')" 2>$null
        if ($LASTEXITCODE -eq 0 -and $ver) {
            $parts = $ver.Trim().Split(".")
            if ([int]$parts[0] -ge 3 -and [int]$parts[1] -ge 12) {
                $pyCmd = @($exe) + $args
                break
            }
        }
    } catch { }
}
if (-not $pyCmd) {
    Die "Python 3.12 or newer is required.`n`nDownload from https://www.python.org/downloads/`n(check 'Add to PATH' during install) then re-run."
}
Log "Using $((& $pyCmd[0] @($pyCmd[1..($pyCmd.Count-1)] + '--version') 2>&1))"

$wheelDir = "radkit-wheels"
$wheels = @(Get-ChildItem $wheelDir -Filter "cisco_radkit_*.whl" -ErrorAction SilentlyContinue)
if ($wheels.Count -eq 0) {
    Die @"
RADKit wheels not found.

Download the four RADKit 1.9.9 cp312 wheels for Windows from:
   https://radkit.cisco.com/downloads/release/

Drop them into:
   $((Get-Location).Path)\$wheelDir\

Then run this launcher again.
"@
}

# Pull latest from GitHub if this is a git checkout.
if ((Test-Path ".git") -and (Get-Command git -ErrorAction SilentlyContinue)) {
    Log "Checking for updates..."
    try { & git pull --ff-only 2>$null | Out-Null } catch { Log "git pull skipped" }
}

# Create venv on first run.
if (-not (Test-Path ".venv")) {
    Log "Creating virtual environment..."
    & $pyCmd[0] @($pyCmd[1..($pyCmd.Count-1)] + @("-m", "venv", ".venv"))
    if ($LASTEXITCODE -ne 0) { Die "Failed to create virtualenv." }
}
$pyExe = ".\.venv\Scripts\python.exe"
$pipInstall = @("-m", "pip", "install", "--quiet")

# Install deps if requirements or wheels changed.
$stamp = ".venv\.installed"
$needInstall = $false
if (-not (Test-Path $stamp)) { $needInstall = $true }
elseif ((Get-Item "requirements.txt").LastWriteTime -gt (Get-Item $stamp).LastWriteTime) { $needInstall = $true }
if (Test-Path $stamp) {
    $stampTime = (Get-Item $stamp).LastWriteTime
    foreach ($w in $wheels) {
        if ($w.LastWriteTime -gt $stampTime) { $needInstall = $true }
    }
}
if ($needInstall) {
    Log "Installing dependencies (one-time, ~1-2 min)..."
    & $pyExe -m pip install --quiet --upgrade pip
    & $pyExe @($pipInstall + @("-r", "requirements.txt"))
    if ($LASTEXITCODE -ne 0) { Die "pip install -r requirements.txt failed." }
    # pip picks the wheel matching this interpreter; non-matching wheels are
    # skipped without error, so dropping multiple platforms here is fine.
    & $pyExe @($pipInstall + @("--upgrade") + ($wheels | ForEach-Object { $_.FullName }))
    if ($LASTEXITCODE -ne 0) { Die "Failed to install RADKit wheels from $wheelDir." }
    New-Item -ItemType File -Path $stamp -Force | Out-Null
}

# Open browser ~2s after server starts.
Start-Job -ScriptBlock { Start-Sleep -Seconds 2; Start-Process "http://127.0.0.1:8000" } | Out-Null

Log "Starting on http://127.0.0.1:8000  (Ctrl+C to stop)"
& $pyExe -m uvicorn server:app --host 127.0.0.1 --port 8000
