# Chạy toàn bộ pipeline Người A trên Windows (PowerShell). Chạy từ thư mục ml\:
#   .\run_lanl.ps1                                  # dữ liệu thật trong data\raw\
#   .\run_lanl.ps1 -Synth                           # chạy thử bằng dữ liệu giả
#   .\run_lanl.ps1 -EndDay 15 -UserSample 0.02      # máy ít RAM
#   .\run_lanl.ps1 -TrainEnd 12 -ValEnd 16 -Es https://192.168.1.10:9200
# Nếu bị chặn chạy script: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
param(
    [switch]$Synth,
    [int]$StartDay = 0,
    [int]$EndDay = 30,
    [double]$UserSample = 0.05,
    [double]$MachineSample = 0.002,
    [int]$TrainEnd = -1,
    [int]$ValEnd = -1,
    [string]$Es = "",
    [string]$Index = "alerts-ueba"
)
$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"   # in tiếng Việt không lỗi trên console Windows
Set-Location $PSScriptRoot

function Run($argsList) {
    Write-Host ">> python $($argsList -join ' ')" -ForegroundColor Cyan
    & python @argsList
    if ($LASTEXITCODE -ne 0) { throw "Lỗi ở bước: python $($argsList -join ' ')" }
}

if ($Synth) {
    Run @("src\make_synthetic_lanl.py")
    $auth = "data\raw\synthetic\auth.txt.gz"; $red = "data\raw\synthetic\redteam.txt.gz"
    $EndDay = 14; $UserSample = 1; $MachineSample = 1
    if ($TrainEnd -lt 0) { $TrainEnd = 7 }
    if ($ValEnd -lt 0) { $ValEnd = 10 }
} else {
    $auth = "data\raw\auth.txt.gz"; $red = "data\raw\redteam.txt.gz"
    if (-not (Test-Path $auth)) { throw "Không thấy $auth - tải LANL về data\raw\ trước" }
    Run @("src\lanl_explore_redteam.py")
}

Run @("src\lanl_load_auth.py", "--auth", $auth, "--redteam", $red, "--start-day", $StartDay,
      "--end-day", $EndDay, "--user-sample", $UserSample, "--machine-sample", $MachineSample)
Run @("src\features.py", "--window", "3600", "--warmup-days", "2")

$trainArgs = @("src\train.py")
if ($TrainEnd -ge 0) { $trainArgs += @("--train-end-day", $TrainEnd) }
if ($ValEnd -ge 0) { $trainArgs += @("--val-end-day", $ValEnd) }
Run $trainArgs

Run @("src\evaluate.py", "--alert-quantile", "0.995")

$exportArgs = @("src\export_alerts.py", "--split", "test", "--min-score", "0.995")
if ($Es) { $exportArgs += @("--es", $Es, "--index", $Index) }
Run $exportArgs

Write-Host "Xong. Kết quả: reports\metrics.md, reports\roc_pr.png, reports\alerts.json" -ForegroundColor Green
