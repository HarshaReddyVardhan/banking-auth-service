<#
.SYNOPSIS
    Generate JWT keys and application secrets for banking-auth-service.

.DESCRIPTION
    This script generates:
    - 3072-bit RSA key pair for JWT signing
    - Strong random passwords for database and Redis
    - AES-256 field encryption key (64 hex chars)
    
    Outputs kubectl commands to create secrets directly in Kubernetes.

.EXAMPLE
    .\setup-secrets.ps1
    
.NOTES
    Requirements:
    - OpenSSL (via Git for Windows or standalone)
    - kubectl (for applying secrets to cluster)
#>

param(
    [string]$Namespace = "banking",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Find OpenSSL
$OpenSSL = $null
$possiblePaths = @(
    "C:\Program Files\Git\usr\bin\openssl.exe",
    "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    "openssl"
)

foreach ($path in $possiblePaths) {
    try {
        $null = & $path version 2>$null
        $OpenSSL = $path
        break
    } catch {}
}

if (-not $OpenSSL) {
    Write-Error "OpenSSL not found. Install Git for Windows or OpenSSL."
    exit 1
}

Write-Host "Using OpenSSL: $OpenSSL" -ForegroundColor Cyan
Write-Host ""

# Create keys directory
$KeysDir = Join-Path $PSScriptRoot "..\keys"
if (-not (Test-Path $KeysDir)) {
    New-Item -ItemType Directory -Path $KeysDir -Force | Out-Null
}
$KeysDir = Resolve-Path $KeysDir

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  GENERATING JWT KEYS" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

$PrivateKeyPath = Join-Path $KeysDir "private.pem"
$PublicKeyPath = Join-Path $KeysDir "public.pem"

# Generate 3072-bit RSA private key
Write-Host "Generating 3072-bit RSA private key..." -ForegroundColor Green
& $OpenSSL genrsa -out $PrivateKeyPath 3072 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to generate private key"
    exit 1
}

# Generate public key
Write-Host "Extracting public key..." -ForegroundColor Green
& $OpenSSL rsa -in $PrivateKeyPath -pubout -out $PublicKeyPath 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to extract public key"
    exit 1
}

Write-Host ""
Write-Host "✓ Private key: $PrivateKeyPath" -ForegroundColor Green
Write-Host "✓ Public key:  $PublicKeyPath" -ForegroundColor Green
Write-Host ""

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  GENERATING APPLICATION SECRETS" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

# Generate strong passwords
function New-RandomPassword {
    param([int]$Length = 32)
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function New-HexKey {
    param([int]$Bytes = 32)
    $hexChars = "0123456789abcdef"
    -join ((1..($Bytes * 2)) | ForEach-Object { $hexChars[(Get-Random -Maximum $hexChars.Length)] })
}

$DbPassword = New-RandomPassword -Length 32
$RedisPassword = New-RandomPassword -Length 32
$EncryptionKey = New-HexKey -Bytes 32

Write-Host "✓ Database password:     $($DbPassword.Substring(0,8))..." -ForegroundColor Green
Write-Host "✓ Redis password:        $($RedisPassword.Substring(0,8))..." -ForegroundColor Green
Write-Host "✓ Field encryption key:  $($EncryptionKey.Substring(0,16))..." -ForegroundColor Green
Write-Host ""

# Save backup
$BackupPath = Join-Path $PSScriptRoot "..\.secrets.backup"
@"
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# ⚠️ KEEP THIS FILE SECURE - DO NOT COMMIT TO GIT

DB_PASSWORD=$DbPassword
REDIS_PASSWORD=$RedisPassword
FIELD_ENCRYPTION_KEY=$EncryptionKey
"@ | Out-File -FilePath $BackupPath -Encoding UTF8

Write-Host "✓ Passwords saved to: $BackupPath" -ForegroundColor Cyan
Write-Host "  ⚠️  Keep this file secure!" -ForegroundColor Yellow
Write-Host ""

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  KUBECTL COMMANDS" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

$dryRunFlag = if ($DryRun) { "--dry-run=client -o yaml" } else { "" }

Write-Host "# 1. Create namespace (if needed)" -ForegroundColor Cyan
Write-Host "kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f -" -ForegroundColor White
Write-Host ""

Write-Host "# 2. Create JWT keys secret" -ForegroundColor Cyan
$jwtCmd = @"
kubectl create secret generic banking-auth-jwt-keys ``
  --from-file=private.pem="$PrivateKeyPath" ``
  --from-file=public.pem="$PublicKeyPath" ``
  -n $Namespace $dryRunFlag
"@
Write-Host $jwtCmd -ForegroundColor White
Write-Host ""

Write-Host "# 3. Create application secrets" -ForegroundColor Cyan
$secretsCmd = @"
kubectl create secret generic banking-auth-secrets ``
  --from-literal=DB_PASSWORD="$DbPassword" ``
  --from-literal=REDIS_PASSWORD="$RedisPassword" ``
  --from-literal=FIELD_ENCRYPTION_KEY="$EncryptionKey" ``
  --from-literal=SMTP_PASSWORD="" ``
  --from-literal=HIBP_API_KEY="" ``
  -n $Namespace $dryRunFlag
"@
Write-Host $secretsCmd -ForegroundColor White
Write-Host ""

Write-Host "# 4. Make secrets immutable (optional)" -ForegroundColor Cyan
Write-Host "kubectl patch secret banking-auth-jwt-keys -n $Namespace -p '{\"immutable\": true}'" -ForegroundColor White
Write-Host "kubectl patch secret banking-auth-secrets -n $Namespace -p '{\"immutable\": true}'" -ForegroundColor White
Write-Host ""

Write-Host "# 5. Verify secrets" -ForegroundColor Cyan
Write-Host "kubectl get secrets -n $Namespace" -ForegroundColor White
Write-Host ""

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✓ SETUP COMPLETE" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Run the kubectl commands above to create secrets" -ForegroundColor White
Write-Host "  2. Update SMTP_PASSWORD and HIBP_API_KEY if needed" -ForegroundColor White
Write-Host "  3. Deploy the application" -ForegroundColor White
Write-Host ""
