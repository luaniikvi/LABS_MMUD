# Lab 3 - Build and Test Script
# Supports both MSVC and MinGW (MSYS2)
# Usage: .\build_lab3.ps1 [-Compiler msvc|mingw]

param(
    [ValidateSet("msvc", "mingw")]
    [string]$Compiler = "msvc"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Lab 3 - RSA-OAEP & Hybrid Encryption" -ForegroundColor Cyan
Write-Host "Build and Test Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Selected compiler: $Compiler" -ForegroundColor Yellow
Write-Host ""

# Navigate to Lab3 directory
Set-Location "$PSScriptRoot\Lab3_RSA_Hybrid"

# Create build directory
$BuildDir = "build_$Compiler"
if (Test-Path $BuildDir) {
    Write-Host "[INFO] Build directory already exists, cleaning..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $BuildDir
}

Write-Host "[1/4] Creating build directory..." -ForegroundColor Green
New-Item -ItemType Directory -Path $BuildDir | Out-Null
Set-Location $BuildDir

# Configure with CMake
Write-Host "[2/4] Configuring with CMake..." -ForegroundColor Green

if ($Compiler -eq "msvc") {
    cmake .. -G "Visual Studio 17 2022" -A x64
} else {
    # MinGW (MSYS2)
    cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] CMake configuration failed!" -ForegroundColor Red
    exit 1
}

# Build
Write-Host "[3/4] Building project..." -ForegroundColor Green

if ($Compiler -eq "msvc") {
    cmake --build . --config Release
} else {
    cmake --build .
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "[4/4] Running tests..." -ForegroundColor Green
Write-Host ""

# Run tests
ctest -C Release -V

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Executables location:" -ForegroundColor Yellow

if ($Compiler -eq "msvc") {
    Write-Host "  rsatool.exe:         .\Release\rsatool.exe" -ForegroundColor White
    Write-Host "  test_lab3.exe:       .\Release\test_lab3.exe" -ForegroundColor White
    Write-Host "  benchmark_lab3.exe:  .\Release\benchmark_lab3.exe" -ForegroundColor White
    Write-Host ""
    Write-Host "Quick test commands:" -ForegroundColor Yellow
    Write-Host "  .\Release\rsatool.exe keygen --bits 3072 --pub pub.pem --priv priv.pem" -ForegroundColor White
    Write-Host "  .\Release\rsatool.exe encrypt --text 'Hello!' --pub pub.pem --out ct.bin" -ForegroundColor White
    Write-Host "  .\Release\rsatool.exe decrypt --in ct.bin --priv priv.pem --out msg.txt" -ForegroundColor White
} else {
    Write-Host "  rsatool.exe:         .\rsatool.exe" -ForegroundColor White
    Write-Host "  test_lab3.exe:       .\test_lab3.exe" -ForegroundColor White
    Write-Host "  benchmark_lab3.exe:  .\benchmark_lab3.exe" -ForegroundColor White
    Write-Host ""
    Write-Host "Quick test commands:" -ForegroundColor Yellow
    Write-Host "  .\rsatool.exe keygen --bits 3072 --pub pub.pem --priv priv.pem" -ForegroundColor White
    Write-Host "  .\rsatool.exe encrypt --text 'Hello!' --pub pub.pem --out ct.bin" -ForegroundColor White
    Write-Host "  .\rsatool.exe decrypt --in ct.bin --priv priv.pem --out msg.txt" -ForegroundColor White
}

Write-Host ""
