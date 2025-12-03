# Kinkntease GitHub Auto-Update Script v3.5
# This script downloads the latest files and prepares them for GitHub commit

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  KINKNTEASE GITHUB AUTO-UPDATER v3.5  " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Define paths
$repoPath = "C:\Users\peet.vanniekerk\Desktop\KNT FILES\kinkntease-github"
$tempPath = "$env:TEMP\kinkntease-update"

# Check if repo exists
if (-not (Test-Path $repoPath)) {
    Write-Host "ERROR: Repository not found at: $repoPath" -ForegroundColor Red
    Write-Host "Please check the path and try again." -ForegroundColor Red
    pause
    exit
}

Write-Host "Repository found: $repoPath" -ForegroundColor Green
Write-Host ""

# Create temp directory
Write-Host "Creating temporary directory..." -ForegroundColor Yellow
if (Test-Path $tempPath) {
    Remove-Item $tempPath -Recurse -Force
}
New-Item -ItemType Directory -Path $tempPath | Out-Null
New-Item -ItemType Directory -Path "$tempPath\backend" | Out-Null
New-Item -ItemType Directory -Path "$tempPath\frontend" | Out-Null

Write-Host "Downloading files from Claude..." -ForegroundColor Yellow
Write-Host ""

# Download backend file
Write-Host "[1/4] Downloading backend/index.php..." -ForegroundColor Cyan
try {
    # NOTE: These URLs need to be updated with actual download links
    # For now, this is a template showing the structure
    Write-Host "  (Skipping - requires manual download links from Claude)" -ForegroundColor Gray
    # Invoke-WebRequest -Uri "YOUR_BACKEND_URL_HERE" -OutFile "$tempPath\backend\index.php"
    # Write-Host "  SUCCESS!" -ForegroundColor Green
} catch {
    Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

# Download frontend files
Write-Host "[2/4] Downloading frontend/kinkntease-v4-CLEAR-LOGIN.html..." -ForegroundColor Cyan
Write-Host "  (Skipping - requires manual download links from Claude)" -ForegroundColor Gray

Write-Host "[3/4] Downloading frontend/favicon.svg..." -ForegroundColor Cyan
Write-Host "  (Skipping - requires manual download links from Claude)" -ForegroundColor Gray

Write-Host "[4/4] Downloading frontend/verify.html..." -ForegroundColor Cyan
Write-Host "  (Skipping - requires manual download links from Claude)" -ForegroundColor Gray

Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  NOTE: AUTO-DOWNLOAD NOT AVAILABLE    " -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Claude cannot provide direct download URLs due to security." -ForegroundColor Yellow
Write-Host "But we can make this easier! Here's what to do:" -ForegroundColor Yellow
Write-Host ""
Write-Host "OPTION 1: Download the ZIP file manually" -ForegroundColor Cyan
Write-Host "  - Download: kinkntease-github-update-v3.5.zip" -ForegroundColor White
Write-Host "  - Extract to Desktop" -ForegroundColor White
Write-Host "  - Run this script will copy files from there!" -ForegroundColor White
Write-Host ""
Write-Host "OPTION 2: Just use the ZIP method (recommended)" -ForegroundColor Cyan
Write-Host "  - Download ZIP (1 file)" -ForegroundColor White
Write-Host "  - Extract and copy (30 seconds)" -ForegroundColor White
Write-Host "  - Use GitHub Desktop (30 seconds)" -ForegroundColor White
Write-Host ""

# Ask if user has extracted the ZIP
Write-Host ""
$response = Read-Host "Have you extracted the ZIP file to Desktop? (y/n)"

if ($response -eq "y" -or $response -eq "Y") {
    $zipExtractPath = "C:\Users\peet.vanniekerk\Desktop\github-update-v3.5"
    
    if (Test-Path $zipExtractPath) {
        Write-Host ""
        Write-Host "Found extracted files! Copying to repository..." -ForegroundColor Green
        
        # Copy backend files
        Copy-Item "$zipExtractPath\backend\*" "$repoPath\backend\" -Force -Recurse
        Write-Host "  backend/index.php copied!" -ForegroundColor Green
        
        # Copy frontend files
        Copy-Item "$zipExtractPath\frontend\*" "$repoPath\frontend\" -Force -Recurse
        Write-Host "  frontend files copied!" -ForegroundColor Green
        
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  FILES UPDATED SUCCESSFULLY!           " -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "NEXT STEPS:" -ForegroundColor Cyan
        Write-Host "1. Open GitHub Desktop" -ForegroundColor White
        Write-Host "2. You should see 4 changed files" -ForegroundColor White
        Write-Host "3. Commit message: v3.5: Email verification, registration fixes, favicon" -ForegroundColor White
        Write-Host "4. Click 'Commit to main'" -ForegroundColor White
        Write-Host "5. Click 'Push origin'" -ForegroundColor White
        Write-Host ""
        Write-Host "Done! Press any key to exit..." -ForegroundColor Green
        pause
    } else {
        Write-Host ""
        Write-Host "Could not find: $zipExtractPath" -ForegroundColor Red
        Write-Host "Make sure you extracted the ZIP to Desktop!" -ForegroundColor Red
        Write-Host ""
        pause
    }
} else {
    Write-Host ""
    Write-Host "No problem! Download the ZIP file first, extract it, then run this script again." -ForegroundColor Yellow
    Write-Host ""
    pause
}
