# SecureBank — one-time GitHub publish script
# Run AFTER creating a Personal Access Token (PAT) at:
# https://github.com/settings/tokens  →  "Generate new token (classic)"  →  scope: repo

param(
    [Parameter(Mandatory = $true)]
    [string]$GitHubToken,

    [string]$RepoName = "SecureBank"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $ProjectRoot

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Write-Host "==> Authenticating GitHub CLI..."
$GitHubToken | gh auth login --hostname github.com --git-protocol https --with-token

Write-Host "==> Creating repository aliakhtermm1437-dev/$RepoName (public)..."
gh repo create $RepoName --public `
  --description "SecureBank: cloud-native DevSecOps banking platform — CYC386 COMSATS Spring 2026" `
  --source . --remote origin --push

Write-Host "==> Pushing release tag..."
git push origin v1.0.0-exam

Write-Host "==> Setting repository topics..."
gh repo edit --add-topic devsecops,kubernetes-security,zero-trust,oauth2,fastapi,docker-security,terraform,owasp-asvs,comsats-university

Write-Host ""
Write-Host "DONE! Repository URL:"
gh repo view --json url -q .url
