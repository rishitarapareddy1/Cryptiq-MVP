# demo-reset.ps1 — Windows version: return everything to starting state
Write-Host "==> Destroying demo infra..."
Push-Location demo-infra
terraform destroy -auto-approve
Pop-Location

Write-Host "==> Clearing audit log..."
Remove-Item -Force out\audit.log -ErrorAction SilentlyContinue

Write-Host "==> Clearing scan databases..."
Remove-Item -Force cryptiq.db -ErrorAction SilentlyContinue
Remove-Item -Force ssh_scanner\ssh_scanner.db -ErrorAction SilentlyContinue

Write-Host "==> Done. Run 'terraform apply' in demo-infra\ to start fresh."
