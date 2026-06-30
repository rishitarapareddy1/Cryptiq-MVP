#!/usr/bin/env bash
# demo-reset.sh — return everything to the starting state after a demo
set -e

echo "==> Destroying demo infra..."
cd demo-infra
terraform destroy -auto-approve
cd ..

echo "==> Clearing audit log..."
rm -f out/audit.log

echo "==> Clearing scan databases..."
rm -f cryptiq.db ssh_scanner/ssh_scanner.db

echo "==> Done. Run 'terraform apply' in demo-infra/ when ready to demo again."
