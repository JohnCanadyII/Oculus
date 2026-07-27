# Oculus daily runner (Windows) — scrape the latest news, then email the digest.
# Scheduled to run every day at 7am via Task Scheduler (see setup below).
#
# ── One-time setup ────────────────────────────────────────────────────────────
# 1. Install Python 3.10+ (check "Add python.exe to PATH"), then in the repo:
#       py -m pip install -e .
# 2. Store your SMTP password as a USER env var (so it isn't in this file):
#       setx OCULUS_SMTP_PASSWORD "your-gmail-app-password"
#    (Gmail: create an App Password at https://myaccount.google.com/apppasswords —
#     requires 2-Step Verification. Use that 16-char password, not your login one.)
# 3. Create C:\Users\<you>\.config\oculus\config.yaml with your email block
#    (see config.example.yaml).
# 4. (Optional, for AI summaries) install Ollama and: ollama pull qwen2.5:3b
#
# ── Schedule it at 7am daily (run once, in PowerShell) ────────────────────────
#   $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
#     -Argument '-NoProfile -ExecutionPolicy Bypass -File "D:\oculus\extracted\oculus\packaging\oculus-daily.ps1"'
#   $trigger = New-ScheduledTaskTrigger -Daily -At 7am
#   Register-ScheduledTask -TaskName "Oculus Daily Digest" -Action $action -Trigger $trigger `
#     -Description "Daily 7am security + enterprise-tech intelligence email"
#
# Test it now without waiting for 7am:
#   Start-ScheduledTask -TaskName "Oculus Daily Digest"

$ErrorActionPreference = "Stop"
$repo = "D:\oculus\extracted\oculus"      # <-- change if you move the project
Set-Location $repo

$log = Join-Path $repo "oculus-daily.log"
"$(Get-Date -Format o)  starting daily run" | Out-File -Append $log

try {
    py -m oculus scrape   2>&1 | Out-File -Append $log
    py -m oculus email    2>&1 | Out-File -Append $log
    "$(Get-Date -Format o)  done" | Out-File -Append $log
} catch {
    "$(Get-Date -Format o)  ERROR: $_" | Out-File -Append $log
    throw
}
