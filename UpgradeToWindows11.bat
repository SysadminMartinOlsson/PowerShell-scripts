set SCRIPT="%~dp0Start-Windows11Upgrade.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -ArgumentList '-NoExit -ExecutionPolicy Bypass -File ""%SCRIPT%""' -Verb RunAs"
