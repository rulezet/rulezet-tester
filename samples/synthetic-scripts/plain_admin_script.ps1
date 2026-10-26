Get-ChildItem -Path C:\Logs -Filter *.log | Where-Object { $_.Length -gt 1MB } | Select-Object Name, Length
