$pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
$pipes | Where-Object { $_ -match "openwrt" }
Write-Output ("total pipes: " + $pipes.Count)
