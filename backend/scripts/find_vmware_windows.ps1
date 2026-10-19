param([int]$TargetPid = 0)
$signature = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class Win32Enum2 {
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumWindowsProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
}
'@
Add-Type -TypeDefinition $signature
$pids = @(Get-Process vmware,vmware-vmx -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
Write-Output ("watch pids: " + ($pids -join ","))
$script:found = @()
$cb = {
    param($h, $l)
    [uint32]$procId = 0
    [Win32Enum2]::GetWindowThreadProcessId($h, [ref]$procId) | Out-Null
    if ($pids -contains $procId -and [Win32Enum2]::IsWindowVisible($h)) {
        $sb = New-Object System.Text.StringBuilder 512
        [Win32Enum2]::GetClassName($h, $sb, 512) | Out-Null
        $tb = New-Object System.Text.StringBuilder 512
        [Win32Enum2]::GetWindowText($h, $tb, 512) | Out-Null
        $script:found += "PID=$procId HWND=$h CLASS=$($sb.ToString()) TITLE=$($tb.ToString())"
    }
    return $true
}
[Win32Enum2]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
$script:found | ForEach-Object { Write-Output $_ }
