param([int]$DialogHwnd = 0, [string]$ClickText = "")
$signature = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class Dlg {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumWindowsProc cb, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
}
'@
Add-Type -TypeDefinition $signature
$target = [IntPtr]$DialogHwnd
if ($target -eq [IntPtr]::Zero) { Write-Output "no dialog hwnd"; exit 1 }
$script:buttons = @()
$script:children = @()
$cb = {
    param($h, $l)
    $c = New-Object System.Text.StringBuilder 256
    [Dlg]::GetClassName($h, $c, 256) | Out-Null
    $t = New-Object System.Text.StringBuilder 256
    [Dlg]::GetWindowText($h, $t, 256) | Out-Null
    $cls = $c.ToString(); $txt = $t.ToString()
    $script:children += ("child HWND=$h CLASS=$cls TEXT=$txt")
    if ($cls -eq "Button") { $script:buttons += [pscustomobject]@{Hwnd=$h; Text=$txt} }
    return $true
}
[Dlg]::EnumChildWindows($target, $cb, [IntPtr]::Zero) | Out-Null
$script:children | ForEach-Object { Write-Output $_ }
if ($ClickText -ne "") {
    foreach ($b in $script:buttons) {
        if ($b.Text -like "*$ClickText*") {
            [Dlg]::SendMessage($b.Hwnd, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null  # BM_CLICK
            Write-Output ("clicked: " + $b.Text)
            return
        }
    }
    Write-Output "button not found: $ClickText"
}
