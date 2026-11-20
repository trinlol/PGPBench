# Capture PGPBench screenshots WITHOUT depending on what's on top:
#   PrintWindow  - reads the window's own pixels (works while occluded)
#   PostMessage  - clicks the tab inside the app (never touches the real cursor)
# Then verifies the result with pixel checks, since the operator can't view images.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
if (-not ("WinPix" -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class WinPix {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    public delegate bool EnumProc(IntPtr h, IntPtr lp);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lp);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr lp);
    [DllImport("user32.dll")] static extern int GetClassName(IntPtr h, StringBuilder sb, int max);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
    public static IntPtr FindTop() {
        IntPtr found = IntPtr.Zero;
        EnumWindows((h, lp) => {
            var c = new StringBuilder(256); GetClassName(h, c, 256);
            if (c.ToString() == "Tauri Window" && IsWindowVisible(h)) { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static IntPtr FindChild(IntPtr parent) {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(parent, (h, lp) => {
            var c = new StringBuilder(256); GetClassName(h, c, 256);
            if (c.ToString() == "Chrome_WidgetWin_1") { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static void ClickChild(IntPtr child, int x, int y) {
        IntPtr lp = (IntPtr)((y << 16) | (x & 0xFFFF));
        PostMessage(child, 0x0201, (IntPtr)0x0001, lp);  // WM_LBUTTONDOWN, MK_LBUTTON
        PostMessage(child, 0x0202, IntPtr.Zero, lp);     // WM_LBUTTONUP
    }
}
"@
}

function Capture-Window([IntPtr]$hwnd, [int]$w, [int]$hgt, [string]$path) {
    $bmp = New-Object System.Drawing.Bitmap($w, $hgt)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    # 3 = PW_CLIENTONLY | PW_RENDERFULLCONTENT (DirectComposition / WebView2)
    [WinPix]::PrintWindow($hwnd, $hdc, 3) | Out-Null
    $g.ReleaseHdc($hdc)
    $g.Dispose()
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    return $bmp
}

$h = [WinPix]::FindTop()
if ($h -eq [IntPtr]::Zero) { throw "Tauri window not found" }
$child = [WinPix]::FindChild($h)
if ($child -eq [IntPtr]::Zero) { throw "WebView2 child not found" }
$r = New-Object WinPix+RECT
[WinPix]::GetClientRect($h, [ref]$r) | Out-Null
$w = $r.Right - $r.Left; $hgt = $r.Bottom - $r.Top
Write-Host "window ${w}x${hgt}, webview child: $child"

# --- workbench ---
$bmp1 = Capture-Window $h $w $hgt "$PWD\docs\shot-workbench.png"
# The app content is max-w-5xl (1024) centered in the 1080 window: 28px margin,
# then px-4 padding: the 32x32 logo square spans ~(44..76, 16..48). Its center
# carries a white key glyph, so scan the box for the indigo/violet gradient.
$logoIndigo = $false
$bg = $bmp1.GetPixel(900, 300)         # empty surface, dark mode
for ($x = 42; $x -le 78 -and -not $logoIndigo; $x += 2) {
    for ($y = 14; $y -le 50; $y += 2) {
        $p = $bmp1.GetPixel($x, $y)
        if ($p.B -gt 140 -and ($p.B - $p.G) -gt 50) { $logoIndigo = $true; break }
    }
}
Write-Host ("logo has indigo gradient: {0}   bg RGB: {1},{2},{3}" -f $logoIndigo, $bg.R, $bg.G, $bg.B)
$logoOk = $logoIndigo
$bgOk = ($bg.R -lt 45) -and ($bg.G -lt 45) -and ($bg.B -lt 45)
if (-not ($logoOk -and $bgOk)) {
    Write-Host "PrintWindow content check FAILED (logoOk=$logoOk bgOk=$bgOk) - trying foreground restore"
    [WinPix]::ShowWindow($h, 6) | Out-Null   # SW_MINIMIZE
    Start-Sleep -Milliseconds 400
    [WinPix]::ShowWindow($h, 9) | Out-Null   # SW_RESTORE
    $deadline = (Get-Date).AddSeconds(5)
    while ((Get-Date) -lt $deadline -and [WinPix]::GetForegroundWindow() -ne $h) { Start-Sleep -Milliseconds 200 }
    $bmp1.Dispose()
    $bmp1 = Capture-Window $h $w $hgt "$PWD\docs\shot-workbench.png"
    $logoIndigo = $false
    for ($x = 42; $x -le 78 -and -not $logoIndigo; $x += 2) {
        for ($y = 14; $y -le 50; $y += 2) {
            $p = $bmp1.GetPixel($x, $y)
            if ($p.B -gt 140 -and ($p.B - $p.G) -gt 50) { $logoIndigo = $true; break }
        }
    }
    $logoOk = $logoIndigo
    if (-not $logoOk) { throw "capture still not showing the app UI" }
    Write-Host "foreground-restore capture passed"
} else {
    Write-Host "PrintWindow capture verified (logo + dark background)"
}

# --- switch to Keys via window message (no real cursor movement) ---
[WinPix]::ClickChild($child, 796, 102)
Start-Sleep -Seconds 2
$bmp2 = Capture-Window $h $w $hgt "$PWD\docs\shot-keys.png"

# --- verify the tab actually switched: sample the surface below the nav ---
$same = 0; $diff = 0
$rand = New-Object System.Random(7)
for ($i = 0; $i -lt 250; $i++) {
    $x = $rand.Next(60, $w - 60)
    $y = $rand.Next(140, $hgt - 20)
    $p1 = $bmp1.GetPixel($x, $y)
    $p2 = $bmp2.GetPixel($x, $y)
    if ([Math]::Abs($p1.R - $p2.R) -gt 25 -or [Math]::Abs($p1.G - $p2.G) -gt 25 -or [Math]::Abs($p1.B - $p2.B) -gt 25) { $diff++ } else { $same++ }
}
$bmp1.Dispose(); $bmp2.Dispose()
$pct = [Math]::Round(100 * $diff / 250, 1)
Write-Host "surface pixel change: $diff/250 ($pct%)"
if ($diff -lt 60) {
    Write-Host "tab click may have missed - retrying at adjusted coords"
    [WinPix]::ClickChild($child, 800, 100)
    Start-Sleep -Seconds 2
    $bmp1 = Capture-Window $h $w $hgt "$PWD\docs\tmp1.png"
    $bmp2 = Capture-Window $h $w $hgt "$PWD\docs\shot-keys.png"
    $same = 0; $diff = 0
    for ($i = 0; $i -lt 250; $i++) {
        $x = $rand.Next(60, $w - 60); $y = $rand.Next(140, $hgt - 20)
        $p1 = $bmp1.GetPixel($x, $y); $p2 = $bmp2.GetPixel($x, $y)
        if ([Math]::Abs($p1.R - $p2.R) -gt 25 -or [Math]::Abs($p1.G - $p2.G) -gt 25 -or [Math]::Abs($p1.B - $p2.B) -gt 25) { $diff++ }
    }
    $bmp1.Dispose(); $bmp2.Dispose()
    $pct = [Math]::Round(100 * $diff / 250, 1)
    Write-Host "retry surface pixel change: $diff/250 ($pct%)"
    Remove-Item "$PWD\docs\tmp1.png" -Force
}
if ($diff -lt 60) { Write-Host "WARNING: Keys tab switch unverified" } else { Write-Host "Keys tab switch verified" }

Get-ChildItem docs\*.png | Select-Object Name, @{N="KB";E={[math]::Round($_.Length/1KB,1)}} | Format-Table -AutoSize | Out-String