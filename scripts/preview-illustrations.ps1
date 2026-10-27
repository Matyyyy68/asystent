param([switch]$NewOnly)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$illustrations = Join-Path $repo 'media/illustrations'
$output = Join-Path $repo 'artifacts/illustration-previews'
New-Item -ItemType Directory -Force $output | Out-Null
Add-Type -AssemblyName System.Drawing

if ($NewOnly) {
  $plan = Get-Content (Join-Path $illustrations 'NEW_ASSETS_PLAN.md') -Raw
  $relative = [regex]::Matches($plan, '(?m)^\d+\. `([^`]+\.png)`') | ForEach-Object { $_.Groups[1].Value }
  $files = $relative | ForEach-Object { Join-Path $illustrations $_ }
} else {
  $files = Get-ChildItem -LiteralPath $illustrations -Recurse -Filter *.png | Sort-Object FullName | ForEach-Object FullName
}

$pageSize = 20; $columns = 5; $cellWidth = 320; $cellHeight = 180
$backgrounds = @(
  @{ Name = 'light'; Color = [System.Drawing.Color]::FromArgb(245, 247, 250) },
  @{ Name = 'dark'; Color = [System.Drawing.Color]::FromArgb(19, 28, 42) }
)
for ($page = 0; $page -lt [Math]::Ceiling($files.Count / $pageSize); $page++) {
  foreach ($background in $backgrounds) {
    $sheet = [System.Drawing.Bitmap]::new($columns * $cellWidth, 4 * $cellHeight)
    try {
      $graphics = [System.Drawing.Graphics]::FromImage($sheet)
      try {
        $graphics.Clear($background.Color)
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $font = New-Object System.Drawing.Font('Segoe UI', 9)
        $brush = New-Object System.Drawing.SolidBrush($(if ($background.Name -eq 'dark') { [System.Drawing.Color]::White } else { [System.Drawing.Color]::FromArgb(31, 41, 55) }))
        try {
          for ($slot = 0; $slot -lt $pageSize; $slot++) {
            $index = $page * $pageSize + $slot
            if ($index -ge $files.Count) { break }
            $x = ($slot % $columns) * $cellWidth
            $y = [Math]::Floor($slot / $columns) * $cellHeight
            $image = [System.Drawing.Image]::FromFile($files[$index])
            try { $graphics.DrawImage($image, [System.Drawing.Rectangle]::new($x + 24, $y + 4, 272, 150)) }
            finally { $image.Dispose() }
            $caption = [IO.Path]::GetRelativePath($illustrations, $files[$index])
            $graphics.DrawString($caption, $font, $brush, $x + 8, $y + 158)
          }
        } finally { $font.Dispose(); $brush.Dispose() }
      } finally { $graphics.Dispose() }
      $suffix = if ($NewOnly) { 'new-' } else { '' }
      $path = Join-Path $output ("{0}{1}-{2:D2}.png" -f $suffix, $background.Name, ($page + 1))
      $sheet.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally { $sheet.Dispose() }
  }
}
Write-Host "Created $($files.Count) illustration previews in $output"
