function Select-ArrowMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [Parameter(Mandatory = $true)]
        [string[]]$Options,
        [switch]$MultiSelect,
        [switch]$AllowSelectAll
    )

    if (-not $Options -or $Options.Count -eq 0) {
        return @()
    }

    if ([Console]::IsInputRedirected -or -not [Environment]::UserInteractive) {
        Write-Host $Title -ForegroundColor Cyan
        for ($i = 0; $i -lt $Options.Count; $i++) {
            Write-Host "[$($i + 1)] $($Options[$i])"
        }

        if ($MultiSelect) {
            $selection = Read-Host "Selection (comma-separated numbers or 'all')"
            if ($selection -match '^\s*all\s*$') {
                return $Options
            }

            $indices = $selection -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ - 1 } | Where-Object { $_ -ge 0 -and $_ -lt $Options.Count } | Select-Object -Unique
            return $indices | ForEach-Object { $Options[$_] }
        }

        $selection = Read-Host "Selection (number)"
        if ($selection -match '^\d+$') {
            $index = [int]$selection - 1
            if ($index -ge 0 -and $index -lt $Options.Count) {
                return $Options[$index]
            }
        }

        return $null
    }

    $selected = @{}
    $currentIndex = 0

    if ($MultiSelect) {
        $instructions = "Use Up/Down to move, Space to toggle, Enter to confirm."
        if ($AllowSelectAll) {
            $instructions += " Press A to select all."
        }
    } else {
        $instructions = "Use Up/Down to move, Enter to confirm."
    }

    while ($true) {
        Clear-Host
        Write-Host $Title -ForegroundColor Cyan
        Write-Host $instructions -ForegroundColor DarkGray

        $maxRows = [Math]::Max([Console]::WindowHeight - 6, 1)
        $windowStart = 0
        $windowEnd = $Options.Count - 1

        if ($Options.Count -gt $maxRows) {
            $windowStart = [Math]::Max(0, [Math]::Min($currentIndex - [int]($maxRows / 2), $Options.Count - $maxRows))
            $windowEnd = [Math]::Min($Options.Count - 1, $windowStart + $maxRows - 1)
            Write-Host "Showing $($windowStart + 1)-$($windowEnd + 1) of $($Options.Count)" -ForegroundColor DarkGray
        }

        for ($i = $windowStart; $i -le $windowEnd; $i++) {
            $isCurrent = $i -eq $currentIndex
            $prefix = if ($isCurrent) { ">" } else { " " }

            if ($MultiSelect) {
                $isSelected = $selected.ContainsKey($i) -and $selected[$i]
                $mark = if ($isSelected) { "[x]" } else { "[ ]" }
                $line = "$prefix $mark $($Options[$i])"
            } else {
                $line = "$prefix $($Options[$i])"
            }

            if ($isCurrent) {
                Write-Host $line -ForegroundColor Yellow
            } else {
                Write-Host $line
            }
        }

        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            "UpArrow" {
                $currentIndex--
                if ($currentIndex -lt 0) {
                    $currentIndex = $Options.Count - 1
                }
            }
            "DownArrow" {
                $currentIndex++
                if ($currentIndex -ge $Options.Count) {
                    $currentIndex = 0
                }
            }
            "Home" { $currentIndex = 0 }
            "End" { $currentIndex = $Options.Count - 1 }
            "Spacebar" {
                if ($MultiSelect) {
                    $selected[$currentIndex] = -not ($selected.ContainsKey($currentIndex) -and $selected[$currentIndex])
                }
            }
            "A" {
                if ($AllowSelectAll -and $MultiSelect) {
                    for ($i = 0; $i -lt $Options.Count; $i++) {
                        $selected[$i] = $true
                    }
                }
            }
            "Escape" { return @() }
            "Enter" { break }
        }
    }

    if ($MultiSelect) {
        $indices = $selected.Keys | Where-Object { $selected[$_] } | Sort-Object
        return $indices | ForEach-Object { $Options[$_] }
    }

    return $Options[$currentIndex]
}
