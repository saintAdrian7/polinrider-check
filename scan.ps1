<#
.SYNOPSIS
    PolinRider check — scans a folder, its git repositories and this machine for
    the PolinRider / TasksJacker malware. Read-only: it changes nothing.

.DESCRIPTION
    Six checks:
      1. Payload hidden in files (any tracked text file, not only configs): known
         signature strings, the family's structural traits, a giant line hidden
         behind whitespace padding, the ESM `createRequire` shim, and text files
         disguised as fonts (.woff/.woff2/.ttf/.eot that are not real fonts).
      2. Git repository artifacts: temp_auto_push.bat, temp_interactive_push.bat,
         config.bat, branch_structure.json, injected .gitignore lines, amended
         commits in the reflog.
      3. .vscode/tasks.json tasks that run on folder open and download or execute
         something (TasksJacker), including the known C2 hosts.
      4. package.json dependencies on the actor's npm packages.
      5. This machine: tampered npm CLI, global npm packages, Run keys and
         scheduled tasks that reference the malware's files, the lock file it
         leaves in Temp.
      6. With -Remote: every remote branch of every repository found, read
         straight from git objects (nothing is checked out, so a payload can't
         run). The payload is usually force-pushed to the remote while the local
         checkout stays clean, so a local-only scan can miss an infected repo.

.PARAMETER Path
    Folder to scan. Defaults to the current folder.

.PARAMETER Remote
    Also fetch and scan every remote branch of each repository found.

.PARAMETER SkipMachine
    Skip the machine-wide checks (npm CLI, Run keys, scheduled tasks).

.EXAMPLE
    .\scan.ps1
    .\scan.ps1 C:\Projects
    .\scan.ps1 C:\Projects -Remote

.NOTES
    Exit codes: 0 clean, 1 findings, 2 bad path.
    Works on Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [string]$Path = "",
    [switch]$Remote,
    [switch]$SkipMachine
)

$ErrorActionPreference = "Continue"
$VERSION = "2.0.0"

# ---------------------------------------------------------------- indicators

# Exact strings seen in payloads. Each build of the malware uses new constants,
# so these catch known builds only; the structural checks below catch the rest.
$SIGNATURE_LITERALS = @(
    '("rmcej%otb%",2857687)',
    "global['!']='8-",
    '("Cot%3t=shtP",1111436)',
    "global['_V']='8-",
    'global.i="A10'
)

# Traits shared across builds of the family.
$SIGNATURE_REGEX = @(
    'global\s*\.\s*i\s*=\s*["'']A\d+',
    'global\s*\[\s*["''][^"'']{1,4}["'']\s*\]\s*=\s*["'']\d+-',
    "global\s*\[\s*['""]r['""]\s*\]\s*=\s*require",
    '\)\)\s*;\s*\}\s*run\s*\(\s*\)\s*;?\s*$'
)

# The payload is appended to the end of a real line after hundreds of spaces, so
# an editor shows nothing unless you scroll far right. This shape has survived
# every rewrite so far.
$MIN_PAYLOAD_LINE = 2000
$MIN_PADDING_RUN  = 200

# Files the malware drops into a repository, and the .gitignore lines it adds to
# hide them (the lines outlive the files).
$REPO_ARTIFACTS = @(
    "temp_auto_push.bat",
    "temp_interactive_push.bat",
    "config.bat",
    "branch_structure.json"
)
$GITIGNORE_INJECTED = '^\s*(config\.bat|temp-auto\.bat|temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json)\s*$'

# TasksJacker command-and-control hosts and template marker.
$C2_HOSTS = @(
    "260120.vercel.app",
    "default-configuration.vercel.app",
    "vscode-settings-bootstrap.vercel.app",
    "vscode-settings-config.vercel.app",
    "vscode-bootstrapper.vercel.app",
    "vscode-load-config.vercel.app"
)
$STAKINGGAME_UUID = "e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9"

# npm packages published by the actor as droppers.
$MALICIOUS_PACKAGES = @(
    "tailwindcss-style-animate",
    "tailwind-mainanimation",
    "tailwind-autoanimation",
    "tailwind-animationbased",
    "tailwindcss-typography-style",
    "tailwindcss-style-modify",
    "tailwindcss-animate-style"
)

# A clean npm `lib/cli.js` is a few hundred bytes; an infected one carries the
# payload and is over a megabyte, and re-spawns the malware on every npm run.
$NPM_CLI_MAX_CLEAN_BYTES = 5000

$SKIP_DIRS   = @("node_modules", ".git", ".next", "dist", "build", "coverage", ".cache", "vendor")
$MAX_FILE_MB = 20

# ---------------------------------------------------------------- state

$script:Findings = New-Object System.Collections.Generic.List[string]
$script:RepoCount = 0
$selfDir = $PSScriptRoot

function Add-Finding ([string]$Kind, [string]$Where, [string]$Detail) {
    $script:Findings.Add("$Kind|$Where|$Detail")
    Write-Host "  [!] " -ForegroundColor Red -NoNewline
    Write-Host "$Where" -NoNewline
    Write-Host "  -  $Detail" -ForegroundColor Red
}

function Write-Section ([string]$Text) {
    Write-Host ""
    Write-Host $Text -ForegroundColor Cyan
}

function Test-SkippedPath ([string]$FullPath) {
    foreach ($d in $SKIP_DIRS) {
        if ($FullPath -match ('[\\/]' + [regex]::Escape($d) + '[\\/]')) { return $true }
    }
    if ($selfDir -and $FullPath.StartsWith($selfDir, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true   # this tool's own files contain the indicator strings
    }
    return $false
}

# ---------------------------------------------------------------- content checks

# Returns a description of what matched, or $null. Works on a string so the same
# logic serves files on disk and blobs read from git.
function Find-Payload ([string]$Content, [string]$Name) {
    $hits = New-Object System.Collections.Generic.List[string]

    foreach ($lit in $SIGNATURE_LITERALS) {
        if ($Content.Contains($lit)) { $hits.Add("signature '$lit'") }
    }
    foreach ($rx in $SIGNATURE_REGEX) {
        if ([regex]::IsMatch($Content, $rx, 'Multiline')) { $hits.Add("trait /$rx/") }
    }

    $lineNo = 0
    foreach ($line in ($Content -split "`n")) {
        $lineNo++
        if ($line.Length -ge $MIN_PAYLOAD_LINE -and $line -match "\s{$MIN_PADDING_RUN,}\S") {
            $hits.Add("line $lineNo is $($line.Length) chars, hidden behind whitespace padding")
            break
        }
    }

    # In .mjs configs the payload needs CommonJS require, so it injects this shim
    # at the top. A plain PostCSS/Tailwind/ESLint config never needs it.
    if ($Name -match '\.(mjs|config\.(js|ts))$' -and $Content -match 'createRequire\s*\(\s*import\.meta\.url\s*\)') {
        $hits.Add("createRequire(import.meta.url) shim (left behind when the payload is cut off the bottom)")
    }

    if ($hits.Count -eq 0) { return $null }
    return ($hits -join "; ")
}

function Test-IsBinary ([byte[]]$Bytes) {
    $n = [Math]::Min($Bytes.Length, 8000)
    for ($i = 0; $i -lt $n; $i++) { if ($Bytes[$i] -eq 0) { return $true } }
    return $false
}

# Real font magic numbers. A "font" that is text is the malware's disguise.
function Test-IsRealFont ([byte[]]$Bytes) {
    if ($Bytes.Length -lt 4) { return $false }
    $head = [System.Text.Encoding]::ASCII.GetString($Bytes, 0, 4)
    if ($head -eq "wOF2" -or $head -eq "wOFF" -or $head -eq "OTTO" -or $head -eq "true" -or $head -eq "ttcf") { return $true }
    if ($Bytes[0] -eq 0 -and $Bytes[1] -eq 1 -and $Bytes[2] -eq 0 -and $Bytes[3] -eq 0) { return $true }   # TrueType
    if ($Bytes.Length -ge 36 -and $Bytes[34] -eq 0x4C -and $Bytes[35] -eq 0x50) { return $true }          # EOT 'LP'
    return $false
}

function Invoke-FileScan ([string]$Root) {
    Write-Section "1. Payload hidden in files"
    $before = $script:Findings.Count
    $files = Get-ChildItem -Path $Root -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { -not (Test-SkippedPath $_.FullName) -and $_.Length -le ($MAX_FILE_MB * 1MB) -and $_.Length -gt 0 }

    foreach ($f in $files) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
        } catch { continue }

        $isFont = $f.Extension -match '^\.(woff2?|ttf|otf|eot)$'
        if ($isFont) {
            if (-not (Test-IsRealFont $bytes) -and -not (Test-IsBinary $bytes)) {
                Add-Finding "payload" $f.FullName "not a real font: a text file disguised as one ($($f.Length) bytes). The whole file is the payload."
            }
            continue
        }
        if (Test-IsBinary $bytes) { continue }
        if ($f.Extension -match '^\.(md|txt|lock|map|svg|csv|log)$') { continue }

        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        $hit = Find-Payload $text $f.Name
        if ($hit) { Add-Finding "payload" $f.FullName $hit }
    }
    if ($script:Findings.Count -eq $before) { Write-Host "  clean" -ForegroundColor Green }
}

# ---------------------------------------------------------------- repositories

function Get-GitRepos ([string]$Root) {
    Get-ChildItem -Path $Root -Recurse -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq ".git" -and -not ($_.FullName -match '[\\/]node_modules[\\/]') } |
        ForEach-Object { $_.Parent.FullName }
    if (Test-Path (Join-Path $Root ".git")) { $Root }
}

function Invoke-RepoArtifactScan ([string[]]$Repos) {
    Write-Section "2. Git repository artifacts ($($Repos.Count) repositories)"
    $before = $script:Findings.Count
    foreach ($repo in $Repos) {
        $hadFinding = $false
        foreach ($name in $REPO_ARTIFACTS) {
            if (Test-Path (Join-Path $repo $name)) {
                Add-Finding "artifact" (Join-Path $repo $name) "malware file present"
                $hadFinding = $true
            }
        }
        $gi = Join-Path $repo ".gitignore"
        if (Test-Path $gi) {
            $lines = Get-Content $gi -ErrorAction SilentlyContinue | Where-Object { $_ -match $GITIGNORE_INJECTED }
            foreach ($l in $lines) {
                Add-Finding "artifact" $gi "injected line '$($l.Trim())' (hides the malware's files)"
                $hadFinding = $true
            }
        }
        # Only meaningful alongside another finding: people amend commits too.
        if ($hadFinding) {
            $reflog = & git -C $repo reflog 2>$null
            if ($reflog -match "commit \(amend\)") {
                Add-Finding "artifact" $repo "reflog has amended commits (temp_auto_push.bat amends the last commit with a rewound clock)"
            }
        }
    }
    if ($script:Findings.Count -eq $before) { Write-Host "  clean" -ForegroundColor Green }
}

# ---------------------------------------------------------------- tasks.json

function Invoke-TasksJsonScan ([string]$Root) {
    Write-Section "3. VS Code tasks that run on folder open"
    $before = $script:Findings.Count
    $tasks = Get-ChildItem -Path $Root -Recurse -File -Force -Filter "tasks.json" -ErrorAction SilentlyContinue |
        Where-Object { $_.Directory.Name -eq ".vscode" -and -not (Test-SkippedPath $_.FullName) }
    foreach ($t in $tasks) {
        $c = Get-Content $t.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $c) { continue }
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($h in $C2_HOSTS) { if ($c.Contains($h)) { $hits.Add("C2 host $h") } }
        if ($c.Contains($STAKINGGAME_UUID)) { $hits.Add("StakingGame template UUID") }
        if ($c -match 'folderOpen') {
            if ($c -match 'curl|wget|Invoke-WebRequest|iwr\s|certutil') { $hits.Add("runs on folderOpen and downloads something") }
            if ($c -match 'node\s+[^"\r\n]*\.(woff2?|ttf|eot|otf|png|jpg)') { $hits.Add("runs on folderOpen and executes a 'font'/'image' file with node") }
            if ($c -match 'temp_auto_push|config\.bat') { $hits.Add("runs on folderOpen and calls a malware script") }
        }
        if ($hits.Count -gt 0) { Add-Finding "tasks" $t.FullName ($hits -join "; ") }
    }
    if ($script:Findings.Count -eq $before) { Write-Host "  clean" -ForegroundColor Green }
}

# ---------------------------------------------------------------- package.json

function Invoke-PackageScan ([string]$Root) {
    Write-Section "4. Malicious npm packages in package.json"
    $before = $script:Findings.Count
    $pkgs = Get-ChildItem -Path $Root -Recurse -File -Filter "package.json" -ErrorAction SilentlyContinue |
        Where-Object { -not (Test-SkippedPath $_.FullName) }
    foreach ($p in $pkgs) {
        $c = Get-Content $p.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $c) { continue }
        $hits = @($MALICIOUS_PACKAGES | Where-Object { $c.Contains('"' + $_ + '"') })
        if ($hits.Count -gt 0) { Add-Finding "package" $p.FullName ("depends on " + ($hits -join ", ")) }
    }
    if ($script:Findings.Count -eq $before) { Write-Host "  clean" -ForegroundColor Green }
}

# ---------------------------------------------------------------- machine

function Invoke-MachineScan {
    Write-Section "5. This machine"
    $before = $script:Findings.Count

    # npm CLI entry point
    $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
    if ($npmCmd) {
        $prefix = & npm prefix -g 2>$null
        $candidates = @()
        if ($prefix) { $candidates += (Join-Path $prefix "node_modules\npm\lib\cli.js") }
        $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
        if ($nodeCmd) { $candidates += (Join-Path (Split-Path $nodeCmd.Source) "node_modules\npm\lib\cli.js") }
        foreach ($cli in ($candidates | Select-Object -Unique)) {
            if (Test-Path $cli) {
                $len = (Get-Item $cli).Length
                if ($len -gt $NPM_CLI_MAX_CLEAN_BYTES) {
                    Add-Finding "machine" $cli "npm CLI is $len bytes (clean is a few hundred): the malware re-spawns from here on every npm command"
                } else {
                    Write-Host "  npm CLI $cli is $len bytes, normal" -ForegroundColor DarkGray
                }
            }
        }
        # global packages
        $globalList = & npm ls -g --depth=0 --json 2>$null | Out-String
        foreach ($m in $MALICIOUS_PACKAGES) {
            if ($globalList.Contains('"' + $m + '"')) { Add-Finding "machine" "npm global" "malicious package $m installed globally" }
        }
    } else {
        Write-Host "  npm not found on PATH, skipping npm checks" -ForegroundColor DarkGray
    }

    if ($IsWindowsHost) {
        foreach ($key in @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                           "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                           "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                           "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce")) {
            $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -like "PS*") { continue }
                $v = [string]$p.Value
                if ($v -match 'temp_auto_push|config\.bat|\.woff2?|branch_structure|vercel\.app') {
                    Add-Finding "machine" "$key\$($p.Name)" "startup entry runs: $v"
                }
            }
        }
        try {
            $tasksOut = & schtasks /query /fo LIST /v 2>$null | Out-String
            foreach ($blk in ($tasksOut -split "(?m)^\s*$")) {
                if ($blk -match 'temp_auto_push|config\.bat|\.woff2?|vercel\.app|branch_structure') {
                    $name = ([regex]::Match($blk, 'TaskName:\s*(.+)')).Groups[1].Value.Trim()
                    Add-Finding "machine" "scheduled task $name" "references the malware's files"
                }
            }
        } catch { }
        $lock = Join-Path $env:LOCALAPPDATA "Temp\tmp7A863DD1.tmp"
        if (Test-Path $lock) { Add-Finding "machine" $lock "known PolinRider lock file" }
    } else {
        $crons = & crontab -l 2>$null | Out-String
        if ($crons -match 'temp_auto_push|\.woff2?|vercel\.app') { Add-Finding "machine" "crontab" "entry references the malware's files" }
        foreach ($dir in @("$HOME/Library/LaunchAgents", "$HOME/.config/autostart")) {
            if (Test-Path $dir) {
                Get-ChildItem $dir -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $c = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                    if ($c -and $c -match 'temp_auto_push|\.woff2?|vercel\.app|branch_structure') { Add-Finding "machine" $_.FullName "startup item references the malware's files" }
                }
            }
        }
    }
    if ($script:Findings.Count -eq $before) { Write-Host "  clean" -ForegroundColor Green }
}

# ---------------------------------------------------------------- remote branches

# Reads blobs straight from git objects. Nothing is checked out, so an infected
# config is never executed. Blob SHAs are taken from ls-tree, which avoids the
# "ref:path" form that some shells mangle.
function Invoke-RemoteScan ([string[]]$Repos) {
    Write-Section "6. Remote branches (fetching; this can take a while)"
    $before = $script:Findings.Count
    $nameFilter = '(\.config\.(js|mjs|cjs|ts)|^(app|App|index|truffle)\.js|\.woff2?|\.gitignore|tasks\.json|package\.json|temp_auto_push\.bat|temp_interactive_push\.bat|config\.bat|branch_structure\.json)$'
    foreach ($repo in $Repos) {
        $remotes = & git -C $repo remote 2>$null
        if (-not $remotes) { continue }
        Write-Host "  $repo" -ForegroundColor DarkGray
        & git -C $repo fetch --all --prune --quiet 2>$null
        $refs = & git -C $repo for-each-ref --format='%(refname)' refs/remotes 2>$null | Where-Object { $_ -and $_ -notmatch '/HEAD$' }
        foreach ($ref in $refs) {
            $entries = & git -C $repo ls-tree -r $ref 2>$null
            foreach ($e in $entries) {
                # <mode> <type> <sha>\t<path>
                $parts = $e -split "`t", 2
                if ($parts.Count -lt 2) { continue }
                $path = $parts[1]
                $leaf = Split-Path $path -Leaf
                if ($leaf -notmatch $nameFilter -or $path -match '(^|/)node_modules/') { continue }
                $sha = ($parts[0] -split ' ')[2]
                $size = [int](& git -C $repo cat-file -s $sha 2>$null)
                if ($size -le 0 -or $size -gt ($MAX_FILE_MB * 1MB)) { continue }
                $raw = & git -C $repo cat-file -p $sha 2>$null | Out-String
                $where = "$repo  $ref : $path"
                if ($leaf -in $REPO_ARTIFACTS) { Add-Finding "remote" $where "malware file present on this branch"; continue }
                if ($leaf -eq ".gitignore") {
                    foreach ($l in ($raw -split "`n")) { if ($l -match $GITIGNORE_INJECTED) { Add-Finding "remote" $where "injected line '$($l.Trim())'" } }
                    continue
                }
                if ($leaf -eq "package.json") {
                    $hits = @($MALICIOUS_PACKAGES | Where-Object { $raw.Contains('"' + $_ + '"') })
                    if ($hits.Count -gt 0) { Add-Finding "remote" $where ("depends on " + ($hits -join ", ")) }
                    continue
                }
                if ($leaf -eq "tasks.json") {
                    if (($raw -match 'folderOpen') -and ($raw -match 'curl|wget|node\s+[^"\r\n]*\.(woff2?|ttf)|vercel\.app')) { Add-Finding "remote" $where "task runs on folderOpen and downloads/executes" }
                    continue
                }
                if ($leaf -match '\.woff2?$') {
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
                    if (-not (Test-IsRealFont $bytes) -and -not (Test-IsBinary $bytes)) { Add-Finding "remote" $where "text file disguised as a font ($size bytes)" }
                    continue
                }
                $hit = Find-Payload $raw $leaf
                if ($hit) { Add-Finding "remote" $where $hit }
            }
        }
    }
    if ($script:Findings.Count -eq $before) { Write-Host "  clean" -ForegroundColor Green }
}

# ---------------------------------------------------------------- entry point

$IsWindowsHost = ($PSVersionTable.PSVersion.Major -lt 6) -or [bool](Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)

if ([string]::IsNullOrEmpty($Path)) { $Path = (Get-Location).Path }
try { $Path = (Convert-Path $Path) } catch { Write-Error "Folder not found: $Path"; exit 2 }
if (-not (Test-Path $Path -PathType Container)) { Write-Error "Not a folder: $Path"; exit 2 }

Write-Host ""
Write-Host "PolinRider check v$VERSION" -ForegroundColor White
Write-Host "Scanning $Path"
if ($Remote) { Write-Host "Including remote branches" }

$repos = @(Get-GitRepos $Path | Select-Object -Unique)
$script:RepoCount = $repos.Count

Invoke-FileScan $Path
Invoke-RepoArtifactScan $repos
Invoke-TasksJsonScan $Path
Invoke-PackageScan $Path
if (-not $SkipMachine) { Invoke-MachineScan }
if ($Remote) { Invoke-RemoteScan $repos }

Write-Host ""
Write-Host "----------------------------------------"
if ($script:Findings.Count -gt 0) {
    Write-Host "RESULT: $($script:Findings.Count) finding(s)" -ForegroundColor Red
    Write-Host ""
    Write-Host "What to do next: open CLEANUP.md in this folder (or the README on GitHub)."
    Write-Host "Short version: do not open the infected folders in an editor, do not run npm"
    Write-Host "in them, revoke your GitHub tokens and OAuth apps first, then clean."
    exit 1
}
Write-Host "RESULT: clean" -ForegroundColor Green
if (-not $Remote -and $script:RepoCount -gt 0) {
    Write-Host "Local files are clean. The payload is usually on the REMOTE while the local"
    Write-Host "checkout stays clean, so also run:  .\scan.ps1 `"$Path`" -Remote"
}
exit 0
