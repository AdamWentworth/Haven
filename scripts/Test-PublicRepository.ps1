[CmdletBinding()]
param(
    [switch] $Staged
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = (git rev-parse --show-toplevel).Trim()
if ([string]::IsNullOrWhiteSpace($repositoryRoot)) {
    throw 'This check must run inside a Git repository.'
}

Push-Location -LiteralPath $repositoryRoot

try {
    $candidateFiles = if ($Staged) {
        @(git diff --cached --name-only --diff-filter=ACMR)
    }
    else {
        @(git ls-files --cached --others --exclude-standard)
    }

    $candidateFiles = @($candidateFiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

    $blockedExtensions = @(
        '.cer', '.crt', '.db', '.dmp', '.etl', '.evtx', '.key', '.ovpn',
        '.p12', '.pcap', '.pcapng', '.pem', '.pfx', '.sqlite', '.sqlite3'
    )

    $textExtensions = @(
        '', '.cjs', '.css', '.dockerignore', '.go', '.gitignore', '.html', '.js',
        '.json', '.md', '.ps1', '.sh', '.toml', '.ts', '.tsx', '.txt',
        '.xml', '.yaml', '.yml'
    )

    $checks = @(
        [pscustomobject]@{
            Name = 'private key material'
            Pattern = '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
        },
        [pscustomobject]@{
            Name = 'credential-like assignment'
            Pattern = '(?i)(?:password|passwd|api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*["'']?[^\s"'']{8,}'
        },
        [pscustomobject]@{
            Name = 'connection-string password'
            Pattern = '(?i)(?:password|pwd)\s*=\s*[^;\s]{4,}'
        },
        [pscustomobject]@{
            Name = 'token-shaped value'
            Pattern = '(?:gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'
        },
        [pscustomobject]@{
            Name = 'personal user-profile path'
            Pattern = '(?i)(?:[A-Z]:\\Users\\(?!example(?:\\|$))|/home/(?!example(?:/|$)))'
        },
        [pscustomobject]@{
            Name = 'private or carrier-grade IPv4 address'
            Pattern = '(?<!\d)(?:10(?:\.\d{1,3}){3}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?!\d)'
        },
        [pscustomobject]@{
            Name = 'non-example email address'
            Pattern = '(?i)\b[A-Z0-9._%+-]+@(?!example\.(?:com|net|org)\b)[A-Z0-9.-]+\.[A-Z]{2,}\b'
        }
    )

    $findings = [System.Collections.Generic.List[string]]::new()

    foreach ($relativePath in $candidateFiles) {
        $fullPath = Join-Path -Path $repositoryRoot -ChildPath $relativePath
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            continue
        }

        $extension = [System.IO.Path]::GetExtension($relativePath).ToLowerInvariant()
        if ($blockedExtensions -contains $extension) {
            $findings.Add("$relativePath`: blocked artifact type $extension")
            continue
        }

        if ($textExtensions -notcontains $extension) {
            continue
        }

        $lineNumber = 0
        foreach ($line in [System.IO.File]::ReadLines($fullPath)) {
            $lineNumber++
            if ($relativePath -eq 'scripts/Test-PublicRepository.ps1' -and $line -match '^\s*Pattern\s*=') {
                continue
            }

			# A systemd template instance such as worker@8081.service resembles an
			# email address. Remove only validated unit-name tokens before applying
			# the email check; every other secret and address check still sees the
			# original line.
			$emailCheckLine = $line -replace '(?i)\b[A-Z0-9_.-]+@[A-Z0-9_.:-]+\.(?:service|socket)\b', ''
			# npm lockfiles can reproduce third-party package deprecation messages
			# containing maintainer addresses. Continue every credential, token, IP,
			# and path check, but do not treat upstream metadata as HAVEN user data.
			$isDependencyLock = $relativePath -match '(?i)(?:^|/)package-lock\.json$'

            foreach ($check in $checks) {
				if ($isDependencyLock -and $check.Name -eq 'non-example email address') { continue }
				$checkedLine = if ($check.Name -eq 'non-example email address') { $emailCheckLine } else { $line }
				if ($checkedLine -match $check.Pattern) {
                    $findings.Add("$relativePath`:$lineNumber`: $($check.Name)")
                }
            }
        }
    }

    if ($findings.Count -gt 0) {
        Write-Error (@"
HAVEN's public-repository check found material that needs review:

$($findings -join [Environment]::NewLine)

Use synthetic documentation values (example.com and RFC 5737 IP ranges), and keep
runtime data, credentials, certificates, captures, and local configuration outside
the repository. Do not bypass this check for a real secret; revoke it first.
"@)
        exit 1
    }

    Write-Host "Public-repository check passed for $($candidateFiles.Count) file(s)."
}
finally {
    Pop-Location
}
