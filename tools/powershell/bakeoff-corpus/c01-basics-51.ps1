param([string]$Name = "world", [int]$Count = 3)
$ErrorActionPreference = 'Stop'
function Get-Greeting {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Who)
    process { "Hello, $Who!" }
}
for ($i = 0; $i -lt $Count; $i++) { Get-Greeting -Who $Name }
$h = @{ A = 1; B = 'two' }
$a = @(1,2,3) | Where-Object { $_ -gt 1 }
try { Get-Item C:\nope } catch { Write-Error $_.Exception.Message } finally { }
switch ($Name) { 'world' { 'earth' } default { 'other' } }
