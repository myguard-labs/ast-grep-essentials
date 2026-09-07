$x = $null
$y = $x ?? 'default'
$z = ${x}?.Length
$x ??= 'set'
$r = 1..5 | ForEach-Object -Parallel { $_ * 2 } -ThrottleLimit 4
Invoke-RestMethod -Uri https://example.com -SkipCertificateCheck
$t = $val ? 'yes' : 'no'
class Foo { [int]$Bar; Foo([int]$b) { $this.Bar = $b } [string] Show() { return "$($this.Bar)" } }
enum Color { Red; Green }
$e = [Foo]::new(1)
& { 'nested' }
