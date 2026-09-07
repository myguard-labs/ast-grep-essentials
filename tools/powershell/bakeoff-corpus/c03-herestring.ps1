$a = @"
expandable $env:USERNAME
with "quotes" and 'more'
"@
$b = @'
literal $notexpanded
"@ not a terminator
'@
Write-Output $a $b
