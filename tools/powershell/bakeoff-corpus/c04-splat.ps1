$params = @{ Path = 'C:\tmp'; Recurse = $true; ErrorAction = 'SilentlyContinue' }
Get-ChildItem @params
$argsList = @('-l','-a')
& ls @argsList
Copy-Item @params -Destination D:\out
