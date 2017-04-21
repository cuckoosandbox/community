rule PowershellDI {
  meta:
	author = "FDD"
	description = "Extract Download/Invoke calls from powershell script"
  strings:
	$d1 = /downloaddata\([^)]+\)/ nocase
	$d2 = /downloadstring\([^)]+\)/ nocase
	$d3 = /downloadfile\([^)]+\)/ nocase
	$i1 = /invoke[^;]*/ nocase
	$i2 = /iex[^;]*/ nocase
  condition:
	any of ($d*) and any of ($i*)
}
