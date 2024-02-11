# Ochrona poświadczeń systemu Windows

## Ochrona poświadczeń

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## WDigest

Protokół [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396), wprowadzony wraz z systemem Windows XP, jest przeznaczony do uwierzytelniania za pomocą protokołu HTTP i jest **domyślnie włączony w systemach Windows XP do Windows 8.0 oraz Windows Server 2003 do Windows Server 2012**. Ustawienie to powoduje **przechowywanie haseł w postaci tekstu jawnego w usłudze LSASS** (Local Security Authority Subsystem Service). Atakujący może użyć narzędzia Mimikatz do **wydobycia tych poświadczeń** wykonując polecenie:
```bash
sekurlsa::wdigest
```
Aby **wyłączyć lub włączyć tę funkcję**, klucze rejestru _**UseLogonCredential**_ i _**Negotiate**_ w lokalizacji _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ muszą być ustawione na "1". Jeśli te klucze są **nieobecne lub ustawione na "0"**, WDigest jest **wyłączony**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Ochrona LSA

Rozpoczynając od **Windows 8.1**, Microsoft wzmocnił bezpieczeństwo LSA, aby **blokować nieautoryzowane odczyty pamięci lub wstrzykiwanie kodu przez niezaufane procesy**. To ulepszenie utrudnia typowe działanie poleceń takich jak `mimikatz.exe sekurlsa:logonpasswords`. Aby **włączyć tę ulepszoną ochronę**, wartość _**RunAsPPL**_ w _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ powinna zostać dostosowana do 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Ominięcie

Możliwe jest ominięcie tej ochrony za pomocą sterownika Mimikatz o nazwie mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard**, funkcja dostępna wyłącznie w edycjach **Windows 10 (Enterprise i Education)**, zwiększa bezpieczeństwo poświadczeń maszyny za pomocą **Virtual Secure Mode (VSM)** i **Virtualization Based Security (VBS)**. Wykorzystuje rozszerzenia wirtualizacji CPU do izolacji kluczowych procesów w chronionej przestrzeni pamięci, niedostępnej dla głównego systemu operacyjnego. Ta izolacja zapewnia, że nawet jądro nie może uzyskać dostępu do pamięci w VSM, skutecznie chroniąc poświadczenia przed atakami typu **pass-the-hash**. **Local Security Authority (LSA)** działa w tym bezpiecznym środowisku jako trustlet, podczas gdy proces **LSASS** w głównym systemie operacyjnym pełni jedynie rolę komunikatora z LSA w VSM.

Domyślnie **Credential Guard** nie jest aktywny i wymaga ręcznego aktywowania w organizacji. Jest to kluczowe dla zwiększenia bezpieczeństwa przed narzędziami takimi jak **Mimikatz**, które mają utrudnioną możliwość wydobycia poświadczeń. Jednak podatności nadal mogą być wykorzystane poprzez dodanie niestandardowych **Security Support Providers (SSP)** w celu przechwytywania poświadczeń w postaci tekstu jawnego podczas prób logowania.

Aby sprawdzić status aktywacji **Credential Guard**, można sprawdzić klucz rejestru **_LsaCfgFlags_** w lokalizacji **_HKLM\System\CurrentControlSet\Control\LSA_**. Wartość "**1**" oznacza aktywację z **blokadą UEFI**, "**2**" bez blokady, a wartość "**0**" oznacza, że funkcja nie jest włączona. Sprawdzenie tego klucza rejestru, choć jest silnym wskaźnikiem, nie jest jedynym krokiem do aktywacji Credential Guard. Szczegółowe instrukcje oraz skrypt PowerShell do aktywacji tej funkcji są dostępne online.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Dla pełnego zrozumienia i instrukcji dotyczących włączania **Credential Guard** w systemie Windows 10 oraz jego automatycznego aktywowania w kompatybilnych systemach **Windows 11 Enterprise i Education (wersja 22H2)**, odwiedź [dokumentację Microsoftu](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Dodatkowe informacje na temat implementacji niestandardowych SSP do przechwytywania poświadczeń są dostępne w [tym przewodniku](../active-directory-methodology/custom-ssp.md).


## Tryb RDP RestrictedAdmin

**Windows 8.1 i Windows Server 2012 R2** wprowadziły wiele nowych funkcji zabezpieczeń, w tym **_tryb Restricted Admin dla RDP_**. Ten tryb został zaprojektowany w celu zwiększenia bezpieczeństwa poprzez zmniejszenie ryzyka związanego z atakami typu **[pass the hash](https://blog.ahasayen.com/pass-the-hash/)**.

Tradycyjnie, podczas łączenia się z komputerem zdalnym za pomocą RDP, twoje poświadczenia są przechowywane na docelowym komputerze. Wiąże się to z istotnym ryzykiem bezpieczeństwa, zwłaszcza przy użyciu kont z podwyższonymi uprawnieniami. Jednak dzięki wprowadzeniu **_trybu Restricted Admin_**, to ryzyko jest znacznie zmniejszone.

Podczas inicjowania połączenia RDP za pomocą polecenia **mstsc.exe /RestrictedAdmin**, uwierzytelnianie na komputerze zdalnym odbywa się bez przechowywania twoich poświadczeń na nim. Taki podejście zapewnia, że w przypadku zainfekowania złośliwym oprogramowaniem lub dostania się do zdalnego serwera przez złośliwego użytkownika, twoje poświadczenia nie zostaną kompromitowane, ponieważ nie są przechowywane na serwerze.

Warto zauważyć, że w trybie **Restricted Admin**, próby dostępu do zasobów sieciowych z sesji RDP nie będą korzystać z twoich osobistych poświadczeń; zamiast tego używana jest **tożsamość maszyny**.

Ta funkcja stanowi znaczący krok naprzód w zabezpieczaniu połączeń zdalnego pulpitu i ochronie poufnych informacji przed ujawnieniem w przypadku naruszenia bezpieczeństwa.

![](../../.gitbook/assets/ram.png)

Aby uzyskać bardziej szczegółowe informacje, odwiedź [ten zasób](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).


## Buforowane poświadczenia

System Windows zabezpiecza **poświadczenia domeny** za pomocą **Lokalnego Urzędu ds. Bezpieczeństwa (LSA)**, obsługując procesy logowania przy użyciu protokołów bezpieczeństwa takich jak **Kerberos** i **NTLM**. Istotną cechą systemu Windows jest możliwość buforowania **ostatnich dziesięciu logowań do domeny**, aby użytkownicy mogli nadal uzyskiwać dostęp do swoich komputerów, nawet jeśli **kontroler domeny jest niedostępny** - co jest korzystne dla użytkowników laptopów często pracujących poza siecią firmową.

Liczba buforowanych logowań można dostosować za pomocą określonego **klucza rejestru lub zasad grupy**. Aby wyświetlić lub zmienić to ustawienie, używa się następującego polecenia:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Dostęp do tych buforowanych poświadczeń jest ściśle kontrolowany, przy czym tylko konto **SYSTEM** ma odpowiednie uprawnienia do ich wyświetlania. Administratorzy potrzebujący dostępu do tych informacji muszą to robić przy użyciu uprawnień użytkownika SYSTEM. Poświadczenia są przechowywane pod adresem: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** może być używany do wydobycia tych buforowanych poświadczeń za pomocą polecenia `lsadump::cache`.

Aby uzyskać dalsze szczegóły, oryginalne [źródło](http://juggernaut.wikidot.com/cached-credentials) zawiera wyczerpujące informacje.


## Użytkownicy chronieni

Członkostwo w grupie **Protected Users** wprowadza kilka ulepszeń związanych z bezpieczeństwem dla użytkowników, zapewniając wyższy poziom ochrony przed kradzieżą i nadużyciem poświadczeń:

- **Delegowanie poświadczeń (CredSSP)**: Nawet jeśli ustawienie zasad grupy dla **Zezwalaj na delegowanie domyślnych poświadczeń** jest włączone, poświadczenia tekstowe użytkowników chronionych nie będą buforowane.
- **Windows Digest**: Począwszy od **Windows 8.1 i Windows Server 2012 R2**, system nie będzie buforować poświadczeń tekstowych użytkowników chronionych, niezależnie od stanu Windows Digest.
- **NTLM**: System nie będzie buforować poświadczeń tekstowych użytkowników chronionych ani jednokierunkowych funkcji NT (NTOWF).
- **Kerberos**: Dla użytkowników chronionych uwierzytelnianie Kerberos nie generuje kluczy **DES** ani **RC4**, nie buforuje również poświadczeń tekstowych ani długoterminowych kluczy poza początkowym uzyskaniem biletu TGT (Ticket-Granting Ticket).
- **Logowanie offline**: Użytkownicy chronieni nie będą mieli utworzonego buforowanego weryfikatora podczas logowania lub odblokowywania, co oznacza, że logowanie offline nie jest obsługiwane dla tych kont.

Te zabezpieczenia są aktywowane w momencie, gdy użytkownik, który jest członkiem grupy **Protected Users**, loguje się do urządzenia. Zapewnia to, że krytyczne środki bezpieczeństwa są wdrożone w celu ochrony przed różnymi metodami kompromitacji poświadczeń.

Aby uzyskać bardziej szczegółowe informacje, zapoznaj się z oficjalną [dokumentacją](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Tabela z** [**dokumentacji**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów na GitHubie**.

</details>
