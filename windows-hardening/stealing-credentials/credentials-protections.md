# Ochrona poświadczeń systemu Windows

## Ochrona poświadczeń

<details>

<summary><strong>Zacznij od zera i stań się ekspertem od hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## WDigest

Protokół [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396), wprowadzony wraz z systemem Windows XP, jest przeznaczony do uwierzytelniania za pomocą protokołu HTTP i jest **domyślnie włączony w systemach Windows XP do Windows 8.0 oraz Windows Server 2003 do Windows Server 2012**. To domyślne ustawienie powoduje **przechowywanie haseł w postaci tekstu jawnego w LSASS** (Local Security Authority Subsystem Service). Atakujący może użyć Mimikatz do **wydobycia tych poświadczeń**, wykonując:
```bash
sekurlsa::wdigest
```
Aby **włączyć lub wyłączyć tę funkcję**, klucze rejestru _**UseLogonCredential**_ i _**Negotiate**_ w _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ muszą być ustawione na "1". Jeśli te klucze są **nieobecne lub ustawione na "0"**, WDigest jest **wyłączony**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Ochrona LSA

Rozpoczynając od **Windows 8.1**, Microsoft wzmocnił zabezpieczenia LSA, aby **blokować nieautoryzowane odczyty pamięci lub wstrzykiwanie kodu przez niezaufane procesy**. To usprawnienie utrudnia typowe działanie poleceń takich jak `mimikatz.exe sekurlsa:logonpasswords`. Aby **włączyć tę usprawnioną ochronę**, wartość _**RunAsPPL**_ w _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ powinna zostać dostosowana do 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Ominięcie

Możliwe jest ominięcie tej ochrony za pomocą sterownika Mimikatz o nazwie mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Ochrona poświadczeń

**Ochrona poświadczeń**, funkcja dostępna wyłącznie w edycjach **Windows 10 (Enterprise i Education)**, zwiększa bezpieczeństwo poświadczeń maszyny za pomocą **Trybu Wirtualnego Bezpieczeństwa (VSM)** i **Bezpieczeństwa Opartego na Wirtualizacji (VBS)**. Wykorzystuje rozszerzenia wirtualizacji CPU do izolacji kluczowych procesów w chronionej przestrzeni pamięci, poza zasięgiem głównego systemu operacyjnego. Ta izolacja zapewnia, że nawet jądro nie może uzyskać dostępu do pamięci w VSM, skutecznie zabezpieczając poświadczenia przed atakami typu **pass-the-hash**. **Lokalna Służba Bezpieczeństwa (LSA)** działa w tym bezpiecznym środowisku jako zaufany element, podczas gdy proces **LSASS** w głównym systemie operacyjnym działa jedynie jako komunikator z LSA w VSM.

Domyślnie **Ochrona poświadczeń** nie jest aktywna i wymaga ręcznej aktywacji w organizacji. Jest to istotne dla zwiększenia bezpieczeństwa przed narzędziami takimi jak **Mimikatz**, które są utrudnione w wydobywaniu poświadczeń. Niemniej jednak, nadal można wykorzystać podatności poprzez dodanie niestandardowych **Dostawców Wsparcia Bezpieczeństwa (SSP)** w celu przechwytywania poświadczeń w postaci tekstu jawnego podczas prób logowania.

Aby zweryfikować stan aktywacji **Ochrony poświadczeń**, można sprawdzić klucz rejestru _**LsaCfgFlags**_ w _**HKLM\System\CurrentControlSet\Control\LSA**_. Wartość "**1**" oznacza aktywację z **blokadą UEFI**, "**2**" bez blokady, a "**0**" oznacza, że nie jest włączona. To sprawdzenie rejestru, choć silny wskaźnik, nie jest jedynym krokiem do aktywacji Ochrony poświadczeń. Szczegółowe wskazówki i skrypt PowerShell do aktywacji tej funkcji są dostępne online.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Dla kompleksowego zrozumienia i instrukcji dotyczących włączenia **Guardian Credentials** w systemie Windows 10 oraz automatycznego aktywowania go w kompatybilnych systemach **Windows 11 Enterprise i Education (wersja 22H2)**, odwiedź [dokumentację Microsoftu](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Dodatkowe szczegóły dotyczące implementacji niestandardowych SSP do przechwytywania poświadczeń znajdują się w [tym przewodniku](../active-directory-methodology/custom-ssp.md).

## Tryb RDP RestrictedAdmin

**Windows 8.1 i Windows Server 2012 R2** wprowadziły kilka nowych funkcji zabezpieczeń, w tym _**Tryb Restricted Admin dla RDP**_. Ten tryb został zaprojektowany w celu zwiększenia bezpieczeństwa poprzez zmniejszenie ryzyka związanego z atakami typu [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradycyjnie, podczas łączenia się z komputerem zdalnym za pomocą RDP, Twoje poświadczenia są przechowywane na maszynie docelowej. Stanowi to znaczne ryzyko dla bezpieczeństwa, zwłaszcza przy użyciu kont z podwyższonymi uprawnieniami. Jednak wprowadzenie _**Trybu Restricted Admin**_ znacząco zmniejsza to ryzyko.

Podczas inicjowania połączenia RDP za pomocą polecenia **mstsc.exe /RestrictedAdmin**, uwierzytelnianie na komputerze zdalnym odbywa się bez przechowywania Twoich poświadczeń na nim. Ten podejście zapewnia, że w przypadku zainfekowania złośliwym oprogramowaniem lub gdy złośliwy użytkownik uzyska dostęp do serwera zdalnego, Twoje poświadczenia nie zostaną naruszone, ponieważ nie są przechowywane na serwerze.

Warto zauważyć, że w **Trybie Restricted Admin** próby dostępu do zasobów sieciowych z sesji RDP nie będą korzystały z Twoich osobistych poświadczeń; zamiast tego używana jest **tożsamość maszyny**.

Ta funkcja stanowi znaczący krok naprzód w zabezpieczaniu połączeń pulpitu zdalnego i ochronie poufnych informacji przed ujawnieniem w przypadku naruszenia bezpieczeństwa.

![](../../.gitbook/assets/RAM.png)

Aby uzyskać bardziej szczegółowe informacje, odwiedź [ten zasób](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Poświadczenia buforowane

System Windows zabezpiecza **poświadczenia domeny** za pomocą **Lokalnego Organu Bezpieczeństwa (LSA)**, obsługując procesy logowania za pomocą protokołów bezpieczeństwa takich jak **Kerberos** i **NTLM**. Istotną cechą systemu Windows jest możliwość buforowania **ostatnich dziesięciu logowań domenowych**, aby zapewnić użytkownikom dostęp do swoich komputerów nawet wtedy, gdy **kontroler domeny jest offline**—co jest korzystne dla użytkowników laptopów często poza siecią firmową.

Liczba buforowanych logowań jest regulowana za pomocą określonego **klucza rejestru lub zasady grupy**. Aby wyświetlić lub zmienić to ustawienie, używane jest następujące polecenie:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Dostęp do tych przechowywanych poświadczeń jest ściśle kontrolowany, z uprawnieniami do ich wyświetlania posiadającymi tylko konto **SYSTEM**. Administratorzy potrzebujący dostępu do tych informacji muszą to zrobić z uprawnieniami użytkownika SYSTEM. Poświadczenia są przechowywane pod adresem: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** może być użyty do wydobycia tych przechowywanych poświadczeń za pomocą polecenia `lsadump::cache`.

Dla dalszych szczegółów, oryginalne [źródło](http://juggernaut.wikidot.com/cached-credentials) dostarcza wyczerpujących informacji.

## Użytkownicy chronieni

Członkostwo w grupie **Protected Users** wprowadza kilka usprawnień związanych z bezpieczeństwem dla użytkowników, zapewniając wyższy poziom ochrony przed kradzieżą i nadużyciem poświadczeń:

* **Delegacja poświadczeń (CredSSP)**: Nawet jeśli ustawienie zasad Grupy dotyczących **Zezwalania na delegowanie domyślnych poświadczeń** jest włączone, poświadczenia w postaci tekstu jawnego użytkowników chronionych nie będą przechowywane w pamięci podręcznej.
* **Windows Digest**: Począwszy od **Windows 8.1 i Windows Server 2012 R2**, system nie będzie przechowywał poświadczeń w postaci tekstu jawnego użytkowników chronionych, niezależnie od statusu Windows Digest.
* **NTLM**: System nie będzie przechowywał poświadczeń w postaci tekstu jawnego użytkowników chronionych ani funkcji jednokierunkowych NT (NTOWF).
* **Kerberos**: Dla użytkowników chronionych, uwierzytelnianie Kerberos nie będzie generować kluczy **DES** ani **RC4**, ani przechowywać poświadczeń w postaci tekstu jawnego lub kluczy długoterminowych poza początkowym uzyskaniem biletu TGT (Ticket-Granting Ticket).
* **Logowanie offline**: Użytkownicy chronieni nie będą mieli utworzonego weryfikatora w pamięci podręcznej podczas logowania się lub odblokowywania, co oznacza brak obsługi logowania offline dla tych kont.

Te zabezpieczenia są aktywowane w momencie, gdy użytkownik, będący członkiem grupy **Protected Users**, loguje się do urządzenia. Zapewnia to, że krytyczne środki bezpieczeństwa są wdrożone, aby chronić przed różnymi metodami kompromitacji poświadczeń.

Aby uzyskać bardziej szczegółowe informacje, skonsultuj się z oficjalną [dokumentacją](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

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
