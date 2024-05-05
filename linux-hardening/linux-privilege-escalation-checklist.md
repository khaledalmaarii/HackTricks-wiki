# Lista kontrolna - Eskalacja uprawnień w systemie Linux

<details>

<summary><strong>Zacznij od zera i stań się ekspertem od hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną na HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami nagród za błędy!

**Spojrzenie na Hakowanie**\
Zajmij się treściami, które zagłębiają się w emocje i wyzwania hakowania

**Aktualności z Hakowania na Żywo**\
Bądź na bieżąco z szybkim tempem świata hakowania dzięki aktualnościom na żywo i spostrzeżeniom

**Najnowsze Ogłoszenia**\
Bądź na bieżąco z najnowszymi programami nagród za błędy i istotnymi aktualizacjami platform

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

### **Najlepsze narzędzie do szukania wektorów eskalacji uprawnień lokalnych w systemie Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacje o Systemie](privilege-escalation/#system-information)

* [ ] Uzyskaj **informacje o systemie operacyjnym**
* [ ] Sprawdź [**ŚCIEŻKĘ**](privilege-escalation/#path), czy istnieje **folder z uprawnieniami do zapisu**?
* [ ] Sprawdź [**zmienne środowiskowe**](privilege-escalation/#env-info), czy zawierają jakieś poufne informacje?
* [ ] Szukaj [**exploitów jądra**](privilege-escalation/#kernel-exploits) **za pomocą skryptów** (DirtyCow?)
* [ ] **Sprawdź**, czy [**wersja sudo jest podatna**](privilege-escalation/#sudo-version)
* [ ] [**Weryfikacja podpisu Dmesg nie powiodła się**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Więcej informacji o systemie ([data, statystyki systemu, informacje o CPU, drukarki](privilege-escalation/#more-system-enumeration))
* [ ] [Eskalacja obrony](privilege-escalation/#enumerate-possible-defenses)

### [Dyski](privilege-escalation/#drives)

* [ ] **Wyświetl zamontowane** dyski
* [ ] Czy jest **jakiś niezamontowany dysk**?
* [ ] Czy są **jakieś dane uwierzytelniające w fstab**?

### [**Zainstalowane Oprogramowanie**](privilege-escalation/#installed-software)

* [ ] Sprawdź, czy jest [**zainstalowane**](privilege-escalation/#useful-software) **użyteczne oprogramowanie**
* [ ] Sprawdź, czy jest [**zainstalowane oprogramowanie podatne na ataki**](privilege-escalation/#vulnerable-software-installed)

### [Procesy](privilege-escalation/#processes)

* [ ] Czy uruchomione jest **nieznane oprogramowanie**?
* [ ] Czy jakieś oprogramowanie działa z **większymi uprawnieniami niż powinno**?
* [ ] Szukaj **exploitów uruchomionych procesów** (szczególnie wersji uruchamianej).
* [ ] Czy możesz **zmodyfikować binarny plik** dowolnego uruchomionego procesu?
* [ ] **Monitoruj procesy** i sprawdź, czy uruchamiany jest jakiś interesujący proces z dużą częstotliwością.
* [ ] Czy możesz **odczytać** pewne interesujące **pamięci procesów** (gdzie mogą być zapisane hasła)?

### [Zadania Zaplanowane/Cron](privilege-escalation/#scheduled-jobs)

* [ ] Czy [**ŚCIEŻKA** ](privilege-escalation/#cron-path)jest modyfikowana przez jakiś cron i możesz w niej **pisać**?
* [ ] Czy w zadaniu cron jest [**znak wieloznaczny** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)?
* [ ] Czy jakiś [**modyfikowalny skrypt** ](privilege-escalation/#cron-script-overwriting-and-symlink)jest **wykonywany** lub znajduje się w **modyfikowalnym folderze**?
* [ ] Czy wykryłeś, że jakiś **skrypt** mógłby być lub jest **wykonywany bardzo często**](privilege-escalation/#frequent-cron-jobs)? (co minutę, co dwie minuty lub co pięć minut)

### [Usługi](privilege-escalation/#services)

* [ ] Czy istnieje **plik .service z uprawnieniami do zapisu**?
* [ ] Czy jest **wykonywany binarny plik z uprawnieniami do zapisu** przez **usługę**?
* [ ] Czy istnieje **folder z uprawnieniami do zapisu w ścieżce systemd**?

### [Timery](privilege-escalation/#timers)

* [ ] Czy istnieje **timer z uprawnieniami do zapisu**?

### [Gniazda](privilege-escalation/#sockets)

* [ ] Czy istnieje **plik .socket z uprawnieniami do zapisu**?
* [ ] Czy możesz **komunikować się z dowolnym gniazdem**?
* [ ] **Gniazda HTTP** z interesującymi informacjami?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Czy możesz **komunikować się z jakimkolwiek D-Bus**?

### [Sieć](privilege-escalation/#network)

* [ ] Wylicz sieć, aby wiedzieć, gdzie się znajdujesz
* [ ] Czy masz dostęp do **otwartych portów**, do których nie mogłeś uzyskać dostępu przed uzyskaniem powłoki wewnątrz maszyny?
* [ ] Czy możesz **przechwytywać ruch** za pomocą `tcpdump`?

### [Użytkownicy](privilege-escalation/#users)

* [ ] Ogólne **wyliczenie użytkowników/grup**
* [ ] Czy masz **bardzo duże UID**? Czy **maszyna** jest **podatna**?
* [ ] Czy możesz [**eskalować uprawnienia dzięki grupie**](privilege-escalation/interesting-groups-linux-pe/), do której należysz?
* [ ] Dane z **schowka**?
* [ ] Polityka hasła?
* [ ] Spróbuj **użyć** każdego **znanego hasła**, które wcześniej odkryłeś, aby zalogować się **z każdym** możliwym **użytkownikiem**. Spróbuj również zalogować się bez hasła.

### [Ścieżka z Uprawnieniami do Zapisu](privilege-escalation/#writable-path-abuses)

* [ ] Jeśli masz **uprawnienia do zapisu w jakimś folderze w ŚCIEŻCE**, możesz próbować eskalować uprawnienia

### [Komendy SUDO i SUID](privilege-escalation/#sudo-and-suid)

* [ ] Czy możesz wykonać **dowolną komendę z sudo**? Czy możesz jej użyć do ODCZYTANIA, ZAPISANIA lub WYKONANIA czegoś jako root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Czy jest **podatny binarny plik SUID**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Czy [**komendy sudo są **ograniczone** przez **ścieżkę**? Czy możesz **obejść** te ograniczenia](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Binarny Sudo/SUID bez wskazanej ścieżki**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**Binarny SUID z określoną ścieżką**](privilege-escalation/#suid-binary-with-command-path)? Ominięcie
* [ ] [**Usterka LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Brak biblioteki .so w binarnym SUID**](privilege-escalation/#suid-binary-so-injection) z folderu z uprawnieniami do zapisu?
* [ ] [**Dostępne tokeny SUDO**](privilege-escalation/#reusing-sudo-tokens)? [**Czy możesz utworzyć token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Czy możesz [**odczytać lub modyfikować pliki sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* Czy możesz [**modyfikować /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [**OpenBSD DOAS**](privilege-escalation/#doas) command
### [Uprawnienia](privilege-escalation/#capabilities)

* [ ] Czy którykolwiek plik ma **nieoczekiwane uprawnienia**?

### [Kontrola dostępu ACL](privilege-escalation/#acls)

* [ ] Czy którykolwiek plik ma **nieoczekiwane ACL**?

### [Otwarte sesje powłoki](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Przewidywalny PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Interesujące wartości konfiguracyjne SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interesujące pliki](privilege-escalation/#interesting-files)

* [ ] **Pliki profilowe** - Czytanie poufnych danych? Zapis do eskalacji uprawnień?
* [ ] Pliki **passwd/shadow** - Czytanie poufnych danych? Zapis do eskalacji uprawnień?
* [ ] Sprawdź powszechnie interesujące foldery pod kątem poufnych danych
* [ ] **Dziwne lokalizacje/Pliki własnościowe**, do których możesz mieć dostęp lub zmieniać pliki wykonywalne
* [ ] **Zmodyfikowane** w ostatnich minutach
* [ ] Pliki bazy danych **Sqlite**
* [ ] **Ukryte pliki**
* [ ] **Skrypty/Binaria w PATH**
* [ ] **Pliki internetowe** (hasła?)
* [ ] **Kopie zapasowe**?
* [ ] **Znane pliki zawierające hasła**: Użyj **Linpeas** i **LaZagne**
* [ ] **Ogólne wyszukiwanie**

### [**Pliki z możliwością zapisu**](privilege-escalation/#writable-files)

* [ ] Czy można **zmodyfikować bibliotekę pythona** w celu wykonania dowolnych poleceń?
* [ ] Czy można **zmodyfikować pliki dziennika**? Exploit **Logtotten**
* [ ] Czy można **zmodyfikować /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
* [ ] Czy można [**pisać w plikach ini, int.d, systemd lub rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Inne sztuczki**](privilege-escalation/#other-tricks)

* [ ] Czy można [**wykorzystać NFS do eskalacji uprawnień**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Czy potrzebujesz [**uciec z ograniczonej powłoki**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami błędów!

**Spostrzeżenia dotyczące hakerstwa**\
Zajmij się treściami, które zagłębiają się w emocje i wyzwania hakerstwa

**Aktualności na żywo dotyczące hakerstwa**\
Bądź na bieżąco z szybkim tempem świata hakerstwa dzięki aktualnościom i spostrzeżeniom na żywo

**Najnowsze ogłoszenia**\
Bądź na bieżąco z najnowszymi programami nagród za błędy i istotnymi aktualizacjami platformy

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
