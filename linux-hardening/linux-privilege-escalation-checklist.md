# Lista kontrolna - Eskalacja uprawnień w systemie Linux

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami nagród za błędy!

**Wgląd w hakerstwo**\
Zajmuj się treściami, które zagłębiają się w emocje i wyzwania hakerstwa

**Aktualności na żywo z hakerstwa**\
Bądź na bieżąco z szybkim tempem świata hakerstwa dzięki aktualnym wiadomościom i wglądom

**Najnowsze ogłoszenia**\
Bądź na bieżąco z najnowszymi programami nagród za błędy i ważnymi aktualizacjami platformy

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

### **Narzędzie do wyszukiwania wektorów eskalacji uprawnień lokalnych w systemie Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacje o systemie](privilege-escalation/#system-information)

* [ ] Uzyskaj **informacje o systemie operacyjnym**
* [ ] Sprawdź [**ŚCIEŻKĘ**](privilege-escalation/#path), czy jest **folder z możliwością zapisu**?
* [ ] Sprawdź [**zmienne środowiskowe**](privilege-escalation/#env-info), czy zawierają jakieś wrażliwe dane?
* [ ] Szukaj [**exploitów jądra**](privilege-escalation/#kernel-exploits) **za pomocą skryptów** (DirtyCow?)
* [ ] **Sprawdź**, czy [**wersja sudo jest podatna na ataki**](privilege-escalation/#sudo-version)
* [ ] [**Błąd weryfikacji podpisu Dmesg**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Więcej informacji o systemie (data, statystyki systemowe, informacje o procesorze, drukarki](privilege-escalation/#more-system-enumeration))
* [ ] [Wylicz więcej zabezpieczeń](privilege-escalation/#enumerate-possible-defenses)

### [Dyski](privilege-escalation/#drives)

* [ ] Wyświetl **zamontowane** dyski
* [ ] Czy jest **jakiś niezamontowany dysk**?
* [ ] Czy w fstab są **jakieś poświadczenia dostępu**?

### [**Zainstalowane oprogramowanie**](privilege-escalation/#installed-software)

* [ ] Sprawdź, czy jest **zainstalowane** [**użyteczne oprogramowanie**](privilege-escalation/#useful-software)
* [ ] Sprawdź, czy jest **zainstalowane** [**podatne oprogramowanie**](privilege-escalation/#vulnerable-software-installed)

### [Procesy](privilege-escalation/#processes)

* [ ] Czy działa **nieznane oprogramowanie**?
* [ ] Czy jakiekolwiek oprogramowanie działa z **większymi uprawnieniami niż powinno**?
* [ ] Szukaj **exploitów działających procesów** (szczególnie wersji, która jest uruchomiona).
* [ ] Czy możesz **modyfikować binarny plik** dowolnie działającego procesu?
* [ ] **Monitoruj procesy** i sprawdź, czy często uruchamiany jest jakiś interesujący proces.
* [ ] Czy możesz **odczytać** pamięć **procesu** (gdzie mogą być zapisane hasła)?

### [Zadania zaplanowane/Cron](privilege-escalation/#scheduled-jobs)

* [ ] Czy [**ŚCIEŻKA**](privilege-escalation/#cron-path) jest modyfikowana przez cron i możesz w niej **pisać**?
* [ ] Czy w zadaniu cron jest [**symbol wieloznaczny**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)?
* [ ] Czy jest wykonywany [**modyfikowalny skrypt**](privilege-escalation/#cron-script-overwriting-and-symlink) lub znajduje się w **modyfikowalnym folderze**?
* [ ] Czy wykryłeś, że jakiś **skrypt** może być lub jest [**wykonywany bardzo często**](privilege-escalation/#frequent-cron-jobs)? (co 1, 2 lub 5 minut)

### [Usługi](privilege-escalation/#services)

* [ ] Czy istnieje **plik .service z możliwością zapisu**?
* [ ] Czy jakaś **wykonywalna binarka z możliwością zapisu** jest uruchamiana przez **usługę**?
* [ ] Czy istnieje **folder z możliwością zapisu w ścieżce systemd**?

### [Timery](privilege-escalation/#timers)

* [ ] Czy istnieje **timer z możliwością zapisu**?

### [Gniazda](privilege-escalation/#sockets)

* [ ] Czy istnieje **plik .socket z możliwością zapisu**?
* [ ] Czy możesz **komunikować się z dowolnym gniazdem**?
* [ ] **Gniazda HTTP** z interesującymi informacjami?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Czy możesz **komunikować się z dowolnym D-Bus**?

### [Sieć](privilege-escalation/#network)

* [ ] Wylicz sieć, aby dowiedzieć się, gdzie się znajdujesz
* [ ] Czy masz dostęp do **otwartych portów**, do których wcześniej nie miałeś dostępu po uzyskaniu powłoki w maszynie?
* [ ] Czy możesz **przechwytywać ruch** za pomocą `tcpdump`?

### [Użytkownicy](privilege-escalation/#users)

* [
### [Capabilities](privilege-escalation/#capabilities)

* [ ] Czy jakikolwiek plik ma **nieoczekiwane uprawnienia**?

### [ACLs](privilege-escalation/#acls)

* [ ] Czy jakikolwiek plik ma **nieoczekiwane ACL**?

### [Open Shell sessions](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Przewidywalny PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Interesujące wartości konfiguracji SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interesujące pliki](privilege-escalation/#interesting-files)

* [ ] **Pliki profilowe** - Czytanie poufnych danych? Zapis do podniesienia uprawnień?
* [ ] **Pliki passwd/shadow** - Czytanie poufnych danych? Zapis do podniesienia uprawnień?
* [ ] **Sprawdź powszechnie interesujące foldery** pod kątem poufnych danych
* [ ] **Dziwne lokalizacje/posiadane pliki**, do których możesz mieć dostęp lub zmieniać pliki wykonywalne
* [ ] **Zmodyfikowane** w ostatnich minutach
* [ ] **Pliki bazy danych Sqlite**
* [ ] **Ukryte pliki**
* [ ] **Skrypty/Binarki w PATH**
* [ ] **Pliki internetowe** (hasła?)
* [ ] **Kopie zapasowe**?
* [ ] **Znane pliki zawierające hasła**: Użyj **Linpeas** i **LaZagne**
* [ ] **Ogólne wyszukiwanie**

### [**Pliki z możliwością zapisu**](privilege-escalation/#writable-files)

* [ ] **Modyfikacja biblioteki python** w celu wykonania dowolnych poleceń?
* [ ] Czy możesz **modyfikować pliki dziennika**? Wykorzystanie podatności Logtotten
* [ ] Czy możesz **modyfikować /etc/sysconfig/network-scripts/**? Wykorzystanie podatności w Centos/Redhat
* [ ] Czy możesz [**pisać w plikach ini, int.d, systemd lub rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Inne sztuczki**](privilege-escalation/#other-tricks)

* [ ] Czy możesz [**wykorzystać NFS do eskalacji uprawnień**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Czy musisz [**uciec z ograniczonej powłoki**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami błędów!

**Wnioski z Hackingu**\
Zajmuj się treściami, które zagłębiają się w emocje i wyzwania związane z hakowaniem

**Aktualności o Hackingu na Żywo**\
Bądź na bieżąco z szybkim tempem świata hakowania dzięki aktualnym wiadomościom i spostrzeżeniom

**Najnowsze Ogłoszenia**\
Bądź na bieżąco z najnowszymi programami bug bounty i ważnymi aktualizacjami platformy

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
