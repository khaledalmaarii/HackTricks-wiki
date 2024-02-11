# Linux Forensics

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społeczności.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Początkowe gromadzenie informacji

### Podstawowe informacje

Po pierwsze, zaleca się posiadanie **pendrive'a** z **dobrze znaczącymi binarnymi i bibliotekami** (możesz po prostu pobrać Ubuntu i skopiować foldery _/bin_, _/sbin_, _/lib_ i _/lib64_), następnie zamontować pendrive i zmodyfikować zmienne środowiskowe, aby używać tych binarnych plików:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Po skonfigurowaniu systemu do użycia dobrych i znanych plików binarnych możesz rozpocząć **wydobywanie podstawowych informacji**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Podejrzane informacje

Podczas uzyskiwania podstawowych informacji warto sprawdzić, czy nie ma niczego podejrzanego, takiego jak:

* **Procesy roota** zazwyczaj mają niskie PID-y, więc jeśli znajdziesz proces roota z dużym PID-em, może to budzić podejrzenia.
* Sprawdź **zarejestrowane logowania** użytkowników bez powłoki w pliku `/etc/passwd`.
* Sprawdź **hasze haseł** użytkowników bez powłoki w pliku `/etc/shadow`.

### Zrzut pamięci

Aby uzyskać zrzut pamięci działającego systemu, zaleca się użycie [**LiME**](https://github.com/504ensicsLabs/LiME).\
Aby go **skompilować**, musisz użyć **tego samego jądra**, którego używa maszyna ofiary.

{% hint style="info" %}
Pamiętaj, że **nie możesz zainstalować LiME ani niczego innego** na maszynie ofiary, ponieważ wprowadzi to wiele zmian.
{% endhint %}

Jeśli masz identyczną wersję Ubuntu, możesz użyć `apt-get install lime-forensics-dkms`\
W innych przypadkach musisz pobrać [**LiME**](https://github.com/504ensicsLabs/LiME) z githuba i skompilować go z odpowiednimi nagłówkami jądra. Aby **uzyskać dokładne nagłówki jądra** maszyny ofiary, po prostu **skopiuj katalog** `/lib/modules/<wersja jądra>` na swoją maszynę, a następnie **skompiluj** LiME, używając ich:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME obsługuje 3 **formaty**:

* Surowy (każdy segment sklejony razem)
* Wygładzony (taki sam jak surowy, ale z zerami na prawej stronie)
* Lime (zalecany format z metadanymi)

LiME można również użyć do **wysłania zrzutu przez sieć** zamiast przechowywania go w systemie, używając na przykład: `path=tcp:4444`

### Tworzenie obrazu dysku

#### Wyłączanie

Przede wszystkim będziesz musiał **wyłączyć system**. Nie zawsze jest to możliwe, ponieważ czasami system będzie serwerem produkcyjnym, którego firma nie może sobie pozwolić na wyłączenie.\
Istnieją **2 sposoby** wyłączania systemu: **normalne wyłączenie** i **wyłączenie "wyciągnij wtyczkę"**. Pierwszy pozwoli na **zakończenie procesów** i **synchronizację systemu plików**, ale również umożliwi **potencjalnemu złośliwemu oprogramowaniu zniszczenie dowodów**. Podejście "wyciągnij wtyczkę" może wiązać się z **pewną utratą informacji** (nie wiele informacji zostanie utraconych, ponieważ już zrobiliśmy obraz pamięci) i **złośliwe oprogramowanie nie będzie miało możliwości** nic z tym zrobić. Dlatego jeśli **podejrzewasz**, że może być **złośliwe oprogramowanie**, po prostu wykonaj polecenie **`sync`** na systemie i wyciągnij wtyczkę.

#### Tworzenie obrazu dysku

Ważne jest zauważenie, że **przed podłączeniem swojego komputera do czegokolwiek związanego z tą sprawą**, musisz upewnić się, że będzie on **zamontowany w trybie tylko do odczytu**, aby uniknąć modyfikowania jakichkolwiek informacji.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Wstępna analiza obrazu dysku

Tworzenie obrazu dysku bez dodatkowych danych.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społeczności.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Wyszukiwanie znanego złośliwego oprogramowania

### Zmodyfikowane pliki systemowe

Linux oferuje narzędzia do zapewnienia integralności komponentów systemowych, co jest kluczowe dla wykrywania potencjalnie problematycznych plików.

- **Systemy oparte na RedHat**: Użyj `rpm -Va` do przeprowadzenia kompleksowej kontroli.
- **Systemy oparte na Debian**: `dpkg --verify` do wstępnej weryfikacji, a następnie `debsums | grep -v "OK$"` (po zainstalowaniu `debsums` za pomocą `apt-get install debsums`) do identyfikacji ewentualnych problemów.

### Detektory złośliwego oprogramowania/rootkitów

Przeczytaj następującą stronę, aby dowiedzieć się o narzędziach, które mogą być przydatne do wyszukiwania złośliwego oprogramowania:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Wyszukiwanie zainstalowanych programów

Aby skutecznie wyszukiwać zainstalowane programy zarówno w systemach Debian, jak i RedHat, rozważ wykorzystanie dzienników systemowych i baz danych w połączeniu z ręcznymi sprawdzaniami w popularnych katalogach.

- Dla systemu Debian, sprawdź pliki **_`/var/lib/dpkg/status`_** i **_`/var/log/dpkg.log`_** w celu uzyskania szczegółów dotyczących instalacji pakietów, używając `grep` do filtrowania konkretnych informacji.

- Użytkownicy RedHat mogą zapytać bazę danych RPM za pomocą `rpm -qa --root=/mntpath/var/lib/rpm`, aby wyświetlić zainstalowane pakiety.

Aby odkryć oprogramowanie zainstalowane ręcznie lub poza tymi menedżerami pakietów, przejrzyj katalogi takie jak **_`/usr/local`_**, **_`/opt`_**, **_`/usr/sbin`_**, **_`/usr/bin`_**, **_`/bin`_**, i **_`/sbin`_**. Połącz listy katalogów z poleceniami specyficznymi dla systemu, aby zidentyfikować pliki wykonywalne niepowiązane z znanymi pakietami, co zwiększy skuteczność wyszukiwania wszystkich zainstalowanych programów.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** z wykorzystaniem najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Odzyskiwanie usuniętych uruchomionych plików binarnych

Wyobraź sobie proces, który został uruchomiony z /tmp/exec i został usunięty. Można go odzyskać.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
### Zaplanowane zadania

Zaplanowane zadania są jednym z miejsc, w których można znaleźć autostartujące się programy w systemie Linux. Aby sprawdzić zaplanowane zadania, wykonaj następujące kroki:

1. Otwórz terminal.
2. Uruchom polecenie `crontab -l`, aby wyświetlić listę zaplanowanych zadań dla bieżącego użytkownika.
3. Sprawdź każde zadanie, aby zidentyfikować podejrzane wpisy lub programy, które mogą być uruchamiane automatycznie.

Jeśli znajdziesz podejrzane zadania, zapisz je lub udokumentuj, aby móc je zbadać później.
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### Usługi

Ścieżki, w których złośliwe oprogramowanie może być zainstalowane jako usługa:

- **/etc/inittab**: Wywołuje skrypty inicjalizacyjne, takie jak rc.sysinit, kierując dalej do skryptów uruchamiania.
- **/etc/rc.d/** i **/etc/rc.boot/**: Zawierają skrypty do uruchamiania usług, przy czym te drugie występują w starszych wersjach systemu Linux.
- **/etc/init.d/**: Używane w niektórych wersjach systemu Linux, takich jak Debian, do przechowywania skryptów uruchamiania.
- Usługi mogą być również aktywowane za pomocą **/etc/inetd.conf** lub **/etc/xinetd/**, w zależności od wariantu systemu Linux.
- **/etc/systemd/system**: Katalog dla skryptów systemowych i menedżera usług.
- **/etc/systemd/system/multi-user.target.wants/**: Zawiera linki do usług, które powinny być uruchamiane w wieloużytkownikowym poziomie uruchamiania.
- **/usr/local/etc/rc.d/**: Dla niestandardowych lub zewnętrznych usług.
- **~/.config/autostart/**: Dla aplikacji uruchamianych automatycznie dla konkretnego użytkownika, co może być ukrytym miejscem dla złośliwego oprogramowania ukierunkowanego na użytkownika.
- **/lib/systemd/system/**: Pliki jednostek domyślnych dla całego systemu dostarczane przez zainstalowane pakiety.


### Moduły jądra

Moduły jądra Linux, często wykorzystywane przez złośliwe oprogramowanie jako komponenty rootkitu, są ładowane podczas uruchamiania systemu. Katalogi i pliki istotne dla tych modułów to:

- **/lib/modules/$(uname -r)**: Zawiera moduły dla aktualnie używanej wersji jądra.
- **/etc/modprobe.d**: Zawiera pliki konfiguracyjne do kontrolowania ładowania modułów.
- **/etc/modprobe** i **/etc/modprobe.conf**: Pliki dla globalnych ustawień modułów.

### Inne lokalizacje automatycznego uruchamiania

System Linux używa różnych plików do automatycznego uruchamiania programów po zalogowaniu użytkownika, potencjalnie ukrywając złośliwe oprogramowanie:

- **/etc/profile.d/***, **/etc/profile** i **/etc/bash.bashrc**: Wykonywane dla każdego logowania użytkownika.
- **~/.bashrc**, **~/.bash_profile**, **~/.profile** i **~/.config/autostart**: Pliki specyficzne dla użytkownika, które są uruchamiane po jego zalogowaniu.
- **/etc/rc.local**: Uruchamiany po uruchomieniu wszystkich usług systemowych, oznaczając zakończenie przejścia do środowiska wieloużytkownikowego.

## Sprawdzanie logów

Systemy Linux rejestrują aktywności użytkowników i zdarzenia systemowe za pomocą różnych plików dziennika. Te dzienniki są kluczowe do identyfikacji nieautoryzowanego dostępu, infekcji złośliwym oprogramowaniem i innych incydentów związanych z bezpieczeństwem. Kluczowe pliki dziennika to:

- **/var/log/syslog** (Debian) lub **/var/log/messages** (RedHat): Rejestrują komunikaty i aktywności na poziomie systemu.
- **/var/log/auth.log** (Debian) lub **/var/log/secure** (RedHat): Rejestrują próby uwierzytelnienia, udane i nieudane logowania.
- Użyj polecenia `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` do filtrowania istotnych zdarzeń uwierzytelniania.
- **/var/log/boot.log**: Zawiera komunikaty uruchamiania systemu.
- **/var/log/maillog** lub **/var/log/mail.log**: Rejestrują aktywności serwera poczty, przydatne do śledzenia usług związanych z pocztą.
- **/var/log/kern.log**: Przechowuje komunikaty jądra, w tym błędy i ostrzeżenia.
- **/var/log/dmesg**: Zawiera komunikaty sterowników urządzeń.
- **/var/log/faillog**: Rejestruje nieudane próby logowania, pomagając w dochodzeniu w sprawie naruszenia bezpieczeństwa.
- **/var/log/cron**: Rejestruje wykonania zadań cron.
- **/var/log/daemon.log**: Śledzi aktywności usług w tle.
- **/var/log/btmp**: Dokumentuje nieudane próby logowania.
- **/var/log/httpd/**: Zawiera dzienniki błędów i dostępu Apache HTTPD.
- **/var/log/mysqld.log** lub **/var/log/mysql.log**: Rejestrują aktywności bazy danych MySQL.
- **/var/log/xferlog**: Rejestruje transfery plików FTP.
- **/var/log/**: Zawsze sprawdzaj, czy nie ma tu nieoczekiwanych dzienników.

{% hint style="info" %}
Dzienniki systemowe i podsystemy audytu w systemach Linux mogą być wyłączone lub usunięte w przypadku włamania lub incydentu związanego z złośliwym oprogramowaniem. Ponieważ dzienniki w systemach Linux zazwyczaj zawierają najbardziej przydatne informacje o działaniach złośliwych, intruzi rutynowo je usuwają. Dlatego podczas analizy dostępnych plików dziennika ważne jest, aby szukać przerw lub wpisów w niewłaściwej kolejności, które mogą wskazywać na usunięcie lub manipulację.
{% endhint %}

**Linux przechowuje historię poleceń dla każdego użytkownika**, zapisaną w:

- ~/.bash_history
- ~/.zsh_history
- ~/.zsh_sessions/*
- ~/.python_history
- ~/.*_history

Ponadto, polecenie `last -Faiwx` dostarcza listę logowań użytkowników. Sprawdź go w celu znalezienia nieznanych lub nieoczekiwanych logowań.

Sprawdź pliki, które mogą przyznać dodatkowe uprawnienia:

- Przejrzyj plik `/etc/sudoers` w celu znalezienia nieoczekiwanych uprawnień użytkownika, które mogły zostać przyznane.
- Przejrzyj katalog `/etc/sudoers.d/` w celu znalezienia nieoczekiwanych uprawnień użytkownika, które mogły zostać przyznane.
- Sprawdź plik `/etc/groups`, aby zidentyfikować niezwykłe przynależności do grup lub uprawnienia.
- Sprawdź plik `/etc/passwd`, aby zidentyfikować niezwykłe przynależności do grup lub uprawnienia.

Niektóre aplikacje generują również swoje własne dzienniki:

- **SSH**: Sprawdź _~/.ssh/authorized_keys_ i _~/.ssh/known_hosts_ w celu znalezienia nieautoryzowanych połączeń zdalnych.
- **Pulpit Gnome**: Sprawdź _~/.recently-used.xbel_ w poszukiwaniu ostatnio używanych plików za pomocą aplikacji Gnome.
- **Firefox/Chrome**: Sprawdź historię przeglądarki i pobrane pliki w _~/.mozilla/firefox_ lub _~/.config/google-chrome_ w poszukiwaniu podejrzanej aktywności.
- **VIM**: Przejrzyj _~/.viminfo_ w celu uzyskania szczegółów dotyczących korzystania, takich jak ścieżki dostępu do plików i historia wyszukiwania.
- **Open Office**: Sprawdź ostatnio używane dokumenty, które mogą wskazywać na skompromitowane pliki.
- **FTP/SFTP**: Przejrzyj dzienniki w _~/.ftp_history_ lub _~/.sftp_history_ w poszukiwaniu nieautoryzowanych transferów plików.
- **MySQL**: Zbadaj _~/.mysql_history_ w celu znalezienia wykonanych zapytań MySQL, które mogą ujawnić nieautoryzowane działania na bazie danych.
- **Less**: Analizuj _~/.lesshst_ w celu uzyskania historii korzystania, w tym przeglądanych plików i wykonanych poleceń.
- **Git**: Sprawdź _~/.gitconfig_ i _.git/logs_ projektu w celu znalezienia zmian w repozytoriach.

### Dzienniki USB

[**usbrip**](https://github.com/snovvcrash/usbrip) to niewielkie oprogramowanie napisane w czystym Pythonie 3, które analizuje pliki dziennika systemu Linux (`/var/log/syslog*` lub `/var/log/messages*` w zależności od dystrybucji) w celu tworzenia tabel historii zdarzeń USB.

Warto **znać wszystkie używane urządzenia USB**, a będzie to bardziej przydatne, jeśli masz autoryzowaną listę urządzeń USB, aby znaleźć "zdarzenia naruszenia" (użycie urządzeń USB, które nie znajdują się na tej liście).

### Instalacja
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Przykłady

#### Przykład 1: Analiza pliku logów systemowych

1. Zidentyfikuj lokalizację plików logów systemowych na systemie Linux. Zwykle są one przechowywane w katalogu `/var/log`.

2. Wybierz odpowiedni plik logów, który chcesz zbadać. Na przykład, jeśli interesuje Cię log związany z autoryzacją, możesz wybrać plik `/var/log/auth.log`.

3. Skorzystaj z narzędzi takich jak `cat`, `less` lub `grep`, aby przeglądać zawartość wybranego pliku logów. Na przykład, możesz użyć polecenia `cat /var/log/auth.log` do wyświetlenia całej zawartości pliku.

4. Przeanalizuj logi w poszukiwaniu podejrzanych aktywności, takich jak nieudane próby logowania, podejrzane adresy IP lub nieznane procesy.

5. Jeśli zauważysz coś podejrzanego, zapisz odpowiednie informacje, takie jak daty, adresy IP lub nazwy procesów.

6. Przeanalizuj inne pliki logów systemowych, które mogą być powiązane z podejrzaną aktywnością.

#### Przykład 2: Analiza obrazu dysku

1. Skopiuj obraz dysku, który chcesz zbadać, na bezpieczne medium, takie jak zewnętrzny dysk twardy lub serwer plików.

2. Skorzystaj z narzędzi takich jak `Autopsy` lub `The Sleuth Kit`, aby przeprowadzić analizę obrazu dysku. Te narzędzia umożliwiają przeglądanie zawartości obrazu, odzyskiwanie plików, analizę rejestru systemowego i wiele innych.

3. Przeanalizuj strukturę katalogów i plików w obrazie dysku, aby znaleźć potencjalnie interesujące informacje. Możesz szukać plików z rozszerzeniami, które wskazują na dane użytkownika, takie jak pliki tekstowe, dokumenty, obrazy itp.

4. Przeanalizuj rejestry systemowe, takie jak rejestry Windows lub pliki dziennika systemowego Linux, w celu znalezienia śladów podejrzanej aktywności, takiej jak instalacja podejrzanych programów, zmiany w ustawieniach systemowych itp.

5. Jeśli zauważysz coś podejrzanego, zapisz odpowiednie informacje, takie jak nazwy plików, daty modyfikacji, ścieżki dostępu itp.

6. Przeanalizuj inne obszary obrazu dysku, takie jak przestrzeń nieprzydzielona lub ukryte partycje, w celu znalezienia dodatkowych informacji.

#### Przykład 3: Analiza ruchu sieciowego

1. Skorzystaj z narzędzi takich jak `Wireshark` lub `tcpdump`, aby przechwycić ruch sieciowy na systemie Linux.

2. Skonfiguruj narzędzie do przechwytywania ruchu na odpowiednim interfejsie sieciowym. Na przykład, jeśli chcesz przechwycić ruch na interfejsie eth0, użyj polecenia `sudo tcpdump -i eth0 -w capture.pcap`.

3. Przeglądaj przechwycony ruch sieciowy w narzędziu analizy pakietów, takim jak `Wireshark`. Możesz filtrować pakiety według różnych kryteriów, takich jak adresy IP, porty, protokoły itp.

4. Przeanalizuj pakiety w poszukiwaniu podejrzanych aktywności, takich jak nieznane połączenia, podejrzane protokoły, niezwykłe wielkości pakietów itp.

5. Jeśli zauważysz coś podejrzanego, zapisz odpowiednie informacje, takie jak adresy IP, porty, treść pakietów itp.

6. Przeanalizuj inne przechwycone sesje sieciowe, które mogą być powiązane z podejrzaną aktywnością.

#### Przykład 4: Analiza plików cookie

1. Zlokalizuj pliki cookie na systemie Linux. Zwykle są one przechowywane w katalogu domowym użytkownika w folderze `.mozilla` lub `.config/google-chrome`.

2. Skorzystaj z narzędzi takich jak `cat` lub `less`, aby przeglądać zawartość plików cookie. Na przykład, możesz użyć polecenia `cat ~/.mozilla/firefox/*.default/cookies.sqlite` do wyświetlenia zawartości pliku cookie dla przeglądarki Firefox.

3. Przeanalizuj zawartość plików cookie w poszukiwaniu informacji, takich jak zapisane sesje logowania, preferencje użytkownika, dane autoryzacyjne itp.

4. Jeśli zauważysz coś podejrzanego, zapisz odpowiednie informacje, takie jak nazwy stron internetowych, identyfikatory sesji, dane autoryzacyjne itp.

5. Przeanalizuj inne pliki cookie, które mogą być powiązane z podejrzaną aktywnością.

#### Przykład 5: Analiza plików dziennika aplikacji

1. Zidentyfikuj lokalizację plików dziennika aplikacji na systemie Linux. Zwykle są one przechowywane w katalogu `/var/log` lub w katalogu domowym użytkownika w folderze `.log`.

2. Wybierz odpowiedni plik dziennika aplikacji, który chcesz zbadać. Na przykład, jeśli interesuje Cię log aplikacji Apache, możesz wybrać plik `/var/log/apache2/access.log`.

3. Skorzystaj z narzędzi takich jak `cat`, `less` lub `grep`, aby przeglądać zawartość wybranego pliku dziennika. Na przykład, możesz użyć polecenia `cat /var/log/apache2/access.log` do wyświetlenia całej zawartości pliku.

4. Przeanalizuj dzienniki aplikacji w poszukiwaniu informacji, takich jak żądania HTTP, błędy aplikacji, adresy IP klientów itp.

5. Jeśli zauważysz coś podejrzanego, zapisz odpowiednie informacje, takie jak daty, adresy IP, treść żądań itp.

6. Przeanalizuj inne pliki dziennika aplikacji, które mogą być powiązane z podejrzaną aktywnością.
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Więcej przykładów i informacji znajdziesz na githubie: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)



<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}



## Przeglądaj konta użytkowników i aktywności logowania

Sprawdź pliki _**/etc/passwd**_, _**/etc/shadow**_ oraz **dzienniki zabezpieczeń** w celu znalezienia nietypowych nazw lub kont utworzonych lub używanych w pobliżu znanych nieautoryzowanych zdarzeń. Sprawdź również możliwe ataki brute-force na sudo.\
Dodatkowo, sprawdź pliki takie jak _**/etc/sudoers**_ i _**/etc/groups**_ w celu znalezienia nieoczekiwanych uprawnień przyznanych użytkownikom.\
Na koniec, poszukaj kont bez hasła lub z łatwo odgadnionymi hasłami.

## Sprawdzanie systemu plików

### Analiza struktur systemu plików w śledztwie dotyczącym złośliwego oprogramowania

Podczas badania incydentów związanych z złośliwym oprogramowaniem, struktura systemu plików jest kluczowym źródłem informacji, ujawniającym zarówno sekwencję zdarzeń, jak i zawartość złośliwego oprogramowania. Jednak autorzy złośliwego oprogramowania opracowują techniki utrudniające tę analizę, takie jak modyfikowanie znaczników czasowych plików lub unikanie systemu plików do przechowywania danych.

Aby przeciwdziałać tym antyforensycznym metodom, ważne jest:

- **Przeprowadzenie dokładnej analizy chronologicznej** za pomocą narzędzi takich jak **Autopsy** do wizualizacji chronologii zdarzeń lub **Sleuth Kit's** `mactime` do uzyskania szczegółowych danych chronologicznych.
- **Badanie nieoczekiwanych skryptów** w ścieżce systemowej $PATH, które mogą zawierać skrypty powłoki lub PHP używane przez atakujących.
- **Sprawdzanie katalogu `/dev` pod kątem nietypowych plików**, ponieważ tradycyjnie zawiera on specjalne pliki, ale może również zawierać pliki związane z złośliwym oprogramowaniem.
- **Szukanie ukrytych plików lub katalogów** o nazwach takich jak ".. " (kropka kropka spacja) lub "..^G" (kropka kropka control-G), które mogą ukrywać złośliwe treści.
- **Identyfikowanie plików setuid root** za pomocą polecenia:
```find / -user root -perm -04000 -print```
To znajduje pliki z podwyższonymi uprawnieniami, które mogą być wykorzystane przez atakujących.
- **Sprawdzanie znaczników czasu usunięcia** w tabelach inodów w celu wykrycia masowych usunięć plików, co może wskazywać na obecność rootkitów lub trojanów.
- **Sprawdzanie kolejnych inodów** w poszukiwaniu pobliskich złośliwych plików po zidentyfikowaniu jednego, ponieważ mogą one zostać umieszczone razem.
- **Sprawdzanie wspólnych katalogów binarnych** (_/bin_, _/sbin_) pod kątem niedawno zmodyfikowanych plików, ponieważ mogą być one zmieniane przez złośliwe oprogramowanie.
```bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
```
{% hint style="info" %}
Zauważ, że **atakujący** może **zmodyfikować** **czas**, aby **pliki wydawały się** **legitymacyjne**, ale nie może zmienić **inode**. Jeśli zauważysz, że **plik wskazuje**, że został utworzony i zmodyfikowany w **tym samym czasie** co reszta plików w tym samym folderze, ale **inode** jest **niespodziewanie większy**, to znaczy, że **zostały zmodyfikowane znaczniki czasowe tego pliku**.
{% endhint %}

## Porównywanie plików różnych wersji systemu plików

### Podsumowanie porównania wersji systemu plików

Aby porównać wersje systemu plików i zlokalizować zmiany, używamy uproszczonych poleceń `git diff`:

- **Aby znaleźć nowe pliki**, porównaj dwa katalogi:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Dla zmodyfikowanej zawartości**, wymień zmiany, ignorując konkretne linie:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Wykrywanie usuniętych plików**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Opcje filtrowania** (`--diff-filter`) pomagają zawęzić wyniki do konkretnych zmian, takich jak dodane (`A`), usunięte (`D`) lub zmodyfikowane (`M`) pliki.
- `A`: Dodane pliki
- `C`: Skopiowane pliki
- `D`: Usunięte pliki
- `M`: Zmodyfikowane pliki
- `R`: Zmienione nazwy plików
- `T`: Zmiany typu (np. plik na symlink)
- `U`: Niescalone pliki
- `X`: Nieznane pliki
- `B`: Uszkodzone pliki

## Odwołania

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Książka: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!

* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Zdobądź dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
