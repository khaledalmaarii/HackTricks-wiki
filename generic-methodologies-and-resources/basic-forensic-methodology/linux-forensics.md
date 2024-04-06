# Analiza śladów w systemie Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społeczności.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Zacznij od zera i zostań ekspertem od hakowania AWS z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Początkowe zbieranie informacji

### Podstawowe informacje

Po pierwsze, zaleca się posiadanie **pendrive'a** z **znanymi dobrymi binarkami i bibliotekami** (możesz po prostu pobrać Ubuntu i skopiować foldery _/bin_, _/sbin_, _/lib_ i _/lib64_), następnie zamontuj pendrive i zmodyfikuj zmienne środowiskowe, aby używać tych binarek:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Gdy skonfigurowano system do użycia dobrych i znanych binariów, można rozpocząć **wydobywanie podstawowych informacji**:
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

Podczas uzyskiwania podstawowych informacji należy sprawdzić dziwne rzeczy, takie jak:

- Procesy **Roota** zazwyczaj działają z niskimi PID-ami, więc jeśli znajdziesz proces Roota z dużym PID-em, możesz podejrzewać
- Sprawdź **zarejestrowane logowania** użytkowników bez powłoki wewnątrz `/etc/passwd`
- Sprawdź **hashe haseł** wewnątrz `/etc/shadow` dla użytkowników bez powłoki

### Zrzut pamięci

Aby uzyskać pamięć działającego systemu, zaleca się użycie [**LiME**](https://github.com/504ensicsLabs/LiME).\
Aby go **skompilować**, musisz użyć **tego samego jądra**, którego używa maszyna ofiary.

{% hint style="info" %}
Pamiętaj, że **nie możesz zainstalować LiME ani niczego innego** na maszynie ofiary, ponieważ spowoduje to kilka zmian w niej
{% endhint %}

Więc jeśli masz identyczną wersję Ubuntu, możesz użyć `apt-get install lime-forensics-dkms`\
W innych przypadkach musisz pobrać [**LiME**](https://github.com/504ensicsLabs/LiME) z githuba i skompilować go z odpowiednimi nagłówkami jądra. Aby **uzyskać dokładne nagłówki jądra** maszyny ofiary, możesz po prostu **skopiować katalog** `/lib/modules/<wersja jądra>` na swoją maszynę, a następnie **skompilować** LiME, używając ich:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME obsługuje 3 **formaty**:

* Surowy (każdy segment sklejony razem)
* Wyściełany (to samo co surowy, ale z zerami na prawej stronie)
* Lime (zalecany format z metadanymi)

LiME można również użyć do **wysłania zrzutu przez sieć** zamiast przechowywania go w systemie, używając czegoś takiego jak: `path=tcp:4444`

### Tworzenie obrazu dysku

#### Wyłączenie

Po pierwsze, będziesz musiał **wyłączyć system**. To nie zawsze jest opcja, ponieważ czasami system będzie serwerem produkcyjnym, którego firma nie może sobie pozwolić na wyłączenie.\
Istnieją **2 sposoby** wyłączenia systemu, **normalne wyłączenie** i **wyłączenie "wyciągnij wtyczkę"**. Pierwsze pozwoli **procesom zakończyć działanie jak zwykle** i **zsynchronizować system plików**, ale pozwoli również ewentualnemu **malware** na **zniszczenie dowodów**. Podejście "wyciągnij wtyczkę" może wiązać się z **pewną utratą informacji** (nie wiele informacji zostanie utraconych, ponieważ już zrobiliśmy obraz pamięci) i **malware nie będzie miał szansy** na zrobienie czegokolwiek w tej sprawie. Dlatego jeśli **podejrzewasz**, że może być **malware**, po prostu wykonaj polecenie **`sync`** na systemie i wyciągnij wtyczkę.

#### Tworzenie obrazu dysku

Ważne jest zauważenie, że **przed podłączeniem komputera do czegokolwiek związanego z sprawą**, musisz upewnić się, że będzie on **zamontowany jako tylko do odczytu**, aby uniknąć modyfikowania jakichkolwiek informacji.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Korzystaj z [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować** przepływy pracy z wykorzystaniem najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Wyszukiwanie znanego oprogramowania złośliwego

### Zmodyfikowane pliki systemowe

Linux oferuje narzędzia do zapewnienia integralności komponentów systemowych, co jest kluczowe dla wykrywania potencjalnie problematycznych plików.

* **Systemy oparte na RedHat**: Użyj `rpm -Va` dla kompleksowej kontroli.
* **Systemy oparte na Debian**: `dpkg --verify` dla wstępnej weryfikacji, a następnie `debsums | grep -v "OK$"` (po zainstalowaniu `debsums` za pomocą `apt-get install debsums`) w celu zidentyfikowania ewentualnych problemów.

### Detektory oprogramowania złośliwego/rootkitów

Przeczytaj następną stronę, aby dowiedzieć się o narzędziach, które mogą być przydatne do wykrywania oprogramowania złośliwego:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Wyszukiwanie zainstalowanych programów

Aby skutecznie wyszukiwać zainstalowane programy zarówno w systemach Debian, jak i RedHat, rozważ wykorzystanie logów systemowych i baz danych w połączeniu z ręcznymi sprawdzeniami w powszechnych katalogach.

* Dla systemu Debian, sprawdź _**`/var/lib/dpkg/status`**_ i _**`/var/log/dpkg.log`**_, aby uzyskać szczegóły dotyczące instalacji pakietów, używając `grep` do filtrowania konkretnych informacji.
* Użytkownicy RedHat mogą zapytać bazę danych RPM za pomocą `rpm -qa --root=/mntpath/var/lib/rpm`, aby wyświetlić zainstalowane pakiety.

Aby odkryć oprogramowanie zainstalowane ręcznie lub poza tymi menedżerami pakietów, przejrzyj katalogi takie jak _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ i _**`/sbin`**_. Połącz listy katalogów z poleceniami specyficznymi dla systemu, aby zidentyfikować pliki wykonywalne niepowiązane z znanymi pakietami, zwiększając tym samym skuteczność wyszukiwania wszystkich zainstalowanych programów.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), aby łatwo budować i **automatyzować** przepływy pracy z wykorzystaniem najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Odzyskiwanie Usuniętych Wykonywalnych Binaries

Wyobraź sobie proces, który został uruchomiony z /tmp/exec, a następnie usunięty. Jest możliwe jego wydobycie.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Sprawdź lokalizacje automatycznego uruchamiania

### Zaplanowane zadania
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

Ścieżki, w których złośliwe oprogramowanie może zostać zainstalowane jako usługa:

- **/etc/inittab**: Wywołuje skrypty inicjalizacyjne, takie jak rc.sysinit, kierując dalej do skryptów uruchamiania.
- **/etc/rc.d/** i **/etc/rc.boot/**: Zawierają skrypty do uruchamiania usług, przy czym te drugie można znaleźć w starszych wersjach systemu Linux.
- **/etc/init.d/**: Używane w niektórych wersjach systemu Linux, takich jak Debian, do przechowywania skryptów uruchamiania.
- Usługi mogą być aktywowane również za pomocą **/etc/inetd.conf** lub **/etc/xinetd/**, w zależności od wariantu systemu Linux.
- **/etc/systemd/system**: Katalog dla skryptów systemowych i menedżera usług.
- **/etc/systemd/system/multi-user.target.wants/**: Zawiera odnośniki do usług, które powinny zostać uruchomione w wielu poziomach uruchamiania.
- **/usr/local/etc/rc.d/**: Dla niestandardowych lub zewnętrznych usług.
- **\~/.config/autostart/**: Dla aplikacji uruchamianych automatycznie dla konkretnego użytkownika, co może być miejscem ukrycia dla złośliwego oprogramowania ukierunkowanego na użytkownika.
- **/lib/systemd/system/**: Pliki jednostek domyślnych dla całego systemu dostarczane przez zainstalowane pakiety.

### Moduły jądra

Moduły jądra Linux, często wykorzystywane przez złośliwe oprogramowanie jako komponenty rootkitów, są ładowane podczas uruchamiania systemu. Istotne katalogi i pliki dla tych modułów to:

- **/lib/modules/$(uname -r)**: Zawiera moduły dla działającej wersji jądra.
- **/etc/modprobe.d**: Zawiera pliki konfiguracyjne do kontrolowania ładowania modułów.
- **/etc/modprobe** i **/etc/modprobe.conf**: Pliki dla globalnych ustawień modułów.

### Inne lokalizacje automatycznego uruchamiania

System Linux wykorzystuje różne pliki do automatycznego uruchamiania programów po zalogowaniu użytkownika, potencjalnie ukrywając złośliwe oprogramowanie:

- **/etc/profile.d/**\*, **/etc/profile** i **/etc/bash.bashrc**: Wykonywane dla każdego logowania użytkownika.
- **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile** i **\~/.config/autostart**: Pliki specyficzne dla użytkownika, które są uruchamiane po ich zalogowaniu.
- **/etc/rc.local**: Uruchamiany po uruchomieniu wszystkich usług systemowych, oznaczając zakończenie przejścia do środowiska wieloużytkownika.

## Analiza logów

Systemy Linux śledzą aktywności użytkowników i zdarzenia systemowe za pomocą różnych plików dziennika. Te dzienniki są kluczowe do identyfikowania nieautoryzowanego dostępu, infekcji złośliwym oprogramowaniem i innych incydentów związanych z bezpieczeństwem. Kluczowe pliki dziennika obejmują:

- **/var/log/syslog** (Debian) lub **/var/log/messages** (RedHat): Zapisują komunikaty i aktywności na poziomie systemu.
- **/var/log/auth.log** (Debian) lub **/var/log/secure** (RedHat): Rejestrują próby uwierzytelnienia, udane i nieudane logowania.
- Użyj `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` do filtrowania istotnych zdarzeń uwierzytelniania.
- **/var/log/boot.log**: Zawiera komunikaty uruchamiania systemu.
- **/var/log/maillog** lub **/var/log/mail.log**: Rejestrują aktywności serwera poczty e-mail, przydatne do śledzenia usług związanych z e-mailem.
- **/var/log/kern.log**: Przechowuje komunikaty jądra, w tym błędy i ostrzeżenia.
- **/var/log/dmesg**: Zawiera komunikaty sterowników urządzeń.
- **/var/log/faillog**: Rejestruje nieudane próby logowania, pomagając w dochodzeniach dotyczących naruszeń bezpieczeństwa.
- **/var/log/cron**: Rejestruje wykonania zadań cron.
- **/var/log/daemon.log**: Śledzi aktywności usług w tle.
- **/var/log/btmp**: Dokumentuje nieudane próby logowania.
- **/var/log/httpd/**: Zawiera dzienniki błędów i dostępu Apache HTTPD.
- **/var/log/mysqld.log** lub **/var/log/mysql.log**: Rejestrują aktywności bazy danych MySQL.
- **/var/log/xferlog**: Rejestruje transfery plików FTP.
- **/var/log/**: Zawsze sprawdzaj tutaj nieoczekiwane dzienniki.

{% hint style="info" %}
Dzienniki systemowe i systemy audytu Linux mogą zostać wyłączone lub usunięte podczas incydentu związanego z włamaniem lub złośliwym oprogramowaniem. Ponieważ dzienniki w systemach Linux zazwyczaj zawierają najbardziej przydatne informacje o działaniach złośliwych, intruzi rutynowo je usuwają. Dlatego podczas analizy dostępnych plików dziennika ważne jest sprawdzenie luk lub nieuporządkowanych wpisów, które mogą wskazywać na usunięcie lub manipulację.
{% endhint %}

**Linux przechowuje historię poleceń dla każdego użytkownika**, zapisaną w:

- \~/.bash\_history
- \~/.zsh\_history
- \~/.zsh\_sessions/\*
- \~/.python\_history
- \~/.\*\_history

Ponadto polecenie `last -Faiwx` dostarcza listę logowań użytkowników. Sprawdź go pod kątem nieznanych lub nieoczekiwanych logowań.

Sprawdź pliki, które mogą przyznać dodatkowe uprawnienia:

- Przejrzyj `/etc/sudoers` w poszukiwaniu nieoczekiwanych uprawnień użytkownika, które mogły zostać przyznane.
- Przejrzyj `/etc/sudoers.d/` w poszukiwaniu nieoczekiwanych uprawnień użytkownika, które mogły zostać przyznane.
- Sprawdź `/etc/groups`, aby zidentyfikować niezwykłe przynależności do grup lub uprawnienia.
- Sprawdź `/etc/passwd`, aby zidentyfikować niezwykłe przynależności do grup lub uprawnienia.

Niektóre aplikacje generują również swoje własne dzienniki:

- **SSH**: Sprawdź _\~/.ssh/authorized\_keys_ i _\~/.ssh/known\_hosts_ w poszukiwaniu nieautoryzowanych połączeń zdalnych.
- **Pulpit Gnome**: Sprawdź _\~/.recently-used.xbel_ w poszukiwaniu niedawno używanych plików za pomocą aplikacji Gnome.
- **Firefox/Chrome**: Sprawdź historię przeglądarki i pobrania w _\~/.mozilla/firefox_ lub _\~/.config/google-chrome_ w poszukiwaniu podejrzanych aktywności.
- **VIM**: Przejrzyj _\~/.viminfo_ w poszukiwaniu szczegółów dotyczących użytkowania, takich jak ścieżki dostępu do plików i historia wyszukiwania.
- **Open Office**: Sprawdź niedawne dostępy do dokumentów, które mogą wskazywać na skompromitowane pliki.
- **FTP/SFTP**: Przejrzyj dzienniki w _\~/.ftp\_history_ lub _\~/.sftp\_history_ w poszukiwaniu transferów plików, które mogą być nieautoryzowane.
- **MySQL**: Zbadaj _\~/.mysql\_history_ w poszukiwaniu wykonanych zapytań MySQL, potencjalnie ujawniających nieautoryzowane działania na bazie danych.
- **Less**: Analizuj _\~/.lesshst_ w poszukiwaniu historii użytkowania, w tym przeglądanych plików i wykonanych poleceń.
- **Git**: Sprawdź _\~/.gitconfig_ i projekt _.git/logs_ w poszukiwaniu zmian w repozytoriach.

### Dzienniki USB

[**usbrip**](https://github.com/snovvcrash/usbrip) to niewielkie oprogramowanie napisane w czystym Pythonie 3, które analizuje pliki dziennika systemu Linux (`/var/log/syslog*` lub `/var/log/messages*` w zależności od dystrybucji) w celu tworzenia tabel historii zdarzeń USB.

Warto **znać wszystkie używane urządzenia USB**, a będzie to bardziej przydatne, jeśli masz autoryzowaną listę urządzeń USB do znalezienia "zdarzeń naruszenia" (użycie urządzeń USB spoza tej listy).

### Instalacja
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Przykłady
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Więcej przykładów i informacji znajdziesz na githubie: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Korzystaj z [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) do łatwego tworzenia i **automatyzacji prac** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Przegląd Kont Użytkowników i Aktywności Logowania

Sprawdź pliki _**/etc/passwd**_, _**/etc/shadow**_ oraz **dzienniki bezpieczeństwa** pod kątem nietypowych nazw lub kont utworzonych i/lub używanych w pobliżu znanych nieautoryzowanych zdarzeń. Sprawdź również możliwe ataki brute-force na sudo.\
Dodatkowo, sprawdź pliki takie jak _**/etc/sudoers**_ i _**/etc/groups**_ pod kątem nieoczekiwanych uprawnień nadanych użytkownikom.\
Na koniec, poszukaj kont bez **hasła** lub z łatwo **odgadnialnymi** hasłami.

## Badanie Systemu Plików

### Analiza Struktur Systemu Plików w Śledztwie w Sprawie Malware

Podczas badania incydentów związanych z malware, struktura systemu plików jest kluczowym źródłem informacji, ujawniając zarówno sekwencję zdarzeń, jak i zawartość malware. Autorzy malware rozwijają jednak techniki utrudniające tę analizę, takie jak modyfikowanie znaczników czasowych plików lub unikanie systemu plików do przechowywania danych.

Aby przeciwdziałać tym antyforensycznym metodom, istotne jest:

* **Przeprowadzenie dokładnej analizy chronologicznej** za pomocą narzędzi takich jak **Autopsy** do wizualizacji chronologii zdarzeń lub `mactime` z **Sleuth Kit** do uzyskania szczegółowych danych chronologicznych.
* **Badanie nieoczekiwanych skryptów** w $PATH systemu, które mogą zawierać skrypty powłoki lub PHP używane przez atakujących.
* **Sprawdzenie `/dev` pod kątem nietypowych plików**, ponieważ tradycyjnie zawiera on pliki specjalne, ale może zawierać pliki związane z malware.
* **Wyszukiwanie ukrytych plików lub katalogów** o nazwach ".. " (kropka kropka spacja) lub "..^G" (kropka kropka control-G), które mogą ukrywać złośliwe treści.
* **Identyfikacja plików setuid root** za pomocą polecenia: `find / -user root -perm -04000 -print` To znajduje pliki z podwyższonymi uprawnieniami, które mogą być wykorzystane przez atakujących.
* **Sprawdzenie znaczników czasu usuwania** w tabelach inode, aby zauważyć masowe usuwanie plików, co może wskazywać na obecność rootkitów lub trojanów.
* **Sprawdzenie kolejnych inode'ów** w poszukiwaniu pobliskich złośliwych plików po zidentyfikowaniu jednego, ponieważ mogły zostać umieszczone razem.
* **Sprawdzenie powszechnych katalogów binarnych** (_/bin_, _/sbin_) pod kątem niedawno zmodyfikowanych plików, ponieważ mogły zostać zmienione przez malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
Zauważ, że **atakujący** może **zmodyfikować** **czas**, aby **pliki wydawały się** **legitymacyjne**, ale nie może zmienić **inode**. Jeśli zauważysz, że **plik wskazuje**, że został utworzony i zmodyfikowany w **tym samym czasie** co reszta plików w tym samym folderze, ale **inode** jest **niespodziewanie większy**, to **znaczy, że znaczniki czasu tego pliku zostały zmodyfikowane**.
{% endhint %}

## Porównywanie plików różnych wersji systemu plików

### Podsumowanie porównania wersji systemu plików

Aby porównać wersje systemu plików i zlokalizować zmiany, używamy uproszczonych poleceń `git diff`:

* **Aby znaleźć nowe pliki**, porównaj dwie katalogi:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Dla zmodyfikowanej zawartości**, wymień zmiany, ignorując konkretne linie:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Wykrywanie usuniętych plików**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **Opcje filtrowania** (`--diff-filter`) pomagają zawęzić wyniki do konkretnych zmian, takich jak dodane (`A`), usunięte (`D`) lub zmodyfikowane (`M`) pliki.
* `A`: Dodane pliki
* `C`: Skopiowane pliki
* `D`: Usunięte pliki
* `M`: Zmodyfikowane pliki
* `R`: Zmienione nazwy plików
* `T`: Zmiany typu (np. plik na symlink)
* `U`: Niescalone pliki
* `X`: Nieznane pliki
* `B`: Uszkodzone pliki

## Referencje

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Książka: Przewodnik po śledzeniu malware dla systemów Linux: Przewodniki po śledzeniu cyfrowym**

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!

* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społeczności na świecie.\
Zdobądź dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
