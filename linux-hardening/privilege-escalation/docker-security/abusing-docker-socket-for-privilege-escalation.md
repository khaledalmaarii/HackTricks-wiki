# Missbrauch des Docker-Sockets zur Privilegieneskalation

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Es gibt einige Gelegenheiten, bei denen du **Zugriff auf den Docker-Socket** hast und ihn nutzen möchtest, um **Privilegien zu eskalieren**. Einige Aktionen könnten sehr verdächtig sein und du möchtest sie möglicherweise vermeiden, daher findest du hier verschiedene Flags, die nützlich sein können, um Privilegien zu eskalieren:

### Über Mount

Du kannst verschiedene Teile des **Dateisystems** in einem Container, der als Root läuft, **einbinden** und auf sie **zugreifen**.\
Du könntest auch **einen Mount missbrauchen, um Privilegien** innerhalb des Containers zu eskalieren.

* **`-v /:/host`** -> Binde das Host-Dateisystem im Container ein, damit du das **Host-Dateisystem lesen kannst.**
* Wenn du **das Gefühl haben möchtest, dass du im Host bist**, aber im Container bist, könntest du andere Abwehrmechanismen mit Flags wie diesen deaktivieren:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Dies ist ähnlich wie die vorherige Methode, aber hier binden wir das **Gerätedisk** ein. Dann führe im Container `mount /dev/sda1 /mnt` aus und du kannst auf das **Host-Dateisystem** in `/mnt` **zugreifen**.
* Führe `fdisk -l` im Host aus, um das `</dev/sda1>`-Gerät zu finden, das du einbinden möchtest.
* **`-v /tmp:/host`** -> Wenn du aus irgendeinem Grund **nur ein Verzeichnis** vom Host einbinden kannst und du Zugriff innerhalb des Hosts hast. Binde es ein und erstelle ein **`/bin/bash`** mit **suid** im eingebundenen Verzeichnis, damit du es **vom Host aus ausführen und zu Root eskalieren** kannst.

{% hint style="info" %}
Beachte, dass du möglicherweise den Ordner `/tmp` nicht einbinden kannst, aber du kannst einen **anderen beschreibbaren Ordner** einbinden. Du kannst beschreibbare Verzeichnisse finden, indem du: `find / -writable -type d 2>/dev/null`

**Beachte, dass nicht alle Verzeichnisse auf einer Linux-Maschine das suid-Bit unterstützen!** Um zu überprüfen, welche Verzeichnisse das suid-Bit unterstützen, führe `mount | grep -v "nosuid"` aus. Zum Beispiel unterstützen normalerweise `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` und `/var/lib/lxcfs` nicht das suid-Bit.

Beachte auch, dass wenn du **`/etc`** oder einen anderen Ordner **mit Konfigurationsdateien** einbinden kannst, du sie vom Docker-Container aus als Root ändern kannst, um sie **im Host zu missbrauchen** und Privilegien zu eskalieren (vielleicht indem du `/etc/shadow` änderst).
{% endhint %}

### Aus dem Container entkommen

* **`--privileged`** -> Mit diesem Flag [entfernst du alle Isolationen vom Container](docker-privileged.md#what-affects). Überprüfe Techniken, um [aus privilegierten Containern als Root zu entkommen](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Um [Privilegien durch Missbrauch von Fähigkeiten zu eskalieren](../linux-capabilities.md), **gewähre diese Fähigkeit dem Container** und deaktiviere andere Schutzmethoden, die verhindern könnten, dass der Exploit funktioniert.

### Curl

Auf dieser Seite haben wir Möglichkeiten zur Privilegieneskalation mit Docker-Flags besprochen, du kannst **Wege finden, diese Methoden mit dem Curl**-Befehl zu missbrauchen, auf der Seite:

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

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
