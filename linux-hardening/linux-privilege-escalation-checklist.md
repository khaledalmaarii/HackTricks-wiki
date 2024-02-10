# Checkliste - Linux Privilege Escalation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Insights**\
Beschäftigen Sie sich mit Inhalten, die sich mit dem Nervenkitzel und den Herausforderungen des Hackens befassen.

**Echtzeit-Hack-News**\
Bleiben Sie mit der schnelllebigen Hacking-Welt durch Echtzeit-Nachrichten und Einblicke auf dem Laufenden.

**Neueste Ankündigungen**\
Bleiben Sie über die neuesten Bug-Bounties und wichtige Plattformupdates informiert.

**Treten Sie uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und arbeiten Sie noch heute mit Top-Hackern zusammen!

### **Bestes Tool zur Suche nach Linux Local Privilege Escalation-Vektoren:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Systeminformationen](privilege-escalation/#system-information)

* [ ] Holen Sie sich **OS-Informationen**
* [ ] Überprüfen Sie den [**PATH**](privilege-escalation/#path), irgendein **beschreibbarer Ordner**?
* [ ] Überprüfen Sie [**Umgebungsvariablen**](privilege-escalation/#env-info), irgendein sensibles Detail?
* [ ] Suchen Sie nach [**Kernel-Exploits**](privilege-escalation/#kernel-exploits) **unter Verwendung von Skripten** (DirtyCow?)
* [ ] **Überprüfen** Sie, ob die [**sudo-Version anfällig ist**](privilege-escalation/#sudo-version)
* [ ] [**Dmesg**-Signaturüberprüfung fehlgeschlagen](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Weitere Systemenummerierung ([Datum, Systemstatistiken, CPU-Informationen, Drucker](privilege-escalation/#more-system-enumeration))
* [ ] [Weitere Verteidigungen aufzählen](privilege-escalation/#enumerate-possible-defenses)

### [Laufwerke](privilege-escalation/#drives)

* [ ] **Auflisten von** eingebundenen Laufwerken
* [ ] **Irgendein nicht eingebundenes Laufwerk**?
* [ ] **Irgendeine Anmeldeinformationen in fstab**?

### [**Installierte Software**](privilege-escalation/#installed-software)

* [ ] **Überprüfen Sie auf**[ **nützliche installierte Software**](privilege-escalation/#useful-software)
* [ ] **Überprüfen Sie auf** [**verwundbare installierte Software**](privilege-escalation/#vulnerable-software-installed)

### [Prozesse](privilege-escalation/#processes)

* [ ] Läuft eine **unbekannte Software**?
* [ ] Läuft eine Software mit **höheren Berechtigungen als erforderlich**?
* [ ] Suchen Sie nach **Exploits von laufenden Prozessen** (insbesondere der verwendeten Version).
* [ ] Können Sie die **Binärdatei** eines laufenden Prozesses **ändern**?
* [ ] **Überwachen Sie Prozesse** und überprüfen Sie, ob häufig ein interessanter Prozess ausgeführt wird.
* [ ] Können Sie den Speicher einiger interessanter Prozesse **lesen** (wo Passwörter gespeichert sein könnten)?

### [Geplante/Cron-Jobs?](privilege-escalation/#scheduled-jobs)

* [ ] Wird der [**PATH** ](privilege-escalation/#cron-path)von einem Cron-Job geändert und können Sie darin **schreiben**?
* [ ] Irgendein [**Platzhalter** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)in einem Cron-Job?
* [ ] Wird ein [**änderbares Skript** ](privilege-escalation/#cron-script-overwriting-and-symlink)**ausgeführt** oder befindet sich in einem **änderbaren Ordner**?
* [ ] Haben Sie festgestellt, dass ein **Skript** sehr **häufig** ausgeführt wird](privilege-escalation/#frequent-cron-jobs)? (alle 1, 2 oder 5 Minuten)

### [Dienste](privilege-escalation/#services)

* [ ] Irgendeine **beschreibbare .service**-Datei?
* [ ] Irgendeine von einem **Dienst ausgeführte beschreibbare Binärdatei**?
* [ ] Irgendein **beschreibbarer Ordner im systemd-PATH**?

### [Timer](privilege-escalation/#timers)

* [ ] Irgendein **beschreibbarer Timer**?

### [Sockets](privilege-escalation/#sockets)

* [ ] Irgendeine **beschreibbare .socket**-Datei?
* [ ] Können Sie mit einem beliebigen Socket **kommunizieren**?
* [ ] **HTTP-Sockets** mit interessanten Informationen?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Können Sie mit einem beliebigen D-Bus **kommunizieren**?

### [Netzwerk](privilege-escalation/#network)

* [ ] Enumerieren Sie das Netzwerk, um zu wissen, wo Sie sich befinden
* [ ] **Offene Ports, auf die Sie vorher keinen Zugriff hatten**, nachdem Sie eine Shell in der Maschine haben?
* [ ] Können Sie den Datenverkehr mit `tcpdump` **mitschneiden**?

### [Benutzer](privilege-escalation/#users)

* [ ] Generische Benutzer/Gruppen-**Enumeration**
* [ ] Haben Sie eine **sehr große UID**? Ist die **Maschine** **anfällig**?
* [ ] Können Sie durch eine Gruppe [**Berechtigungen eskalieren**](privilege-escalation/interesting-groups-linux-pe/), der Sie angehören?
* [ ] **Zwischenablage**-Daten?
* [ ] Passwortrichtlinie?
* [ ] Versuchen Sie, **jedes bekannte Passwort** einzusetzen, das Sie zuvor entdeckt haben, um sich **mit jedem** möglichen **Benutzer** anzumelden. Versuchen Sie auch, sich ohne Passwort anzumelden.

### [Beschreibbarer PATH](privilege-escalation/#writable-path-abuses)

* [ ] Wenn Sie **Schreibrechte über einen Ordner im PATH** haben, können Sie Berechtigungen eskalieren

### [SUDO- und SUID-Befehle](privilege
### [Capabilities](privilege-escalation/#capabilities)

* [ ] Hat irgendeine Binärdatei eine **unerwartete Berechtigung**?

### [ACLs](privilege-escalation/#acls)

* [ ] Hat irgendeine Datei eine **unerwartete ACL**?

### [Offene Shell-Sitzungen](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL vorhersagbarer PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Interessante SSH-Konfigurationswerte**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interessante Dateien](privilege-escalation/#interesting-files)

* [ ] **Profildateien** - Sensible Daten lesen? Für Privilege Escalation schreiben?
* [ ] **passwd/shadow-Dateien** - Sensible Daten lesen? Für Privilege Escalation schreiben?
* [ ] **Überprüfen Sie häufig interessante Ordner** auf sensible Daten
* [ ] **Seltsame Position/Besitztümer von Dateien**, auf die Sie möglicherweise zugreifen oder ausführbare Dateien ändern können
* [ ] **In den letzten Minuten geändert**
* [ ] **Sqlite DB-Dateien**
* [ ] **Versteckte Dateien**
* [ ] **Skripte/Binärdateien im PATH**
* [ ] **Webdateien** (Passwörter?)
* [ ] **Backups**?
* [ ] **Bekannte Dateien, die Passwörter enthalten**: Verwenden Sie **Linpeas** und **LaZagne**
* [ ] **Allgemeine Suche**

### [**Schreibbare Dateien**](privilege-escalation/#writable-files)

* [ ] **Python-Bibliothek ändern**, um beliebige Befehle auszuführen?
* [ ] Können Sie **Logdateien ändern**? **Logtotten**-Exploit
* [ ] Können Sie **/etc/sysconfig/network-scripts/** ändern? Centos/Redhat-Exploit
* [ ] Können Sie in ini-, int.d-, systemd- oder rc.d-Dateien [**schreiben**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Andere Tricks**](privilege-escalation/#other-tricks)

* [ ] Können Sie [**NFS missbrauchen, um Privilegien zu eskalieren**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Müssen Sie aus einer restriktiven Shell [**entkommen**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)-Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Insights**\
Beschäftigen Sie sich mit Inhalten, die sich mit dem Nervenkitzel und den Herausforderungen des Hackens befassen.

**Echtzeit-Hack-News**\
Bleiben Sie mit der schnelllebigen Hacking-Welt durch Echtzeit-Nachrichten und Einblicke auf dem Laufenden.

**Neueste Ankündigungen**\
Bleiben Sie über die neuesten Bug-Bounties und wichtigen Plattformupdates informiert.

**Treten Sie uns bei** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginnen Sie noch heute mit Top-Hackern zusammenzuarbeiten!

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
