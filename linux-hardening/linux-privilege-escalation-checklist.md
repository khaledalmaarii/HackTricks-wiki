# Checkliste - Linux-Privilegieneskalation

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking-Einblicke**\
Beschäftigen Sie sich mit Inhalten, die sich mit dem Nervenkitzel und den Herausforderungen des Hackens befassen

**Echtzeit-Hack-News**\
Bleiben Sie mit der schnelllebigen Hacking-Welt durch Echtzeitnachrichten und Einblicke auf dem Laufenden

**Neueste Ankündigungen**\
Bleiben Sie über die neuesten Bug-Bounties und wichtige Plattformupdates informiert

**Treten Sie uns bei** [**Discord**](https://discord.com/invite/N3FrSbmwdy) und beginnen Sie noch heute mit Top-Hackern zusammenzuarbeiten!

### **Bestes Tool zur Suche nach Linux-lokalen Privilegieneskalationsvektoren:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Systeminformationen](privilege-escalation/#system-information)

* [ ] Erhalten Sie **Betriebssysteminformationen**
* [ ] Überprüfen Sie den [**PATH**](privilege-escalation/#path), irgendein **beschreibbarer Ordner**?
* [ ] Überprüfen Sie [**Umgebungsvariablen**](privilege-escalation/#env-info), irgendein sensibles Detail?
* [ ] Suchen Sie nach [**Kernel-Exploits**](privilege-escalation/#kernel-exploits) **unter Verwendung von Skripten** (DirtyCow?)
* [ ] **Überprüfen** Sie, ob die [**sudo-Version verwundbar ist**](privilege-escalation/#sudo-version)
* [ ] [**Dmesg**-Signaturüberprüfung fehlgeschlagen](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Weitere Systemenum (Datum, Systemstatistiken, CPU-Info, Drucker](privilege-escalation/#more-system-enumeration))
* [ ] [Mehr Verteidigungen aufzählen](privilege-escalation/#enumerate-possible-defenses)

### [Laufwerke](privilege-escalation/#drives)

* [ ] **Auflisten von** eingebundenen Laufwerken
* [ ] **Irgendein nicht eingebundenes Laufwerk?**
* [ ] **Irgendwelche Anmeldeinformationen in fstab?**

### [**Installierte Software**](privilege-escalation/#installed-software)

* [ ] **Überprüfen Sie auf** [**installierte nützliche Software**](privilege-escalation/#useful-software)
* [ ] **Überprüfen Sie auf** [**installierte verwundbare Software**](privilege-escalation/#vulnerable-software-installed)

### [Prozesse](privilege-escalation/#processes)

* [ ] Läuft eine **unbekannte Software**?
* [ ] Läuft eine Software mit **mehr Berechtigungen als sie sollte**?
* [ ] Suchen Sie nach **Exploits von laufenden Prozessen** (insbesondere der ausgeführten Version).
* [ ] Können Sie die **Binärdatei** eines laufenden Prozesses **ändern**?
* [ ] **Überwachen Sie Prozesse** und prüfen Sie, ob ein interessanter Prozess häufig ausgeführt wird.
* [ ] Können Sie einige interessante **Prozessspeicher** lesen (wo Passwörter gespeichert sein könnten)?

### [Geplante/Cron-Jobs?](privilege-escalation/#scheduled-jobs)

* [ ] Wird der [**PATH** ](privilege-escalation/#cron-path)von einem Cronjob modifiziert und Sie können darin **schreiben**?
* [ ] Irgendein [**Platzhalter** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)in einem Cron-Job?
* [ ] Wird ein [**änderbares Skript** ](privilege-escalation/#cron-script-overwriting-and-symlink)ausgeführt oder befindet sich in einem **änderbaren Ordner**?
* [ ] Haben Sie festgestellt, dass ein **Skript** sehr **häufig** (alle 1, 2 oder 5 Minuten) [**ausgeführt**](privilege-escalation/#frequent-cron-jobs) wird?

### [Dienste](privilege-escalation/#services)

* [ ] Irgendeine **beschreibbare .service**-Datei?
* [ ] Wird eine **beschreibbare Binärdatei** von einem **Dienst** ausgeführt?
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
* [ ] **Öffnen Sie Ports, auf die Sie vor dem Erhalten einer Shell innerhalb der Maschine nicht zugreifen konnten**?
* [ ] Können Sie den Datenverkehr mit `tcpdump` **mitschneiden**?

### [Benutzer](privilege-escalation/#users)

* [ ] Generische Benutzer/Gruppen **auflisten**
* [ ] Haben Sie eine **sehr große UID**? Ist die **Maschine** **anfällig**?
* [ ] Können Sie durch eine Gruppe [**Berechtigungen eskalieren**](privilege-escalation/interesting-groups-linux-pe/), der Sie angehören?
* [ ] **Zwischenablage**-Daten?
* [ ] Passwortrichtlinie?
* [ ] Versuchen Sie, jeden **bekannten Benutzernamen** zu verwenden, den Sie zuvor entdeckt haben, um sich **mit jedem** möglichen **Benutzer** anzumelden. Versuchen Sie auch, sich ohne Passwort anzumelden.

### [Beschreibbarer PATH](privilege-escalation/#writable-path-abuses)

* [ ] Wenn Sie **Schreibberechtigungen über einen Ordner im PATH** haben, können Sie Berechtigungen eskalieren

### [SUDO- und SUID-Befehle](privilege-escalation/#sudo-and-suid)

* [ ] Können Sie **einen beliebigen Befehl mit sudo ausführen**? Können Sie es verwenden, um ALS ROOT etwas zu LESEN, ZU SCHREIBEN oder AUSZUFÜHREN? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Gibt es eine **ausnutzbare SUID-Binärdatei**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Sind [**sudo**-Befehle durch **Pfad** **beschränkt**? Können Sie die Einschränkungen **umgehen**](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Sudo/SUID-Binärdatei ohne angegebenen Pfad**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**SUID-Binärdatei mit angegebenem Pfad**](privilege-escalation/#suid-binary-with-command-path)? Umgehen
* [ ] [**LD\_PRELOAD-Schwachstelle**](privilege-escalation/#ld\_preload)
* [ ] [**Fehlen einer .so-Bibliothek in SUID-Binärdatei**](privilege-escalation/#suid-binary-so-injection) aus einem beschreibbaren Ordner?
* [ ] [**SUDO-Token verfügbar**](privilege-escalation/#reusing-sudo-tokens)? [**Können Sie ein SUDO-Token erstellen**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Können Sie [**sudoers-Dateien lesen oder ändern**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Können Sie [**/etc/ld.so.conf.d/** ändern](privilege-escalation/#etc-ld-so-conf-d)?
* [**OpenBSD DOAS**](privilege-escalation/#doas) Befehl
### [Fähigkeiten](privilege-escalation/#capabilities)

* [ ] Hat irgendeine Binärdatei eine **unerwartete Fähigkeit**?

### [ACLs](privilege-escalation/#acls)

* [ ] Hat irgendeine Datei eine **unerwartete ACL**?

### [Offene Shell-Sitzungen](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Vorhersehbarer PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH Interessante Konfigurationswerte**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interessante Dateien](privilege-escalation/#interesting-files)

* [ ] **Profildateien** - Sensible Daten lesen? Schreiben für Privilege Escalation?
* [ ] **Passwd/Shadow-Dateien** - Sensible Daten lesen? Schreiben für Privilege Escalation?
* [ ] **Überprüfen von häufig interessanten Ordnern** auf sensible Daten
* [ ] **Seltsame Position/Besitztümer von Dateien,** auf die Sie zugreifen oder ausführbare Dateien ändern können
* [ ] **In den letzten Minuten geändert**
* [ ] **Sqlite-DB-Dateien**
* [ ] **Versteckte Dateien**
* [ ] **Skripte/Binärdateien im PATH**
* [ ] **Webdateien** (Passwörter?)
* [ ] **Backups**?
* [ ] **Bekannte Dateien, die Passwörter enthalten**: Verwenden Sie **Linpeas** und **LaZagne**
* [ ] **Generische Suche**

### [**Beschreibbare Dateien**](privilege-escalation/#writable-files)

* [ ] **Ändern von Python-Bibliotheken** zum Ausführen beliebiger Befehle?
* [ ] Können Sie **Logdateien ändern**? **Logtotten**-Exploit
* [ ] Können Sie **/etc/sysconfig/network-scripts/** ändern? Centos/Redhat-Exploit
* [ ] Können Sie in [**ini-, int.d-, systemd- oder rc.d-Dateien schreiben**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Andere Tricks**](privilege-escalation/#other-tricks)

* [ ] Können Sie [**NFS missbrauchen, um Privilegien zu eskalieren**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Müssen Sie aus einer restriktiven Shell [**ausbrechen**](privilege-escalation/#escaping-from-restricted-shells)?
