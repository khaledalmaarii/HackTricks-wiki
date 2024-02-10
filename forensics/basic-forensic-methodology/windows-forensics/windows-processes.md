<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


## smss.exe

**Session Manager**.\
Sitzung 0 startet **csrss.exe** und **wininit.exe** (**OS-Dienste**), während Sitzung 1 **csrss.exe** und **winlogon.exe** (**Benutzersitzung**) startet. Sie sollten jedoch **nur einen Prozess** dieser **Binärdatei** ohne Kinder im Prozessbaum sehen.

Außerdem können Sitzungen außerhalb von 0 und 1 bedeuten, dass RDP-Sitzungen stattfinden.


## csrss.exe

**Client/Server Run Subsystem Process**.\
Es verwaltet **Prozesse** und **Threads**, stellt die **Windows-API** für andere Prozesse zur Verfügung und **mappt Laufwerksbuchstaben**, erstellt **Temporärdateien** und behandelt den **Herunterfahrprozess**.

Es gibt eine **Ausführung in Sitzung 0 und eine weitere in Sitzung 1** (also **2 Prozesse** im Prozessbaum). Ein weiterer wird **pro neue Sitzung** erstellt.


## winlogon.exe

**Windows-Anmeldeprozess**.\
Es ist verantwortlich für Benutzer **An- und Abmeldungen**. Es startet **logonui.exe**, um nach Benutzername und Passwort zu fragen, und ruft dann **lsass.exe** auf, um sie zu überprüfen.

Dann startet es **userinit.exe**, die in **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** mit dem Schlüssel **Userinit** angegeben ist.

Darüber hinaus sollte der vorherige Registrierungsschlüssel **explorer.exe** im **Shell-Schlüssel** enthalten, da er sonst als **Malware-Persistenzmethode** missbraucht werden könnte.


## wininit.exe

**Windows-Initialisierungsprozess**. \
Es startet **services.exe**, **lsass.exe** und **lsm.exe** in Sitzung 0. Es sollte nur 1 Prozess geben.


## userinit.exe

**Userinit-Anmeldeanwendung**.\
Lädt die **ntuser.dat in HKCU** und initialisiert die **Benutzerumgebung** und führt **Anmelde**-**Skripte** und **GPO** aus.

Es startet **explorer.exe**.


## lsm.exe

**Lokaler Sitzungsmanager**.\
Es arbeitet mit smss.exe zusammen, um Benutzersitzungen zu manipulieren: Anmeldung/Abmeldung, Starten der Shell, Sperren/Entsperren des Desktops usw.

Nach W7 wurde lsm.exe in einen Dienst (lsm.dll) umgewandelt.

Es sollte nur 1 Prozess in W7 geben und von ihnen aus wird ein Dienst ausgeführt, der die DLL ausführt.


## services.exe

**Dienststeuerungs-Manager**.\
Es **lädt** **als automatisch gestartet** konfigurierte **Dienste** und **Treiber**.

Es ist der übergeordnete Prozess von **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** und vielen anderen.

Dienste sind in `HKLM\SYSTEM\CurrentControlSet\Services` definiert und dieser Prozess verwaltet eine im Speicher befindliche Datenbank mit Serviceinformationen, auf die mit sc.exe zugegriffen werden kann.

Beachten Sie, wie **einige** **Dienste** in einem **eigenen Prozess** ausgeführt werden und andere einen **svchost.exe-Prozess teilen**.

Es sollte nur 1 Prozess geben.


## lsass.exe

**Lokaler Sicherheitsdienst-Subsystem**.\
Es ist verantwortlich für die Benutzer **Authentifizierung** und erstellt die **Sicherheits-Token**. Es verwendet in `HKLM\System\CurrentControlSet\Control\Lsa` befindliche Authentifizierungspakete.

Es schreibt in das **Sicherheitsereignisprotokoll** und es sollte nur 1 Prozess geben.

Beachten Sie, dass dieser Prozess stark angegriffen wird, um Passwörter auszulesen.


## svchost.exe

**Generischer Diensthostprozess**.\
Es hostet mehrere DLL-Dienste in einem gemeinsamen Prozess.

Normalerweise wird **svchost.exe** mit dem Flag `-k` gestartet. Dadurch wird eine Abfrage an den Registrierungsschlüssel **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** gesendet, in dem ein Schlüssel mit dem in -k genannten Argument vorhanden ist, der die im selben Prozess zu startenden Dienste enthält.

Beispiel: `-k UnistackSvcGroup` startet: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Wenn das **Flag `-s`** zusammen mit einem Argument verwendet wird, wird svchost aufgefordert, nur den angegebenen Dienst in diesem Argument zu starten.

Es wird mehrere Prozesse von `svchost.exe` geben. Wenn einer von ihnen **das `-k`-Flag nicht verwendet**, ist das sehr verdächtig. Wenn Sie feststellen, dass **services.exe nicht der übergeordnete Prozess** ist, ist das ebenfalls sehr verdächtig.


## taskhost.exe

Dieser Prozess fungiert als Host für Prozesse, die aus DLLs ausgeführt werden. Er lädt auch die Dienste, die aus DLLs ausgeführt werden.

In W8 wird dies als taskhostex.exe und in W10 als taskhostw.exe bezeichnet.


## explorer.exe

Dies ist der Prozess, der für den **Desktop des Benutzers** und das Starten von Dateien über Dateierweiterungen verantwortlich ist.

Es sollte **nur 1** Prozess pro angemeldetem Benutzer erstellt werden.

Dies wird von **userinit.exe** ausgeführt, das beendet sein sollte, daher sollte für diesen Prozess kein übergeordneter Prozess angezeigt werden.


# Erfassen von bösartigen Prozessen

* Wird es aus dem erwarteten Pfad ausgeführt? (Keine Windows-Binärdateien werden aus dem temporären Speicherort ausgeführt)
* Kommuniziert es mit seltsamen IPs?
* Überprüfen Sie digitale Signaturen (Microsoft-Artefakte sollten signiert sein)
* Ist es korrekt geschrieben?
* Wird es unter der erwarteten SID ausgeführt?
* Ist der übergeordnete Prozess der erwartete (falls vorhanden)?
* Sind die Kindprozesse die erwarteten? (kein cmd.exe, wscript.exe, powershell.exe..?)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**
