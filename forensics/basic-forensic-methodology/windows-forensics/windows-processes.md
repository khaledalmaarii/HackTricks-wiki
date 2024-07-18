{% hint style="success" %}
Lernen & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}


## smss.exe

**Sitzungsmanager**.\
Sitzung 0 startet **csrss.exe** und **wininit.exe** (**Betriebssystemdienste**), während Sitzung 1 **csrss.exe** und **winlogon.exe** (**Benutzersitzung**) startet. Es sollte jedoch **nur ein Prozess** dieses **Binärdateis** ohne Kinder im Prozessbaum geben.

Außerdem können Sitzungen außerhalb von 0 und 1 darauf hinweisen, dass RDP-Sitzungen stattfinden.


## csrss.exe

**Client/Server-Laufzeit-Subsystemprozess**.\
Es verwaltet **Prozesse** und **Threads**, stellt die **Windows-API** für andere Prozesse zur Verfügung und **weist Laufwerksbuchstaben zu**, erstellt **Temporärdateien** und behandelt den **Herunterfahrprozess**.

Es gibt einen, der in Sitzung 0 läuft und einen weiteren in Sitzung 1 (also **2 Prozesse** im Prozessbaum). Ein weiterer wird **pro neuer Sitzung erstellt**.


## winlogon.exe

**Windows-Anmeldeprozess**.\
Er ist verantwortlich für Benutzer **An-**/**Abmeldungen**. Er startet **logonui.exe**, um nach Benutzername und Passwort zu fragen, und ruft dann **lsass.exe** auf, um sie zu überprüfen.

Dann startet er **userinit.exe**, die in **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** mit dem Schlüssel **Userinit** angegeben ist.

Darüber hinaus sollte der vorherige Registrierungseintrag **explorer.exe** im **Shell-Schlüssel** haben, da er sonst als **Malware-Persistenzmethode** missbraucht werden könnte.


## wininit.exe

**Windows-Initialisierungsprozess**. \
Er startet **services.exe**, **lsass.exe** und **lsm.exe** in Sitzung 0. Es sollte nur 1 Prozess geben.


## userinit.exe

**Benutzerinit-Anwendungsanmeldung**.\
Lädt die **ntduser.dat in HKCU** und initialisiert die **Benutzerumgebung** und führt **Anmelde**-**Skripte** und **GPO** aus.

Es startet **explorer.exe**.


## lsm.exe

**Lokaler Sitzungsmanager**.\
Er arbeitet mit smss.exe zusammen, um Benutzersitzungen zu manipulieren: Anmeldung/Abmeldung, Starten der Shell, Desktop sperren/entsperren usw.

Nach W7 wurde lsm.exe in einen Dienst (lsm.dll) umgewandelt.

Es sollte nur 1 Prozess in W7 geben und davon ein Dienst, der die DLL ausführt.


## services.exe

**Dienststeuerungs-Manager**.\
Er **lädt** **Dienste**, die als **automatisch gestartet** und **Treiber** konfiguriert sind.

Er ist der übergeordnete Prozess von **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** und vielen anderen.

Dienste sind in `HKLM\SYSTEM\CurrentControlSet\Services` definiert, und dieser Prozess verwaltet eine DB im Speicher mit Dienstinformationen, die von sc.exe abgefragt werden können.

Beachten Sie, wie **einige** **Dienste** in einem **eigenen Prozess** ausgeführt werden und andere in einem **svchost.exe-Prozess gemeinsam ausgeführt werden**.

Es sollte nur 1 Prozess geben.


## lsass.exe

**Lokaler Sicherheitsdienst-Subsystem**.\
Er ist verantwortlich für die Benutzer **Authentifizierung** und erstellt die **Sicherheits**-**Token**. Er verwendet in `HKLM\System\CurrentControlSet\Control\Lsa` befindliche Authentifizierungspakete.

Er schreibt in das **Sicherheits**-**Ereignisprotokoll**, und es sollte nur 1 Prozess geben.

Beachten Sie, dass dieser Prozess stark angegriffen wird, um Passwörter auszulesen.


## svchost.exe

**Generischer Diensthostprozess**.\
Er hostet mehrere DLL-Dienste in einem gemeinsamen Prozess.

Normalerweise wird **svchost.exe** mit dem Flag `-k` gestartet. Dies führt eine Abfrage des Registrierungsschlüssels **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** durch, in dem ein Schlüssel mit dem im -k genannten Argument enthalten ist, der die Dienste enthält, die im selben Prozess gestartet werden sollen.

Zum Beispiel: `-k UnistackSvcGroup` wird starten: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Wenn das **Flag `-s`** auch mit einem Argument verwendet wird, wird svchost aufgefordert, **nur den angegebenen Dienst** in diesem Argument zu starten.

Es wird mehrere Prozesse von `svchost.exe` geben. Wenn einer von ihnen **nicht das `-k`-Flag verwendet**, ist das sehr verdächtig. Wenn Sie feststellen, dass **services.exe nicht der übergeordnete Prozess** ist, ist das ebenfalls sehr verdächtig.


## taskhost.exe

Dieser Prozess fungiert als Host für Prozesse, die aus DLLs ausgeführt werden. Er lädt auch die Dienste, die aus DLLs ausgeführt werden.

In W8 wird dies taskhostex.exe genannt und in W10 taskhostw.exe.


## explorer.exe

Dies ist der Prozess, der für den **Desktop des Benutzers** und das Starten von Dateien über Dateierweiterungen verantwortlich ist.

Es sollte **nur 1** Prozess pro angemeldetem Benutzer gestartet werden.

Dies wird von **userinit.exe** ausgeführt, das beendet werden sollte, sodass für diesen Prozess **kein übergeordneter Prozess** erscheinen sollte.


# Erfassen von bösartigen Prozessen

* Wird es aus dem erwarteten Pfad ausgeführt? (Keine Windows-Binärdateien werden aus dem temporären Speicherort ausgeführt)
* Kommuniziert es mit seltsamen IPs?
* Überprüfen Sie digitale Signaturen (Microsoft-Artefakte sollten signiert sein)
* Ist es korrekt geschrieben?
* Wird es unter der erwarteten SID ausgeführt?
* Ist der übergeordnete Prozess der erwartete (falls vorhanden)?
* Sind die untergeordneten Prozesse die erwarteten? (kein cmd.exe, wscript.exe, powershell.exe..?)


{% hint style="success" %}
Lernen & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}
