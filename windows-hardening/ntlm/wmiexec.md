# WmiExec

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

## How It Works Explained

प्रक्रियाएँ उन होस्ट पर खोली जा सकती हैं जहाँ उपयोगकर्ता नाम और या तो पासवर्ड या हैश ज्ञात हैं WMI के उपयोग के माध्यम से। Wmiexec द्वारा WMI का उपयोग करके आदेश निष्पादित किए जाते हैं, जो एक अर्ध-इंटरएक्टिव शेल अनुभव प्रदान करता है।

**dcomexec.py:** विभिन्न DCOM एंडपॉइंट्स का उपयोग करते हुए, यह स्क्रिप्ट wmiexec.py के समान एक अर्ध-इंटरएक्टिव शेल प्रदान करती है, विशेष रूप से ShellBrowserWindow DCOM ऑब्जेक्ट का लाभ उठाते हुए। यह वर्तमान में MMC20 का समर्थन करता है। एप्लिकेशन, शेल विंडोज़, और शेल ब्राउज़र विंडो ऑब्जेक्ट। (source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Fundamentals

### Namespace

डायरेक्टरी-शैली की पदानुक्रम में संरचित, WMI का शीर्ष-स्तरीय कंटेनर \root है, जिसके अंतर्गत अतिरिक्त निर्देशिकाएँ, जिन्हें नामस्थान कहा जाता है, व्यवस्थित की जाती हैं।  
नामस्थान सूचीबद्ध करने के लिए आदेश:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Namespaces के भीतर कक्षाओं को सूचीबद्ध करने के लिए:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **क्लासेस**

WMI क्लास नाम, जैसे win32\_process, और जिस नामस्थान में यह स्थित है, जानना किसी भी WMI ऑपरेशन के लिए महत्वपूर्ण है।  
`win32` से शुरू होने वाले क्लासेस की सूची बनाने के लिए कमांड:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
क्लास का आह्वान:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Methods

विधियाँ, जो WMI कक्षाओं के एक या अधिक निष्पादन योग्य कार्य हैं, को निष्पादित किया जा सकता है।
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI Enumeration

### WMI सेवा स्थिति

WMI सेवा के कार्यशील होने की पुष्टि करने के लिए कमांड:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### सिस्टम और प्रक्रिया की जानकारी

WMI के माध्यम से सिस्टम और प्रक्रिया की जानकारी इकट्ठा करना:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
हमलावरों के लिए, WMI सिस्टम या डोमेन के बारे में संवेदनशील डेटा की गणना करने के लिए एक शक्तिशाली उपकरण है।
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Remote querying of WMI for specific information, such as local admins or logged-on users, is feasible with careful command construction.

### **Manual Remote WMI Querying**

Stealthy identification of local admins on a remote machine and logged-on users can be achieved through specific WMI queries. `wmic` भी एक टेक्स्ट फ़ाइल से पढ़ने का समर्थन करता है ताकि एक साथ कई नोड्स पर कमांड निष्पादित किए जा सकें।

To remotely execute a process over WMI, such as deploying an Empire agent, the following command structure is employed, with successful execution indicated by a return value of "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
यह प्रक्रिया WMI की दूरस्थ निष्पादन और प्रणाली गणना की क्षमता को दर्शाती है, जो प्रणाली प्रशासन और पेंटेस्टिंग दोनों के लिए इसकी उपयोगिता को उजागर करती है।

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Automatic Tools

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

{% hint style="success" %}
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PRs सबमिट करें।

</details>
{% endhint %}
