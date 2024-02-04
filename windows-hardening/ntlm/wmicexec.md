# WmicExec

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में** देखना चाहते हैं या **HackTricks को PDF में डाउनलोड** करना चाहते हैं तो [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) और **मुझे** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)** का** **अनुसरण** करें।
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

## कैसे काम करता है विस्तार से समझा गया है

प्रक्रियाएँ उन होस्टों पर खोली जा सकती हैं जहां उपयोगकर्ता का नाम और या तो पासवर्ड या हैश ज्ञात है विमान उपयोग के माध्यम से। Wmiexec द्वारा WMI का उपयोग करके आदेशों को क्रियान्वित किया जाता है, एक अर्ध-संवादात्मक शैल अनुभव प्रदान करता है।

**dcomexec.py:** विभिन्न DCOM अंतास्त्रों का उपयोग करके, यह स्क्रिप्ट wmiexec.py के समान एक अर्ध-संवादात्मक शैल प्रदान करता है, विशेष रूप से ShellBrowserWindow DCOM ऑब्ज
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
एक नेमस्पेस के भीतर क्लासेस को निम्नलिखित तरीके से सूचीबद्ध किया जा सकता है:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **कक्षाएं**

एक WMI कक्षा का नाम जानना, जैसे win32\_process, और उसके नामस्थान को जानना किसी भी WMI ऑपरेशन के लिए महत्वपूर्ण है।
`win32` से शुरू होने वाली कक्षाओं की सूची बनाने के लिए आदेश:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
एक क्लास का आह्वान:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### विधियाँ

विधियाँ, जो WMI क्लास के एक या एक से अधिक कार्यात्मक कार्य होते हैं, को क्रियान्वित किया जा सकता है।
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
## WMI जाँच

### WMI सेवा की स्थिति

यदि WMI सेवा कार्यात्मक है या नहीं यह सत्यापित करने के लिए आदेश:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### सिस्टम और प्रक्रिया सूचना

WMI के माध्यम से सिस्टम और प्रक्रिया सूचना एकत्र करना:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
अटैकर्स के लिए, WMI एक प्रभावशाली उपकरण है जो सिस्टम या डोमेन के बारे में संवेदनशील डेटा की जांच करने के लिए।
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **मैन्युअल रिमोट WMI क्वेरी**

दूरस्थ WMI क्वेरी करके विशिष्ट जानकारी, जैसे स्थानीय एडमिन या लॉग-ऑन उपयोगकर्ता, प्राप्त करना सावधानीपूर्वक निर्मित कमांड के साथ संभव है। `wmic` एक पाठ फ़ाइल से पठन समर्थित करता है ताकि कई नोड पर कमांड को समय-समय पर क्रियान्वित किया जा सके।

WMI के माध्यम से दूरस्थ एक प्रक्रिया को क्रियान्वित करने के लिए, जैसे कि एक एम्पायर एजेंट डिप्लॉय करना, निम्नलिखित कमांड संरचना का उपयोग किया जाता है, सफल क्रियान्वयन को "0" की वापसी द्वारा सूचित किया जाता है:
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
यह प्रक्रिया WMI की दूरस्थ क्रियान्वयन और सिस्टम जांच की क्षमता को विवरणित करती है, जिससे इसका उपयोग सिस्टम प्रशासन और पेनेट्रेशन टेस्टिंग दोनों के लिए साहायक होता है।


# संदर्भ
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## स्वचालित उपकरण

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

दूसरे तरीके HackTricks का समर्थन करने के लिए:

* अगर आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) और **मुझे** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.** का **अनुसरण** करें
* **अपने हैकिंग ट्रिक्स साझा करें** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके।

</details>
