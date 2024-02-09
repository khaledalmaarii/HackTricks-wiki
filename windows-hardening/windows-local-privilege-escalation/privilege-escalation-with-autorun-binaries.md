# ऑटोरन्स के साथ विशेषाधिकार उन्नति

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> के साथ जीरो से हीरो तक AWS हैकिंग सीखें</summary>

हैकट्रिक्स का समर्थन करने के अन्य तरीके:

* यदि आप अपनी कंपनी का विज्ञापन हैकट्रिक्स में देखना चाहते हैं या हैकट्रिक्स को पीडीएफ में डाउनलोड करना चाहते हैं तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**द पीएस फैमिली**](https://opensea.io/collection/the-peass-family) खोजें
* **जुड़ें** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) पर **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में पीआर जमा करके।

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

यदि आप **हैकिंग करियर** में रुचि रखते हैं और अहैकेबल को हैक करना चाहते हैं - **हम भर्ती कर रहे हैं!** (_फ्लूएंट पोलिश लिखित और बोली जानी चाहिए_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** का उपयोग **स्टार्टअप** पर प्रोग्राम चलाने के लिए किया जा सकता है। देखें कि कौन से बाइनरी स्टार्टअप में चलाने के लिए प्रोग्राम किए गए हैं:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## निर्धारित कार्य

**कार्य** को **निश्चित अंतराल** के साथ चलाने के लिए निर्धारित किया जा सकता है। देखें कि कौन से बाइनरी निर्धारित किए गए हैं:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## फोल्डर

**स्टार्टअप फोल्डर में स्थित सभी बाइनरी शुरू होने पर चलाए जाएंगे**। सामान्य स्टार्टअप फोल्डर निम्नलिखित हैं, लेकिन रजिस्ट्री में स्टार्टअप फोल्डर दिखाया गया है। [यहाँ क्लिक करें इसे जानने के लिए।](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## रजिस्ट्री

{% hint style="info" %}
[यहाँ से नोट](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** रजिस्ट्री एंट्री दर्शाती है कि आप 64-बिट विंडोज संस्करण चला रहे हैं। ऑपरेटिंग सिस्टम इस कुंजी का उपयोग करता है HKEY\_LOCAL\_MACHINE\SOFTWARE के लिए एक अलग दृश्य प्रदर्शित करने के लिए 64-बिट विंडोज संस्करण पर चलने वाले 32-बिट एप्लिकेशन्स के लिए।
{% endhint %}

### रन्स

**सामान्य रूप से जानी जाने वाली** ऑटोरन रजिस्ट्री:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

**रजिस्ट्री कुंजी** जिन्हें **रन** और **रनवन्स** के रूप में जाना जाता है, प्रत्येक बार जब एक उपयोगकर्ता सिस्टम में लॉग इन करता है, वे स्वचालित रूप से कार्यक्रमों को क्रियान्वित करने के लिए डिज़ाइन किए गए हैं। कुंजी के डेटा मान के रूप में सौ 260 वर्णों या उससे कम होता है।

**सेवा रन्स** (बूट के दौरान सेवाओं की स्वचालित प्रारंभ को नियंत्रित कर सकते हैं):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

विंडोज विस्टा और उसके बाद के संस्करणों पर, **रन** और **रनवन्स** रजिस्ट्री कुंजी स्वचालित रूप से उत्पन्न नहीं होती हैं। इन कुंजियों में एंट्री या तो सीधे कार्यक्रमों को प्रारंभ कर सकती हैं या उन्हें विभिन्नताओं के रूप में निर्दिष्ट कर सकती हैं। उदाहरण के लिए, लॉगऑन पर एक DLL फ़ाइल लोड करने के लिए, कोई भी "Depend" कुंजी के साथ **RunOnceEx** रजिस्ट्री कुंजी का उपयोग कर सकता है। इसे सिस्टम स्टार्ट-अप के दौरान "C:\\temp\\evil.dll" को क्रियान्वित करने के लिए एक रजिस्ट्री एंट्री जोड़ने के द्वारा प्रदर्शित किया गया है:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**शातिरजीवन 1**: यदि आप **HKLM** के किसी भी उल्लिखित रजिस्ट्री में लिख सकते हैं तो आप उन्नति को बढ़ा सकते हैं जब एक विभिन्न उपयोगकर्ता लॉग इन करता है।
{% endhint %}

{% hint style="info" %}
**शातिरजीवन 2**: यदि आप **HKLM** के क
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### स्टार्टअप पथ

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**स्टार्टअप** फ़ोल्डर में रखे गए शॉर्टकट स्वचालित रूप से सेवाओं या एप्लिकेशन को चालू करेंगे जब उपयोगकर्ता लॉगऑन करता है या सिस्टम पुनरारंभ होता है। **स्टार्टअप** फ़ोल्डर का स्थान रजिस्ट्री में **स्थानीय मशीन** और **वर्तमान उपयोगकर्ता** के लिए परिभाषित है। इसका मतलब है कि इन निर्दिष्ट **स्टार्टअप** स्थानों में जोड़े गए किसी भी शॉर्टकट से जुड़ी सेवा या कार्यक्रम लॉगऑन या पुनरारंभ प्रक्रिया के बाद स्वचालित रूप से शुरू होगा, जिससे किसी कार्यक्रम को स्वचालित रूप से चलाने के लिए एक सीधा तरीका बन जाता है।

{% hint style="info" %}
यदि आप **HKLM** के किसी भी \[उपयोगकर्ता] शैल फोल्डर को अधिलेखित कर सकते हैं, तो आप इसे आपके द्वारा नियंत्रित एक फोल्डर की ओर पहुँचाने और एक बैकडोर रख सकते हैं जो किसी भी उपयोगकर्ता ने सिस्टम में लॉगइन करते समय निष्क्रिय किया जाएगा और विशेषाधिकारों को उन्नत करेगा।
{% endhint %}
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### विनलोगन कुंजी

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

सामान्यत: **Userinit** कुंजी को **userinit.exe** पर सेट किया जाता है। हालांकि, यदि यह कुंजी संशोधित की गई है, तो उपयुक्त कार्यक्रम भी **Winlogon** द्वारा उपयोगकर्ता लॉगऑन पर लॉन्च किया जाएगा। उसी तरह, **Shell** कुंजी का उद्देश्य **explorer.exe** को इंडिकेट करना है, जो विंडोज के लिए डिफ़ॉल्ट शैल है।
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
यदि आप रजिस्ट्री मान्यता या बाइनरी को अधिकलिखित कर सकते हैं तो आपको विशेषाधिकारों को उन्नत करने की क्षमता होगी।
{% endhint %}

### नीति सेटिंग्स

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** कुंजी की जांच करें।
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### सुरक्षित मोड कमांड प्रॉम्प्ट बदलना

Windows रजिस्ट्री के तहत `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` में, डिफ़ॉल्ट रूप से `cmd.exe` के लिए **`AlternateShell`** मान सेट है। इसका मतलब है कि जब आप स्टार्टअप के दौरान "सुरक्षित मोड विथ कमांड प्रॉम्प्ट" चुनते हैं (F8 दबाकर), `cmd.exe` का उपयोग होता है। लेकिन, यह संभव है कि आप अपने कंप्यूटर को इस मोड में स्वचालित रूप से शुरू करने के लिए F8 दबाने और मैन्युअल रूप से चुनने की आवश्यकता न हो।

"सुरक्षित मोड विथ कमांड प्रॉम्प्ट" में स्वचालित रूप से शुरू होने के लिए एक बूट विकल्प बनाने के लिए चरण:

1. `boot.ini` फ़ाइल के गुणों को हटाने के लिए: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` को संपादित करने के लिए खोलें।
3. एक पंक्ति डालें: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. परिवर्तनों को `boot.ini` में सहेजें।
5. मूल फ़ाइल गुणों को पुनः लागू करें: `attrib c:\boot.ini +r +s +h`

- **उत्पादन 1:** **AlternateShell** रजिस्ट्री कुंजी बदलने से अनधिकृत पहुंच के लिए कस्टम कमांड शैल सेटअप किया जा सकता है।
- **उत्पादन 2 (PATH लेखन अनुमतियाँ):** सिस्टम **PATH** चरण के किसी भी हिस्से में लेखन अनुमति होना, विशेष रूप से `C:\Windows\system32` से पहले, आपको एक कस्टम `cmd.exe` को निष्पादित करने की अनुमति देता है, जो यदि सिस्टम सुरक्षित मोड में शुरू हो तो एक बैकडोर हो सकता है।
- **उत्पादन 3 (PATH और boot.ini लेखन अनुमतियाँ):** `boot.ini` में लेखन पहुंच, अगले बूट पर अनधिकृत पहुंच को सुविधाजनक बनाता है।

वर्तमान **AlternateShell** सेटिंग की जाँच करने के लिए इन कमांडों का उपयोग करें:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### इंस्टॉल किया गया घटक

एक्टिव सेटअप एक विशेषता है जो विंडोज में है जो **डेस्कटॉप पर्यावरण पूरी तरह से लोड होने से पहले प्रारंभ होता है**। यह कुछ निर्दिष्ट कमांडों को प्राथमिकता देता है, जो उपयोगकर्ता लॉगऑन आगे बढ़ने से पहले पूरा होना चाहिए। यह प्रक्रिया अन्य स्टार्टअप प्रविष्टियों से भी पहले होती है, जैसे कि रन या रनवन रजिस्ट्री खंडों में वे।

एक्टिव सेटअप निम्नलिखित रजिस्ट्री कुंजियों के माध्यम से प्रबंधित होता है:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

इन कुंजियों में, विभिन्न सबकुंजियाँ मौजूद हैं, प्रत्येक एक विशिष्ट कॉम्पोनेंट को संदर्भित करती है। विशेष ध्यान देने योग्य कुंजी मान शामिल हैं:

- **IsInstalled:**
  - `0` इसका अर्थ है कि कॉम्पोनेंट का कमांड नहीं चलेगा।
  - `1` यह अर्थ है कि कमांड प्रत्येक उपयोगकर्ता के लिए एक बार चलेगा, जो डिफ़ॉल्ट व्यवहार है अगर `IsInstalled` मान गायब है।
- **StubPath:** एक्टिव सेटअप द्वारा चलाने के लिए कमांड को परिभाषित करता है। यह किसी भी मान्य कमांड लाइन हो सकता है, जैसे `notepad` लॉन्च करना।

**सुरक्षा इंगित:**

- **`IsInstalled`** को `"1"` पर सेट करने वाली कुंजी में संदर्भित किसी विशेष **`StubPath`** के साथ संशोधन या लेखन अनधिकृत कमांड निष्पादन की ओर ले जा सकता है, संभावित रूप से विशेषाधिकार उन्नति के लिए।
- किसी भी **`StubPath`** मान में संदर्भित बाइनरी फ़ाइल को संशोधित करना भी विशेषाधिकार उन्नति प्राप्त कर सकता है, पर्याप्त अनुमतियाँ होने पर।

एक्टिव सेटअप कॉम्पोनेंट्स के अंदर **`StubPath`** विन्यासों की जांच करने के लिए, निम्नलिखित कमांड प्रयोग किए जा सकते हैं:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### ब्राउज़र हेल्पर ऑब्जेक्ट्स

### ब्राउज़र हेल्पर ऑब्जेक्ट्स (BHOs) का अवलोकन

ब्राउज़र हेल्पर ऑब्जेक्ट्स (BHOs) DLL मॉड्यूल हैं जो माइक्रोसॉफ्ट के इंटरनेट एक्सप्लोरर में अतिरिक्त सुविधाएँ जोड़ते हैं। वे प्रत्येक स्टार्ट पर इंटरनेट एक्सप्लोरर और विंडोज एक्सप्लोरर में लोड होते हैं। फिर भी, उनके निष्पादन को **NoExplorer** कुंजी को 1 पर सेट करके ब्लॉक किया जा सकता है, जिससे वे विंडोज एक्सप्लोरर उदाहरणों के साथ लोड होने से रोका जा सकता है।

BHOs Windows 10 के साथ इंटरनेट एक्सप्लोरर 11 के माध्यम से संगत हैं, लेकिन वे माइक्रोसॉफ्ट एज में समर्थित नहीं हैं, जो नए संस्करणों के विंडोज का डिफ़ॉल्ट ब्राउज़र है।

एक सिस्टम पर पंजीकृत BHOs की जांच करने के लिए, आप निम्नलिखित रजिस्ट्री कुंजियों की जांच कर सकते हैं:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

प्रत्येक BHO को रजिस्ट्री में उसके **CLSID** द्वारा प्रतिनिधित किया जाता है, जो एक अद्वितीय पहचानकर्ता के रूप में कार्य करता है। प्रत्येक CLSID के बारे में विस्तृत जानकारी `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` के तहत पाई जा सकती है।

रजिस्ट्री में BHOs की क्वेरी के लिए, इन कमांडों का उपयोग किया जा सकता है:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### इंटरनेट एक्सप्लोरर एक्सटेंशन्स

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

नोट करें कि रजिस्ट्री में प्रत्येक dll के लिए 1 नई रजिस्ट्री होगी और यह **CLSID** द्वारा प्रतिनिधित की जाएगी। आप `{<CLSID>}` में CLSID जानकारी `HKLM\SOFTWARE\Classes\CLSID\` में पा सकते हैं।

### फॉन्ट ड्राइवर्स

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### ओपन कमांड

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### छवि फ़ाइल क्रियान्वयन विकल्प
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## सिसइंटरनल्स

ध्यान दें कि ऑटोरन्स को पा सकने वाली सभी साइटें **पहले से ही खोजी गई हैं** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)। हालांकि, एक **अधिक व्यापक सूची के लिए ऑटो-एक्जीक्यूट किए गए** फ़ाइल के लिए आप [सिस्टरनल्स](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) का उपयोग कर सकते हैं:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## अधिक

**[https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)** में रजिस्ट्री की तरह औटोरन्स जैसे और भी ढूंढें।

## संदर्भ

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

यदि आप **हैकिंग करियर** में रुचि रखते हैं और अनहैकेबल को हैक करना चाहते हैं - **हम भर्ती कर रहे हैं!** (_फ्लूएंट पोलिश लिखित और बोली जरुरी है_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी कंपनी का विज्ञापन HackTricks में देखना चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **जुड़ें** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) पर **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके।

</details>
