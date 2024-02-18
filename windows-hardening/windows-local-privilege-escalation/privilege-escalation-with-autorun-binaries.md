# ऑटोरन्स के साथ प्रिविलेज इस्केलेशन

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** द्वारा PRs सबमिट करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**बग बाउंटी टिप**: **Intigriti** के लिए **साइन अप करें**, एक प्रीमियम **हैकर्स द्वारा बनाई गई बग बाउंटी प्लेटफॉर्म**! आज ही हमारे साथ शामिल हों [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) और शुरू करें बाउंटी अप टू **$100,000** तक कमाना!

{% embed url="https://go.intigriti.com/hacktricks" %}

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

सभी बाइनरी जो **स्टार्टअप फोल्डर में स्थित हैं, स्टार्टअप पर निष्पादित किए जाएंगे**। सामान्य स्टार्टअप फोल्डर निम्नलिखित हैं, लेकिन स्टार्टअप फोल्डर रजिस्ट्री में दर्शाया गया है। [यहाँ क्लिक करें इसे जानने के लिए।](privilege-escalation-with-autorun-binaries.md#startup-path)
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
[यहाँ से नोट](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** रजिस्ट्री एंट्री दर्शाती है कि आप 64-बिट विंडोज संस्करण चला रहे हैं। ऑपरेटिंग सिस्टम इस कुंजी का उपयोग करता है HKEY\_LOCAL\_MACHINE\SOFTWARE का एक अलग दृश्य प्रदर्शित करने के लिए 64-बिट विंडोज संस्करण पर चलने वाले 32-बिट एप्लिकेशन्स के लिए।
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

**रन** और **रनवन्स** के रूप में जाने जाने वाले रजिस्ट्री कुंजी उपयुक्तता से प्रत्येक बार उपयोगकर्ता सिस्टम में लॉग इन करते समय कार्यक्रम स्वचालित रूप से क्रियान्वित करने के लिए डिज़ाइन किए गए हैं। कुंजी के डेटा मान के रूप में सौंपी गई कमांड लाइन 260 वर्णों या उससे कम की सीमा में होती है।

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

विंडोज विस्टा और बाद के संस्करणों पर, **रन** और **रनवन्स** रजिस्ट्री कुंजी स्वचालित रूप से उत्पन्न नहीं होती हैं। इन कुंजियों में एंट्री या तो सीधे कार्यक्रमों को प्रारंभ कर सकती हैं या उन्हें आवश्यकताओं के रूप में निर्दिष्ट कर सकती हैं। उदाहरण के लिए, लॉगऑन पर एक DLL फ़ाइल लोड करने के लिए, किसी भी व्यक्ति ने सिस्टम स्टार्ट-अप के दौरान "C:\temp\evil.dll" को क्रियान्वित करने के लिए **RunOnceEx** रजिस्ट्री कुंजी के साथ "Depend" कुंजी का उपयोग किया है।
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**शांति 1**: यदि आप **HKLM** के किसी भी उल्लिखित रजिस्ट्री में लिख सकते हैं तो आप विशेष उपयोगकर्ता लॉग इन करने पर वर्चस्व को उन्नत कर सकते हैं।
{% endhint %}

{% hint style="info" %}
**शांति 2**: यदि आप **HKLM** के किसी भी रजिस्ट्री में उल्लिखित बाइनरी में कोई भी ओवरराइट कर सकते हैं तो आप उस बाइनरी को एक बैकडोर के साथ संशोधित कर सकते हैं जब एक विभिन्न उपयोगकर्ता लॉग इन करता है और वर्चस्व को उन्नत कर सकते हैं।
{% endhint %}
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

**स्टार्टअप** फ़ोल्डर में रखे गए शॉर्टकट स्वचालित रूप से सेवाओं या एप्लिकेशन को लॉगऑन या सिस्टम रिबूट के दौरान लॉन्च करने के लिए ट्रिगर करेंगे। **स्टार्टअप** फ़ोल्डर का स्थान रजिस्ट्री में **लोकल मशीन** और **वर्तमान उपयोगकर्ता** के लिए परिभाषित है। इसका मतलब है कि इन निर्दिष्ट **स्टार्टअप** स्थानों में जोड़े गए किसी भी शॉर्टकट से संबंधित सेवा या कार्य लॉगऑन या रिबूट प्रक्रिया के बाद स्वचालित रूप से शुरू होगा, जिससे किसी प्रोग्राम को स्वचालित रूप से चलाने के लिए एक सीधा तरीका बन जाता है।

{% hint style="info" %}
यदि आप किसी भी **HKLM** के तहत किसी भी \[उपयोगकर्ता] शैल फोल्डर को ओवरराइट कर सकते हैं, तो आप उसे अपने द्वारा नियंत्रित एक फ़ोल्डर की ओर पहुँचाने और एक बैकडोर रख सकते हैं जो किसी भी उपयोगकर्ता ने सिस्टम में लॉगइन करने पर समय-समय पर निषेधों को बढ़ाने के लिए क्रियान्वित किया जाएगा।
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

सामान्यत: **Userinit** कुंजी को **userinit.exe** पर सेट किया जाता है। हालांकि, यदि यह कुंजी संशोधित की गई है, तो निर्दिष्ट एक्जीक्यूटेबल भी **Winlogon** द्वारा उपयोगकर्ता लॉगऑन पर लॉन्च किया जाएगा। उसी तरह, **Shell** कुंजी का उद्देश्य **explorer.exe** को इंडिकेट करना है, जो विंडोज के लिए डिफ़ॉल्ट शैल है।
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
यदि आप रजिस्ट्री मान्यता या बाइनरी को अधिक लिख सकते हैं तो आप विशेषाधिकारों को उन्नत कर सकते हैं।
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

Windows रजिस्ट्री के अंदर `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` के तहत, एक **`AlternateShell`** मान डिफ़ॉल्ट रूप से `cmd.exe` पर सेट किया गया है। इसका मतलब है कि जब आप स्टार्टअप के दौरान "सुरक्षित मोड के साथ कमांड प्रॉम्प्ट" चुनते हैं (F8 दबाकर), `cmd.exe` का उपयोग किया जाता है। लेकिन, यह संभव है कि आप अपने कंप्यूटर को इस मोड में स्वचालित रूप से शुरू करने के लिए F8 दबाने और मैन्युअल रूप से इसे चुनने की आवश्यकता न हो।

"सुरक्षित मोड के साथ कमांड प्रॉम्प्ट" में स्वचालित रूप से शुरू होने के लिए एक बूट विकल्प बनाने के लिए कदम:

1. `boot.ini` फ़ाइल के गुणों को हटाने के लिए: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` को संपादित करने के लिए खोलें।
3. एक पंक्ति डालें: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. परिवर्तनों को `boot.ini` में सहेजें।
5. मूल फ़ाइल गुणों को पुनः लागू करें: `attrib c:\boot.ini +r +s +h`

* **उत्पादन 1:** **AlternateShell** रजिस्ट्री कुंजी बदलने से कस्टम कमांड शैल सेटअप किया जा सकता है, जो अनधिकृत पहुंच के लिए संभावित है।
* **उत्पादन 2 (PATH लेखन अनुमतियाँ):** सिस्टम **PATH** चर के किसी भी हिस्से में लेखन अनुमति होना, विशेष रूप से `C:\Windows\system32` से पहले, आपको एक कस्टम `cmd.exe` को निष्पादित करने की अनुमति देता है, जो यदि सिस्टम सुरक्षित मोड में शुरू हो तो एक बैकडोर हो सकता है।
* **उत्पादन 3 (PATH और boot.ini लेखन अनुमतियाँ):** `boot.ini` में लेखन पहुंच स्वचालित सुरक्षित मोड स्टार्टअप को सुविधाजनक बनाती है, जो अगले बूट पर अनधिकृत पहुंच को सुविधाजनक बनाता है।

वर्तमान **AlternateShell** सेटिंग की जाँच करने के लिए, इन कमांडों का उपयोग करें:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### इंस्टॉल किया गया घटक

एक्टिव सेटअप एक विशेषता है जो विंडोज में **पूरी तरह से लोड होने से पहले प्रारंभ होती है**। यह कुछ निर्दिष्ट कमांडों को प्राथमिकता देती है, जो उपयोगकर्ता लॉगऑन आगे बढ़ने से पहले पूरा होना चाहिए। यह प्रक्रिया अन्य स्टार्टअप प्रविष्टियों से पहले होती है, जैसे कि रन या रनवन रजिस्ट्री खंडों में होने वाली प्रेरित क्रियाएं।

एक्टिव सेटअप निम्नलिखित रजिस्ट्री कुंजियों के माध्यम से प्रबंधित होती है:

* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

इन कुंजियों में, विभिन्न उप-कुंजियाँ मौजूद हैं, प्रत्येक एक विशिष्ट घटक को संदर्भित करती हैं। विशेष ध्यान देने योग्य कुंजी मान निम्नलिखित हैं:

* **IsInstalled:**
  * `0` इसका अर्थ है कि घटक का कमांड नहीं चलेगा।
  * `1` इसका अर्थ है कि कमांड प्रत्येक उपयोगकर्ता के लिए एक बार चलेगा, जो डिफ़ॉल्ट व्यवहार है अगर `IsInstalled` मान गायब है।
* **StubPath:** एक्टिव सेटअप द्वारा चलाने के लिए कमांड को परिभाषित करता है। यह किसी भी मान्य कमांड लाइन हो सकता है, जैसे कि `notepad` लॉन्च करना।

**सुरक्षा दृष्टिकोण:**

* **`IsInstalled`** को `"1"` पर सेट किया गया कुंजी में संशोधन या लेखन करना एक अनधिकृत कमांड निष्पादन की ओर ले जा सकता है, संभावित रूप से विशेषाधिकार उन्नति के लिए।
* किसी भी **`StubPath`** मान में संदर्भित बाइनरी फ़ाइल को बदलना भी यदि पर्याप्त अनुमतियाँ हैं तो विशेषाधिकार उन्नति हासिल की जा सकती है।

एक्टिव सेटअप के घटकों के **`StubPath`** विन्यास की जाँच करने के लिए, निम्नलिखित कमांड प्रयोग किए जा सकते हैं:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### ब्राउज़र हेल्पर ऑब्जेक्ट्स

### ब्राउज़र हेल्पर ऑब्जेक्ट्स (BHOs) का अवलोकन

ब्राउज़र हेल्पर ऑब्जेक्ट्स (BHOs) DLL मॉड्यूल हैं जो माइक्रोसॉफ्ट के इंटरनेट एक्सप्लोरर में अतिरिक्त सुविधाएँ जोड़ते हैं। वे प्रत्येक स्टार्ट पर इंटरनेट एक्सप्लोरर और विंडोज एक्सप्लोरर में लोड होते हैं। फिर भी, उनके निष्पादन को **NoExplorer** कुंजी को 1 पर सेट करके ब्लॉक किया जा सकता है, जिससे वे विंडोज एक्सप्लोरर उदाहरणों के साथ लोड होने से रोका जा सकता है।

BHOs Windows 10 के साथ इंटरनेट एक्सप्लोरर 11 के माध्यम से संगत हैं, लेकिन वे माइक्रोसॉफ्ट एज में समर्थित नहीं हैं, जो नए संस्करणों के विंडोज में डिफ़ॉल्ट ब्राउज़र है।

एक सिस्टम पर पंजीकृत BHOs की जांच करने के लिए, आप निम्नलिखित रजिस्ट्री कुंजीयों की जांच कर सकते हैं:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

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

ध्यान दें कि सभी साइट्स जहां आप ऑटोरन्स पा सकते हैं **पहले से ही खोजी गई हैं**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). हालांकि, एक **अधिक व्यापक सूची के लिए ऑटो-एक्जीक्यूट किए जाने वाले** फ़ाइल के लिए आप [सिसटरनल्स](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) का उपयोग कर सकते हैं:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## अधिक

**ऐसे और Autoruns खोजें जैसे registries में** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## संदर्भ

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**बग बाउंटी टिप**: **साइन अप करें** Intigriti के लिए, एक प्रीमियम **बग बाउंटी प्लेटफॉर्म जो हैकर्स द्वारा बनाया गया है**! हमारे साथ शामिल हों [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) आज ही, और शुरू करें बाउंटी कमाना तक **$100,000** तक!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* प्राप्त करें [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com)
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** पर फॉलो करें 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos को।

</details>
