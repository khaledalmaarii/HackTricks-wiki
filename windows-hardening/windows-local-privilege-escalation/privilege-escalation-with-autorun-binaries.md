# ऑटोरन्स के साथ प्रिविलेज एस्केलेशन

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ हैकट्रिक्स क्लाउड ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 ट्विटर 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ ट्विच 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 यूट्यूब 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **हैकट्रिक्स में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**द पीएस फैमिली**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**एनएफटी संग्रह**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक पीएस और हैकट्रिक्स स्वैग**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें द्वारा पीआर जमा करके** [**हैकट्रिक्स रेपो**](https://github.com/carlospolop/hacktricks) **और** [**हैकट्रिक्स-क्लाउड रेपो**](https://github.com/carlospolop/hacktricks-cloud)।

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

यदि आप **हैकिंग करियर** में रुचि रखते हैं और अहैकेबल को हैक करना चाहते हैं - हम नियुक्ति कर रहे हैं! (_अच्छी पोलिश लिखित और बोली जानी चाहिए_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** का उपयोग **स्टार्टअप** पर प्रोग्राम चलाने के लिए किया जा सकता है। देखें कि कौन से बाइनरीज़ स्टार्टअप में चलाने के लिए प्रोग्राम किए गए हैं:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## निर्धारित कार्य

**कार्य** निश्चित अंतराल के साथ चलाने के लिए निर्धारित किए जा सकते हैं। निम्नलिखित कमांड के साथ चलाने के लिए निर्धारित बाइनरी को देखें:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## फ़ोल्डर

सभी बाइनरी जो **स्टार्टअप फ़ोल्डर में स्थित होते हैं, स्टार्टअप पर निष्पादित होंगे**। सामान्य स्टार्टअप फ़ोल्डर नीचे सूचीबद्ध हैं, लेकिन स्टार्टअप फ़ोल्डर रजिस्ट्री में दिखाया जाता है। [यहां पढ़ें जानने के लिए।](privilege-escalation-with-autorun-binaries.md#startup-path)
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
नोट: **Wow6432Node** रजिस्ट्री प्रविष्टि इसका संकेत देती है कि आप 64-बिट विंडोज संस्करण चला रहे हैं। ऑपरेटिंग सिस्टम इस कुंजी का उपयोग करके 64-बिट विंडोज संस्करणों पर चलने वाले 32-बिट एप्लिकेशन्स के लिए HKEY\_LOCAL\_MACHINE\SOFTWARE का एक अलग दृश्य प्रदर्शित करता है।
{% endhint %}

### रन्स

**सामान्य रूप से ज्ञात** ऑटोरन रजिस्ट्री:

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

रन और रनवन रजिस्ट्री कुंजीयाँ प्रोग्राम को प्रत्येक बार चलाती हैं जब एक उपयोगकर्ता लॉग इन करता है। कुंजी के लिए डेटा मान 260 वर्णों से लंबा नहीं होता है।

**सेवा रन्स** (बूट के दौरान सेवाओं की स्वचालित स्टार्टअप को नियंत्रित कर सकते हैं):

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

यह विंडोजा विस्टा और नवीनतम पर डिफ़ॉल्ट रूप से नहीं बनाया जाता है। रजिस्ट्री रन कुंजी एंट्रीज़ सीधे प्रोग्राम को संदर्भित कर सकती हैं या उन्हें एक आधारभूतता के रूप में सूचीबद्ध कर सकती हैं। उदाहरण के लिए, एक "डिपेंड" कुंजी का उपयोग करके RunOnceEx का उपयोग करके लॉगऑन पर एक DLL लोड करना संभव है: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"`

{% hint style="info" %}
**अभिशाप 1**: यदि आप किसी भी उल्लिखित रजिस्ट्री में **HKLM** के अंदर लिख सकते हैं तो आप उच्चतम अवधि में अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्चतम अवधि में उच्च
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

किसी भी उपकंठ स्थान के लिए बनाया गया कोई शॉर्टकट लॉगऑन/रीबूट के दौरान सेवा को चालू करेगा। स्टार्टअप स्थान स्थानीय मशीन और वर्तमान उपयोगकर्ता दोनों पर निर्दिष्ट किया जाता है।

{% hint style="info" %}
यदि आप किसी भी \[उपयोगकर्ता] शैल फ़ोल्डर को **HKLM** के तहत अधिलेखित कर सकते हैं, तो आप इसे आपके द्वारा नियंत्रित एक फ़ोल्डर की ओर पहुंचित कर सकते हैं और एक बैकडोर रख सकते हैं जो किसी भी उपयोगकर्ता को प्रवेश करने पर नियमित रूप से चलाया जाएगा और विशेषाधिकार को बढ़ाएगा।
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
### Winlogon कुंजी

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

आमतौर पर, **Userinit** कुंजी userinit.exe को दर्शाती है लेकिन यदि इस कुंजी को संशोधित किया जा सकता है, तो वह exe Winlogon द्वारा भी चलाई जाएगी।\
**Shell** कुंजी explorer.exe को दर्शानी चाहिए।
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
यदि आप रजिस्ट्री मान्यता या बाइनरी को अधिकारों को बढ़ाने के लिए ओवरराइट कर सकते हैं।
{% endhint %}

### नीति सेटिंग्स

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**चलाएँ** कुंजी की जांच करें।
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

पथ: **`HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`**

रजिस्ट्री कुंजी `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot` के तहत मान **AlternateShell** है, जिसे डिफ़ॉल्ट रूप से `cmd.exe` (कमांड प्रॉम्प्ट) पर सेट किया जाता है। जब आप स्टार्टअप के दौरान F8 दबाते हैं और "Safe Mode with Command Prompt" का चयन करते हैं, तो सिस्टम इस वैकल्पिक शैल का उपयोग करता है।\
हालांकि, आप एक बूट विकल्प बना सकते हैं ताकि आपको F8 दबाने की आवश्यकता न हो, फिर "Safe Mode with Command Prompt" का चयन करें।

1. बूट.इनी (c:\boot.ini) फ़ाइल विशेषताएँ संशोधित करें ताकि फ़ाइल को गैरपठनीय, गैरसिस्टम और गैरछिपा हो बनाया जा सके (attrib c:\boot.ini -r -s -h)।
2. बूट.इनी खोलें।
3. निम्नलिखित के समान एक पंक्ति जोड़ें: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. फ़ाइल सहेजें।
5. सही अनुमतियाँ पुनः लागू करें (attrib c:\boot.ini +r +s +h)।

जानकारी [यहाँ](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell) से प्राप्त की गई है।

{% hint style="info" %}
**Exploit 1:** यदि आप इस रजिस्ट्री कुंजी को संशोधित कर सकते हैं, तो आप अपने बैकडोर को इसकी ओर पहुंचा सकते हैं
{% endhint %}

{% hint style="info" %}
**Exploit 2 (PATH लेखन अनुमतियाँ)**: यदि आपके पास सिस्टम **PATH** के _C:\Windows\system32_ से पहले किसी भी फ़ोल्डर पर लेखन अनुमति है (या यदि आप इसे बदल सकते हैं), तो आप एक cmd.exe फ़ाइल बना सकते हैं और यदि कोई व्यक्ति सुरक्षित मोड में मशीन को प्रारंभ करता है, तो आपका बैकडोर निष्पादित हो जाएगा।
{% endhint %}

{% hint style="info" %}
**Exploit 3 (PATH लेखन अनुमतियाँ और बूट.इनी लेखन अनुमतियाँ)**: यदि आप बूट.इनी लिख सकते हैं, तो आप अगले रीबूट के लिए सुरक्षित मोड में स्टार्टअप को स्वचालित कर सकते हैं।
{% endhint %}
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### स्थापित कंपोनेंट

* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Active Setup डेस्कटॉप प्रदर्शित होने से पहले चलता है। Active Setup द्वारा शुरू की गई कमांड समकालीन रूप से चलती हैं, जब तक वे कार्यान्वित हो रही होती हैं तब तक लॉगऑन को ब्लॉक करती हैं। Active Setup कोई भी Run या RunOnce रजिस्ट्री प्रविष्टियों की मूल्यांकन करने से पहले निष्पादित होता है।

इन कुंजियों के अंदर आपको और कुंजियाँ मिलेंगी और प्रत्येक कुंजी के लिए कुछ रोचक कुंजी-मान मिलेंगे। सबसे रोचक मान निम्नलिखित हैं:

* **IsInstalled:**
* 0: कंपोनेंट की कमांड नहीं चलेगी।
* 1: कंपोनेंट की कमांड प्रति उपयोगकर्ता एक बार चलेगी। यह डिफ़ॉल्ट है (यदि IsInstalled मान मौजूद नहीं होता है)।
* **StubPath**
* प्रारूप: कोई भी मान्य कमांड लाइन, जैसे "notepad"
* यह कमांड चलाई जाती है अगर Active Setup निर्धारित करता है कि इस कंपोनेंट को लॉगऑन के दौरान चलाने की आवश्यकता है।

{% hint style="info" %}
यदि आप _**IsInstalled == "1"**_ वाली किसी भी कुंजी पर लिख सकते हैं और कुंजी **StubPath** को निर्दिष्ट कर सकते हैं, तो आप इसे एक बैकडोर की ओर पहुंचा सकते हैं और विशेषाधिकारों को उन्नत कर सकते हैं। इसके अलावा, यदि आप किसी भी **StubPath** कुंजी द्वारा निर्दिष्ट किसी भी **बाइनरी** को अधिकृत कर सकते हैं, तो आप विशेषाधिकारों को उन्नत कर सकते हैं।
{% endhint %}
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### ब्राउज़र सहायक ऑब्जेक्ट्स

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

एक **ब्राउज़र सहायक ऑब्जेक्ट** (**BHO**) एक DLL मॉड्यूल होता है जो माइक्रोसॉफ्ट के इंटरनेट एक्सप्लोरर वेब ब्राउज़र के लिए एक प्लगइन के रूप में डिज़ाइन किया गया है जो अतिरिक्त कार्यक्षमता प्रदान करता है। ये मॉड्यूल हर नए इंटरनेट एक्सप्लोरर और हर नए विंडोज़ एक्सप्लोरर के लिए निष्पादित किए जाते हैं। हालांकि, एक BHO को निष्पादित किया जा सकता है ताकि प्रत्येक एक्सप्लोरर इंस्टेंस द्वारा निष्पादित न हो, जब कुंजी **NoExplorer** को 1 सेट किया जाता है।

BHOs अभी भी Windows 10 के साथ, इंटरनेट एक्सप्लोरर 11 के माध्यम से समर्थित हैं, जबकि BHOs को मूल वेब ब्राउज़र माइक्रोसॉफ्ट एज में समर्थित नहीं हैं।
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
नोट करें कि रजिस्ट्री में प्रति DLL के लिए 1 नया रजिस्ट्री होगा और इसे **CLSID** द्वारा प्रतिष्ठित किया जाएगा। आप `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` में CLSID जानकारी ढूंढ सकते हैं।

### इंटरनेट एक्सप्लोरर एक्सटेंशन्स

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

नोट करें कि रजिस्ट्री में प्रति DLL के लिए 1 नया रजिस्ट्री होगा और इसे **CLSID** द्वारा प्रतिष्ठित किया जाएगा। आप `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` में CLSID जानकारी ढूंढ सकते हैं।

### फ़ॉन्ट ड्राइवर्स

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

छवि फ़ाइल क्रियान्वयन विकल्प (Image File Execution Options) एक विंडोज रजिस्ट्री कुंजी है जो एक प्रक्रिया को चालू करने से पहले एक बाइनरी फ़ाइल को स्वचालित रूप से चलाने की अनुमति देती है। यह विशेषता विंडोज विकसितकर्ताओं द्वारा विकसित और टेस्ट किए जाने वाले ऐप्लिकेशन्स के लिए उपयोगी होती है, जहां वे ऐप्लिकेशन के विकास के दौरान बाइनरी को स्वचालित रूप से चलाने के लिए इस्तेमाल की जाती है।

एक हैकर के लिए, छवि फ़ाइल क्रियान्वयन विकल्प एक उपयोगी टूल हो सकती है जो लोकल प्रिविलेज उन्नयन के लिए उपयोग किया जा सकता है। हैकर इस विशेषता का उपयोग करके एक बाइनरी फ़ाइल को चलाने के लिए एक अनुप्रयोग को चुन सकता है, जिससे उन्हें उस अनुप्रयोग के संदर्भ में उच्चतम स्तर के अनुमतियाँ प्राप्त हो सकती हैं। इसके लिए, हैकर को रजिस्ट्री में छवि फ़ाइल क्रियान्वयन विकल्प को संशोधित करने की आवश्यकता होती है और उच्चतम स्तर की अनुमतियों को सेट करने के लिए एक बाइनरी फ़ाइल का चयन करना होता है। इस तरह, हैकर लोकल प्रिविलेज उन्नयन प्राप्त कर सकता है और सिस्टम में अधिकतम नियंत्रण प्राप्त कर सकता है।
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

ध्यान दें कि वह सभी साइट जहां आप autoruns पा सकते हैं, **पहले से ही खोजी जा चुकी हैं**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). हालांकि, एक **और व्यापक सूची के लिए** ऑटो-चलाया जाने वाला फ़ाइल, आप सिस्टर्नल्स का उपयोग कर सकते हैं: [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## अधिक

[https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2) में रजिस्ट्री की तरह और अधिक Autoruns ढूंढें।

## संदर्भ

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

यदि आप **हैकिंग करियर** में रुचि रखते हैं और अहैकेबल को हैक करना चाहते हैं - **हम भर्ती कर रहे हैं!** (_अच्छी पोलिश लिखने और बोलने की जानकारी चाहिए_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहेंगे? या क्या आप **PEASS के नवीनतम संस्करण का उपयोग करना चाहेंगे या HackTricks को PDF में डाउनलोड करना चाहेंगे**? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFT संग्रह**](https://opensea.io/collection/the-peass-family)
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का पालन करें**.
* **अपने हैकिंग ट्रिक्स को हमें PR के माध्यम से सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को साझा करें**।

</details>
