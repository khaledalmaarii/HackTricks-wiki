# Volatility - CheatSheet

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) **स्पेन** में सबसे प्रासंगिक साइबरसुरक्षा कार्यक्रम है और **यूरोप** में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस हर अनुशासन में प्रौद्योगिकी और साइबरसुरक्षा पेशेवरों के लिए एक उबालता हुआ बैठक बिंदु है।

{% embed url="https://www.rootedcon.com/" %}

यदि आप कुछ **तेज और पागल** चाहते हैं जो कई Volatility प्लगइन्स को समानांतर में लॉन्च करेगा, तो आप उपयोग कर सकते हैं: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## स्थापना

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{% tabs %}
{% tab title="Method1" %} मेथड 1
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="विधि 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Volatility Commands

Access the official doc in [Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### A note on “list” vs. “scan” plugins

Volatility के पास प्लगइन्स के लिए दो मुख्य दृष्टिकोण हैं, जो कभी-कभी उनके नामों में परिलक्षित होते हैं। “list” प्लगइन्स Windows Kernel संरचनाओं के माध्यम से नेविगेट करने की कोशिश करेंगे ताकि प्रक्रियाओं जैसी जानकारी प्राप्त की जा सके (मेमोरी में `_EPROCESS` संरचनाओं की लिंक की गई सूची को खोजें और चलाएं), OS हैंडल (हैंडल तालिका को खोजें और सूचीबद्ध करें, पाए गए किसी भी पॉइंटर को डेरिफरेंस करें, आदि)। वे अधिक या कम Windows API की तरह व्यवहार करते हैं यदि अनुरोध किया जाए, उदाहरण के लिए, प्रक्रियाओं की सूची बनाने के लिए।

इससे “list” प्लगइन्स काफी तेज़ हो जाते हैं, लेकिन मैलवेयर द्वारा हेरफेर के लिए Windows API के समान ही संवेदनशील होते हैं। उदाहरण के लिए, यदि मैलवेयर DKOM का उपयोग करके `_EPROCESS` लिंक की गई सूची से एक प्रक्रिया को अनलिंक करता है, तो यह टास्क मैनेजर में नहीं दिखेगी और न ही pslist में।

दूसरी ओर, “scan” प्लगइन्स एक दृष्टिकोण अपनाएंगे जो मेमोरी को उन चीजों के लिए काटने के समान होगा जो विशेष संरचनाओं के रूप में डेरिफरेंस किए जाने पर समझ में आ सकती हैं। उदाहरण के लिए, `psscan` मेमोरी को पढ़ेगा और इससे `_EPROCESS` ऑब्जेक्ट बनाने की कोशिश करेगा (यह पूल-टैग स्कैनिंग का उपयोग करता है, जो 4-बाइट स्ट्रिंग्स की खोज कर रहा है जो किसी रुचि की संरचना की उपस्थिति को इंगित करती हैं)। इसका लाभ यह है कि यह उन प्रक्रियाओं को खोज सकता है जो समाप्त हो गई हैं, और यहां तक कि यदि मैलवेयर `_EPROCESS` लिंक की गई सूची के साथ छेड़छाड़ करता है, तो प्लगइन अभी भी मेमोरी में संरचना को खोज लेगा (क्योंकि इसके लिए प्रक्रिया को चलाने के लिए अभी भी मौजूद होना आवश्यक है)। नुकसान यह है कि “scan” प्लगइन्स “list” प्लगइन्स की तुलना में थोड़े धीमे होते हैं, और कभी-कभी गलत सकारात्मक परिणाम दे सकते हैं (एक प्रक्रिया जो बहुत पहले समाप्त हो गई और जिसकी संरचना के कुछ हिस्से अन्य संचालन द्वारा ओवरराइट हो गए)।

From: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## OS Profiles

### Volatility3

जैसा कि README के अंदर समझाया गया है, आपको उस OS का **सिंबॉल टेबल** _volatility3/volatility/symbols_ के अंदर रखना होगा जिसे आप समर्थन देना चाहते हैं।\
विभिन्न ऑपरेटिंग सिस्टम के लिए सिंबॉल टेबल पैक्स **डाउनलोड** के लिए उपलब्ध हैं:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### External Profile

आप समर्थित प्रोफाइल की सूची प्राप्त कर सकते हैं:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
यदि आप एक **नया प्रोफ़ाइल जिसका आपने डाउनलोड किया है** (उदाहरण के लिए एक लिनक्स वाला) का उपयोग करना चाहते हैं, तो आपको कहीं निम्नलिखित फ़ोल्डर संरचना बनानी होगी: _plugins/overlays/linux_ और इस फ़ोल्डर के अंदर प्रोफ़ाइल वाला ज़िप फ़ाइल डालनी होगी। फिर, प्रोफ़ाइलों की संख्या प्राप्त करने के लिए:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
आप **Linux और Mac प्रोफाइल डाउनलोड कर सकते हैं** [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

पिछले भाग में आप देख सकते हैं कि प्रोफाइल का नाम `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64` है, और आप इसका उपयोग कुछ इस तरह करने के लिए कर सकते हैं:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### प्रोफ़ाइल खोजें
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo और kdbgscan के बीच के अंतर**

[**यहां से**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): जहाँ imageinfo केवल प्रोफ़ाइल सुझाव प्रदान करता है, **kdbgscan** सही प्रोफ़ाइल और सही KDBG पते की सकारात्मक पहचान के लिए डिज़ाइन किया गया है (यदि कई हों)। यह प्लगइन Volatility प्रोफाइल से जुड़े KDBGHeader हस्ताक्षरों के लिए स्कैन करता है और झूठे सकारात्मक को कम करने के लिए सैनीटी चेक लागू करता है। आउटपुट की विस्तारता और किए जा सकने वाले सैनीटी चेक की संख्या इस पर निर्भर करती है कि क्या Volatility एक DTB ढूंढ सकता है, इसलिए यदि आप पहले से ही सही प्रोफ़ाइल जानते हैं (या यदि आपके पास imageinfo से प्रोफ़ाइल सुझाव है), तो सुनिश्चित करें कि आप इसका उपयोग करें।

हमेशा **kdbgscan द्वारा पाए गए प्रक्रियाओं की संख्या** पर नज़र रखें। कभी-कभी imageinfo और kdbgscan **एक से अधिक** उपयुक्त **प्रोफ़ाइल** पा सकते हैं लेकिन केवल **मान्य एक में कुछ प्रक्रिया संबंधित** होगी (यह इसलिए है क्योंकि प्रक्रियाओं को निकालने के लिए सही KDBG पते की आवश्यकता होती है)
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

**कर्नेल डिबगर ब्लॉक**, जिसे **KDBG** के नाम से जाना जाता है, वोलाटिलिटी और विभिन्न डिबगर्स द्वारा किए गए फोरेंसिक कार्यों के लिए महत्वपूर्ण है। इसे `KdDebuggerDataBlock` के रूप में पहचाना जाता है और इसका प्रकार `_KDDEBUGGER_DATA64` है, इसमें आवश्यक संदर्भ जैसे `PsActiveProcessHead` शामिल हैं। यह विशेष संदर्भ प्रक्रिया सूची के सिर की ओर इशारा करता है, जिससे सभी प्रक्रियाओं की सूची बनाना संभव होता है, जो गहन मेमोरी विश्लेषण के लिए मौलिक है।

## OS Information
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
The plugin `banners.Banners` can be used in **vol3 to try to find linux banners** in the dump.

## Hashes/Passwords

SAM हैश, [डोमेन कैश की गई क्रेडेंशियल्स](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) और [lsa रहस्य](../../../windows-hardening/authentication-credentials-uac-and-efs/#lsa-secrets) निकालें।

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{% endtab %}
{% endtabs %}

## मेमोरी डंप

एक प्रक्रिया का मेमोरी डंप वर्तमान स्थिति का **सब कुछ** **निकालेगा**। **procdump** मॉड्यूल केवल **कोड** को **निकालेगा**।
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) **स्पेन** में सबसे प्रासंगिक साइबर सुरक्षा कार्यक्रम है और **यूरोप** में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस हर अनुशासन में प्रौद्योगिकी और साइबर सुरक्षा पेशेवरों के लिए एक उबालता हुआ बैठक बिंदु है।

{% embed url="https://www.rootedcon.com/" %}

## प्रक्रियाएँ

### प्रक्रियाओं की सूची

**संदिग्ध** प्रक्रियाओं (नाम द्वारा) या **अप्रत्याशित** बाल **प्रक्रियाओं** (उदाहरण के लिए, iexplorer.exe का एक बाल cmd.exe) को खोजने की कोशिश करें।\
छिपी हुई प्रक्रियाओं की पहचान करने के लिए pslist के परिणाम की psscan के साथ **तुलना** करना दिलचस्प हो सकता है।

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% endtab %}
{% endtabs %}

### डंप प्रोसेस

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### कमांड लाइन

क्या कुछ संदिग्ध निष्पादित किया गया था?

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

`cmd.exe` में निष्पादित कमांड **`conhost.exe`** (या Windows 7 से पहले के सिस्टम पर `csrss.exe`) द्वारा प्रबंधित होते हैं। इसका मतलब है कि यदि **`cmd.exe`** को एक हमलावर द्वारा समाप्त कर दिया जाता है इससे पहले कि एक मेमोरी डंप प्राप्त किया जाए, तो भी **`conhost.exe`** की मेमोरी से सत्र का कमांड इतिहास पुनर्प्राप्त करना संभव है। ऐसा करने के लिए, यदि कंसोल के मॉड्यूल में असामान्य गतिविधि का पता लगाया जाता है, तो संबंधित **`conhost.exe`** प्रक्रिया की मेमोरी को डंप किया जाना चाहिए। फिर, इस डंप के भीतर **strings** की खोज करके, सत्र में उपयोग की गई कमांड लाइनों को संभावित रूप से निकाला जा सकता है।

### Environment

प्रत्येक चल रही प्रक्रिया के env वेरिएबल प्राप्त करें। कुछ दिलचस्प मान हो सकते हैं।

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{% endtab %}
{% endtabs %}

### टोकन विशेषाधिकार

अप्रत्याशित सेवाओं में विशेषाधिकार टोकन के लिए जांचें।\
कुछ विशेषाधिकार प्राप्त टोकन का उपयोग करने वाली प्रक्रियाओं की सूची बनाना दिलचस्प हो सकता है।

{% tabs %}
{% tab title="vol3" %}
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="vol2" %}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

प्रक्रिया द्वारा स्वामित्व वाले प्रत्येक SSID की जांच करें।\
यह दिलचस्प हो सकता है कि उन प्रक्रियाओं की सूची बनाएं जो एक विशेषाधिकार SIDs का उपयोग कर रही हैं (और उन प्रक्रियाओं की जो कुछ सेवा SIDs का उपयोग कर रही हैं)। 

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### हैंडल

जानना उपयोगी है कि **प्रक्रिया के लिए किस अन्य फ़ाइलों, कुंजियों, थ्रेड्स, प्रक्रियाओं... का हैंडल है** (खुला हुआ है)

{% tabs %}
{% tab title="vol3" %}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% endtabs %}

### DLLs

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### प्रक्रियाओं के अनुसार स्ट्रिंग्स

Volatility हमें यह जांचने की अनुमति देता है कि एक स्ट्रिंग किस प्रक्रिया से संबंधित है।

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

यह एक प्रक्रिया के अंदर स्ट्रिंग्स के लिए yarascan मॉड्यूल का उपयोग करके खोज करने की अनुमति भी देता है:

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows** उन प्रोग्रामों का ट्रैक रखता है जिन्हें आप चलाते हैं, एक फीचर के माध्यम से जो रजिस्ट्री में **UserAssist keys** कहलाता है। ये कीज़ रिकॉर्ड करती हैं कि प्रत्येक प्रोग्राम कितनी बार चलाया गया है और इसे आखिरी बार कब चलाया गया था।

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) **स्पेन** में सबसे प्रासंगिक साइबरसुरक्षा कार्यक्रम है और **यूरोप** में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस हर अनुशासन में प्रौद्योगिकी और साइबरसुरक्षा पेशेवरों के लिए एक उष्णकटिबंधीय बैठक बिंदु है।

{% embed url="https://www.rootedcon.com/" %}

## सेवाएँ

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{% endtab %}
{% endtabs %}

## नेटवर्क

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{% endtab %}
{% endtabs %}

## रजिस्ट्री हाइव

### उपलब्ध हाइव प्रिंट करें

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### एक मान प्राप्त करें

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

### डंप
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## फ़ाइल प्रणाली

### माउंट

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% endtabs %}

### स्कैन/डंप

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% endtabs %}

### मास्टर फ़ाइल तालिका

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

**NTFS फ़ाइल प्रणाली** एक महत्वपूर्ण घटक का उपयोग करती है जिसे _मास्टर फ़ाइल तालिका_ (MFT) के रूप में जाना जाता है। इस तालिका में एक वॉल्यूम पर हर फ़ाइल के लिए कम से कम एक प्रविष्टि शामिल होती है, जिसमें MFT स्वयं भी शामिल है। प्रत्येक फ़ाइल के बारे में महत्वपूर्ण विवरण, जैसे **आकार, समय मुहरें, अनुमतियाँ, और वास्तविक डेटा**, MFT प्रविष्टियों के भीतर या MFT के बाहरी क्षेत्रों में संलग्न होते हैं, लेकिन इन प्रविष्टियों द्वारा संदर्भित होते हैं। अधिक विवरण [आधिकारिक दस्तावेज़ीकरण](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table) में पाया जा सकता है।

### SSL कुंजी/प्रमाणपत्र

{% tabs %}
{% tab title="vol3" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="vol2" %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

## मैलवेयर

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% endtabs %}

### yara के साथ स्कैनिंग

इस स्क्रिप्ट का उपयोग करें सभी yara मैलवेयर नियमों को github से डाउनलोड और मर्ज करने के लिए: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
_**rules**_ निर्देशिका बनाएं और इसे निष्पादित करें। यह _**malware\_rules.yar**_ नामक एक फ़ाइल बनाएगा जिसमें मैलवेयर के लिए सभी yara नियम शामिल हैं।

{% tabs %}
{% tab title="vol3" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% endtab %}

{% tab title="vol2" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}

## MISC

### External plugins

यदि आप बाहरी प्लगइन्स का उपयोग करना चाहते हैं, तो सुनिश्चित करें कि प्लगइन्स से संबंधित फ़ोल्डर पहले पैरामीटर के रूप में उपयोग किए गए हैं।

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

इसे [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns) से डाउनलोड करें
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### सिमलिंक

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

यह संभव है कि **मेमोरी से बैश इतिहास पढ़ा जाए।** आप _.bash\_history_ फ़ाइल को भी डंप कर सकते हैं, लेकिन यह अक्षम था, आप खुश होंगे कि आप इस वोलाटिलिटी मॉड्यूल का उपयोग कर सकते हैं।

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### टाइमलाइन

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### ड्राइवर

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### क्लिपबोर्ड प्राप्त करें
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### IE इतिहास प्राप्त करें
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### नोटपैड टेक्स्ट प्राप्त करें
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### स्क्रीनशॉट
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### मास्टर बूट रिकॉर्ड (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
The **Master Boot Record (MBR)** एक महत्वपूर्ण भूमिका निभाता है जो एक स्टोरेज माध्यम के तार्किक विभाजन का प्रबंधन करता है, जो विभिन्न [file systems](https://en.wikipedia.org/wiki/File\_system) के साथ संरचित होते हैं। यह न केवल विभाजन लेआउट जानकारी रखता है बल्कि इसमें निष्पादन योग्य कोड भी होता है जो एक बूट लोडर के रूप में कार्य करता है। यह बूट लोडर या तो सीधे OS के दूसरे चरण के लोडिंग प्रक्रिया को प्रारंभ करता है (देखें [second-stage boot loader](https://en.wikipedia.org/wiki/Second-stage\_boot\_loader)) या प्रत्येक विभाजन के [volume boot record](https://en.wikipedia.org/wiki/Volume\_boot\_record) (VBR) के साथ सामंजस्य में काम करता है। गहन ज्ञान के लिए, [MBR Wikipedia page](https://en.wikipedia.org/wiki/Master\_boot\_record) देखें।

## References

* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **स्पेन** में सबसे प्रासंगिक साइबर सुरक्षा कार्यक्रम है और **यूरोप** में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने के मिशन** के साथ, यह कांग्रेस हर अनुशासन में प्रौद्योगिकी और साइबर सुरक्षा पेशेवरों के लिए एक उष्णकटिबंधीय बैठक बिंदु है।

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
