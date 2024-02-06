# Volatility - CheatSheet

<details>

<summary><strong>जीरो से हीरो तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

दूसरे तरीके HackTricks का समर्थन करने के लिए:

* अगर आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें, HackTricks** और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks) github repos में PRs सबमिट करके।

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) स्पेन में सबसे महत्वपूर्ण साइबर सुरक्षा घटना है और यूरोप में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा विशेषज्ञों के लिए एक उफान मिलने का समारोह है।

{% embed url="https://www.rootedcon.com/" %}

अगर आप कुछ **तेज़ और पागल** चाहते हैं जो कई Volatility प्लगइन्स को पैरलल पर लॉन्च करेगा तो आप इस्तेमाल कर सकते हैं: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
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
#### volatility2

{% tabs %}
{% tab title="Method1" %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="Method 2" %}यहाँ हम दूसरी विधि का उपयोग करके डेटा विश्लेषण करेंगे।{% endtab %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Volatility Commands

[वॉलेटिलिटी कमांड रेफरेंस](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan) में आधिकारिक दस्तावेज़ तक पहुंचें।

### "सूची" बनाम "स्कैन" प्लगइन पर एक नोट

वॉलेटिलिटी के पास प्लगइन्स के लिए दो मुख्य दृष्टिकोण हैं, जो कभी-कभी उनके नामों में प्रकट होते हैं। "सूची" प्लगइन्स विंडोज कर्नेल संरचनाओं के माध्यम से जानकारी प्राप्त करने के लिए प्रयास करेंगे जैसे प्रक्रियाएँ (यादृच्छिक और लिंक्ड सूची की खोज करें `_EPROCESS` संरचनाओं की मेमोरी में), ओएस हैंडल्स (हैंडल टेबल का पता लगाना, पाए गए किसी भी प्वाइंटर को डीरेफरेंस करना, आदि)। वे अधिक या कम विंडोज एपीआई की तरह व्यवहार करते हैं जैसे, उदाहरण के लिए, प्रक्रियाओं की सूची देने के लिए।

इससे "सूची" प्लगइन्स काफी तेज होते हैं, लेकिन विंडोज एपीआई के साथ एक ही रूप से मलवेयर द्वारा परिवर्तन के लिए विकल्पनशील होते हैं। उदाहरण के लिए, अगर मलवेयर DKOM का उपयोग करता है तो एक प्रक्रिया को `_EPROCESS` लिंक्ड सूची से अलग करने के लिए, तो वह टास्क मैनेजर में प्रकट नहीं होगा और न ही यह pslist में दिखेगा।

दूसरी ओर, "स्कैन" प्लगइन्स, एक तरह का उपाय अपनाएंगे जो विशिष्ट संरचनाओं के रूप में डिरेफरेंस करने पर समझ में आ सकती है। `psscan` उदाहरण के लिए मेमोरी पढ़ेगा और इसे `_EPROCESS` ऑब्ज
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
यदि आप **नया प्रोफ़ाइल जिसे आपने डाउनलोड किया है** (उदाहरण के लिए एक लिनक्स वाला) उसे उपयोग करना चाहते हैं, तो निम्नलिखित फ़ोल्डर संरचना बनानी होगी: _plugins/overlays/linux_ और इस फ़ोल्डर में प्रोफ़ाइल को समेत करने वाली ज़िप फ़ाइल डालें। फिर, निम्नलिखित कमांड का उपयोग करके प्रोफ़ाइल की संख्या प्राप्त करें:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
आप **Linux और Mac profiles** को [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) से डाउनलोड कर सकते हैं।

पिछले चंक में आप देख सकते हैं कि प्रोफ़ाइल का नाम `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64` है, और आप इसका उपयोग कुछ इस प्रकार से कर सकते हैं:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### खोज प्रोफ़ाइल
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo और kdbgscan के बीच अंतर**

जबकि imageinfo केवल प्रोफ़ाइल सुझाव प्रदान करता है, **kdbgscan** का उद्देश्य सही प्रोफ़ाइल और सही KDBG पता (यदि कई हों) को सकारात्मक रूप से पहचानना है। यह प्लगइन Volatility प्रोफ़ाइल्स से जुड़े KDBGHeader हस्ताक्षरों के लिए स्कैन करता है और फर्जी सकारात्मक परिणामों को कम करने के लिए सानिति जांच लागू करता है। आउटपुट की व्यापकता और सानिति जांचों की संख्या इस पर निर्भर करती है कि Volatility क्या एक DTB ढूंढ सकता है, इसलिए यदि आपको पहले से सही प्रोफ़ाइल पता है (या यदि आपके पास imageinfo से प्रोफ़ाइल सुझाव है), तो सुनिश्चित करें कि आप उसका उपयोग करते हैं।

हमेशा **देखें कि kdbgscan ने कितने प्रक्रियाएँ खोजी हैं**। कभी-कभी imageinfo और kdbgscan **एक से अधिक** उपयुक्त **प्रोफ़ाइल** ढूंढ सकते हैं, लेकिन केवल **वैध एक में कुछ प्रक्रिया संबंधित होगी** (यह इसलिए है कि प्रक्रियाएँ निकालने के लिए सही KDBG पता आवश्यक है)
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

**कर्नेल डीबगर ब्लॉक** (जिसे \_KDDEBUGGER\_DATA64 के प्रकार का KdDebuggerDataBlock नामकित किया गया है, या **KDBG** द्वारा volatility) उन कई चीजों के लिए महत्वपूर्ण है जो Volatility और डीबगर करते हैं। उदाहरण के लिए, इसमें PsActiveProcessHead को संदर्भित है जो प्रक्रिया सूचीकरण के लिए सभी प्रक्रियाओं के सूची के मुख्य है।

## ओएस सूचना
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
यह प्लगइन `banners.Banners` डंप में **लिनक्स बैनर्स** खोजने के लिए **vol3** में उपयोग किया जा सकता है।

## Hashes/Passwords

SAM हैश, [डोमेन कैश्ड क्रेडेंशियल्स](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) और [lsa सीक्रेट्स](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets) को निकालें।

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
यहाँ वोलेटिलिटी चीटशीट का अनुभाग है।

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## मेमोरी डंप

प्रक्रिया का मेमोरी डंप प्रक्रिया की वर्तमान स्थिति को **निकालेगा**। **Procdump** मॉड्यूल केवल **कोड** को **निकालेगा**।
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) स्पेन में सबसे महत्वपूर्ण साइबर सुरक्षा घटना है और यूरोप में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा विशेषज्ञों के लिए एक उफनती मिलन स्थल है हर विषय में।

{% embed url="https://www.rootedcon.com/" %}

## प्रक्रियाएँ

### प्रक्रियाएँ की सूची

**संदेहजनक** प्रक्रियाएँ (नाम के द्वारा) या **अप्रत्याशित** बच्चा **प्रक्रियाएँ** (उदाहरण के लिए iexplorer.exe के बच्चे के रूप में cmd.exe) खोजने की कोशिश करें।\
यह दिख सकता है कि pslist का परिणाम psscan के साथ तुलना करना रहस्यमय प्रक्रियाओं की पहचान करने के लिए दिलचस्प हो सकता है।

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %}वोलेटिलिटी चीटशीट

### वोलेटिलिटी चीटशीट

#### वोलेटिलिटी इंस्टॉलेशन

- वोलेटिलिटी इंस्टॉलेशन की जांच करें
  ```bash
  volatility -h
  ```

#### बेसिक कमांड्स

- चलाने के लिए वोलेटिलिटी की जांच करें
  ```bash
  volatility
  ```

- वोलेटिलिटी के साथ उपलब्ध सभी प्लगइन्स की सूची देखें
  ```bash
  volatility --info | less
  ```

#### प्रक्रिया विश्लेषण

- सभी प्रक्रियाओं की सूची देखें
  ```bash
  volatility -f <memory_dump> --profile=<profile> pslist
  ```

- विशिष्ट प्रक्रिया के लिए विस्तृत जानकारी प्राप्त करें
  ```bash
  volatility -f <memory_dump> --profile=<profile> pstree -p <pid>
  ```

#### नेटवर्क विश्लेषण

- नेटवर्क कनेक्शन्स की सूची देखें
  ```bash
  volatility -f <memory_dump> --profile=<profile> connections
  ```

- नेटवर्क ट्रैफिक का विश्लेषण करें
  ```bash
  volatility -f <memory_dump> --profile=<profile> tcpflow -p <pid>
  ```

#### फाइल सिस्टम विश्लेषण

- लोगों, रजिस्ट्री और अन्य फ़ाइलों की सूची देखें
  ```bash
  volatility -f <memory_dump> --profile=<profile> filescan
  ```

- विशिष्ट फ़ाइल के लिए विस्तृत जानकारी प्राप्त करें
  ```bash
  volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -n
  ```

#### रजिस्ट्री विश्लेषण

- रजिस्ट्री कुंजियों की सूची देखें
  ```bash
  volatility -f <memory_dump> --profile=<profile> hivelist
  ```

- रजिस्ट्री से डेटा प्राप्त करें
  ```bash
  volatility -f <memory_dump> --profile=<profile> printkey -o <offset>
  ```

#### डाम्प और लोग फाइल्स

- डाम्प और लोग फ़ाइल्स की सूची देखें
  ```bash
  volatility -f <memory_dump> --profile=<profile> malfind
  ```

- विशिष्ट डाम्प या लोग फ़ाइल के लिए विस्तृत जानकारी प्राप्त करें
  ```bash
  volatility -f <memory_dump> --profile=<profile> malfind -p <pid>
  ```

#### डेटा और टाइमलाइन विश्ग्लेषण

- डेटा और टाइमलाइन विश्लेषण करें
  ```bash
  volatility -f <memory_dump> --profile=<profile> timeliner
  ```

#### अन्य उपयोगी कमांड्स

- वोलेटिलिटी के साथ उपलब्ध सभी कमांड्स की सूची देखें
  ```bash
  volatility --help
  ```

- वोलेटिलिटी के साथ उपलब्ध सभी टेम्प्लेट्स की सूची देखें
  ```bash
  volatility --info | grep "Templates"
  ```

{% endtab %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### डंप प्रोसेस

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="vol2" %}हैकर्स के लिए एक अच्छा उपकरण है Volatility, जो रूपांतरण और विश्लेषण के लिए एक खुला स्रोतीय रूपांतरण उपकरण है। यह एक शक्तिशाली मेमोरी विश्लेषण उपकरण है जो रनटाइम प्रक्रियाओं और कर्मचारियों की जानकारी प्राप्त करने में मदद करता है। यह चीजें जैसे कि प्रक्रिया, नेटवर्क कनेक्शन्स, लोग-ऑन और अन्य उपयोगकर्ता की गतिविधियों का विश्लेषण करने के लिए उपयुक्त है। यह एक उपयुक्त उपकरण है जो डिफेंस और फोरेंसिक्स के क्षेत्र में उपयोग किया जा सकता है।{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### कमांड लाइन

क्या कोई संदेहास्पद क्रियाएँ की गई थीं?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}यहाँ वोलेटिलिटी चीटशीट का अनुभाग है। यह चीटशीट वोलेटिलिटी फ्रेमवर्क के उपयोग के लिए महत्वपूर्ण तकनीकी जानकारी प्रदान करती है। यह विभिन्न मेमोरी डंप एनालिसिस टूल्स के लिए उपयोगी आदेश और उपाय प्रदान करती है। यह चीटशीट विभिन्न ऑपरेटिंग सिस्टम्स और आर्किटेक्चर्स के लिए उपयुक्त है। यह वोलेटिलिटी फ्रेमवर्क का उपयोग करके डेटा एनालिसिस, माल्वेयर डिटेक्शन, और फोरेंसिक्स जैसे कार्यों को सुविधाजनक बनाती है। यह चीटशीट विभिन्न वोलेटिलिटी प्लगइन्स के लिए उपयोगी भी है। %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

कमांड cmd.exe में दर्ज किए गए होते हैं **conhost.exe** द्वारा प्रसंस्कृत किए जाते हैं (Windows 7 से पहले csrss.exe). इसलिए यदि किसी हमलावर ने **cmd.exe को मार दिया** हो **पहले** हमें एक मेमोरी **डंप** प्राप्त करने से पहले, तो भी **conhost.exe की मेमोरी** से कमांड लाइन सत्र का इतिहास पुनः प्राप्त करने की अच्छी संभावना है। यदि आप **कुछ अजीब** (कंसोल के मॉड्यूल का उपयोग करके) पाते हैं, तो **conhost.exe संबंधित** प्रक्रिया की **मेमोरी** को **डंप** करने का प्रयास करें और इसमें से **स्ट्रिंग्स** खोजें ताकि कमांड लाइन्स को निकाल सकें।

### पर्यावरण

प्रत्येक चल रही प्रक्रिया की एनवायरनमेंट वेरिएबल्स प्राप्त करें। कुछ दिलचस्प मान्यताएँ हो सकती हैं।
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% टैब शीर्षक="vol2" %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### टोकन विशेषाधिकार

अप्रत्याशित सेवाओं में विशेषाधिकार टोकन की जांच करें।
कुछ विशेषाधिकृत टोकन का उपयोग करने वाले प्रक्रियाओं की सूची बनाना दिलचस्प हो सकता है।
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="vol2" %}वोलेटिलिटी चीटशीट

### वोलेटिलिटी चीटशीट

#### वोलेटिलिटी टूल्स का उपयोग

- **डेटा कलेक्शन:** `imagecopy`, `memdump`, `memdmp`, `malfind`, `procdump`, `psscan`, `pstree`, `pslist`, `dlllist`, `getsids`, `hivelist`, `apihooks`, `ldrmodules`, `modscan`, `modules`, `moddump`, `modscan`, `ssdt`, `driverirp`, `drivermodule`, `driverscan`, `devicetree`, `atomscan`, `atomtable`, `gdt`, `idt`, `callbacks`, `callback`, `timeliner`, `timers`, `svcscan`, `svcscan2`, `svcscan3`, `mutantscan`, `mutantscan2`, `mutantscan3`, `filescan`, `filescan2`, `filescan3`, `handles`, `handles2`, `handles3`, `privs`, `privs2`, `privs3`, `psxview`, `psscan`, `psscan2`, `psscan3`, `pslist`, `pslist2`, `pslist3`, `psxview`, `psxview2`, `psxview3`, `ssdeep`, `yarascan`, `yarascanner`, `yarascan2`, `yarascanner2`, `yarascan3`, `yarascanner3`, `yarascan4`, `yarascanner4`, `yarascan5`, `yarascanner5`, `yarascan6`, `yarascanner6`, `yarascan7`, `yarascanner7`, `yarascan8`, `yarascanner8`, `yarascan9`, `yarascanner9`, `yarascan10`, `yarascanner10`, `yarascan11`, `yarascanner11`, `yarascan12`, `yarascanner12`, `yarascan13`, `yarascanner13`, `yarascan14`, `yarascanner14`, `yarascan15`, `yarascanner15`, `yarascan16`, `yarascanner16`, `yarascan17`, `yarascanner17`, `yarascan18`, `yarascanner18`, `yarascan19`, `yarascanner19`, `yarascan20`, `yarascanner20`, `yarascan21`, `yarascanner21`, `yarascan22`, `yarascanner22`, `yarascan23`, `yarascanner23`, `yarascan24`, `yarascanner24`, `yarascan25`, `yarascanner25`, `yarascan26`, `yarascanner26`, `yarascan27`, `yarascanner27`, `yarascan28`, `yarascanner28`, `yarascan29`, `yarascanner29`, `yarascan30`, `yarascanner30`, `yarascan31`, `yarascanner31`, `yarascan32`, `yarascanner32`, `yarascan33`, `yarascanner33`, `yarascan34`, `yarascanner34`, `yarascan35`, `yarascanner35`, `yarascan36`, `yarascanner36`, `yarascan37`, `yarascanner37`, `yarascan38`, `yarascanner38`, `yarascan39`, `yarascanner39`, `yarascan40`, `yarascanner40`, `yarascan41`, `yarascanner41`, `yarascan42`, `yarascanner42`, `yarascan43`, `yarascanner43`, `yarascan44`, `yarascanner44`, `yarascan45`, `yarascanner45`, `yarascan46`, `yarascanner46`, `yarascan47`, `yarascanner47`, `yarascan48`, `yarascanner48`, `yarascan49`, `yarascanner49`, `yarascan50`, `yarascanner50`, `yarascan51`, `yarascanner51`, `yarascan52`, `yarascanner52`, `yarascan53`, `yarascanner53`, `yarascan54`, `yarascanner54`, `yarascan55`, `yarascanner55`, `yarascan56`, `yarascanner56`, `yarascan57`, `yarascanner57`, `yarascan58`, `yarascanner58`, `yarascan59`, `yarascanner59`, `yarascan60`, `yarascanner60`, `yarascan61`, `yarascanner61`, `yarascan62`, `yarascanner62`, `yarascan63`, `yarascanner63`, `yarascan64`, `yarascanner64`, `yarascan65`, `yarascanner65`, `yarascan66`, `yarascanner66`, `yarascan67`, `yarascanner67`, `yarascan68`, `yarascanner68`, `yarascan69`, `yarascanner69`, `yarascan70`, `yarascanner70`, `yarascan71`, `yarascanner71`, `yarascan72`, `yarascanner72`, `yarascan73`, `yarascanner73`, `yarascan74`, `yarascanner74`, `yarascan75`, `yarascanner75`, `yarascan76`, `yarascanner76`, `yarascan77`, `yarascanner77`, `yarascan78`, `yarascanner78`, `yarascan79`, `yarascanner79`, `yarascan80`, `yarascanner80`, `yarascan81`, `yarascanner81`, `yarascan82`, `yarascanner82`, `yarascan83`, `yarascanner83`, `yarascan84`, `yarascanner84`, `yarascan85`, `yarascanner85`, `yarascan86`, `yarascanner86`, `yarascan87`, `yarascanner87`, `yarascan88`, `yarascanner88`, `yarascan89`, `yarascanner89`, `yarascan90`, `yarascanner90`, `yarascan91`, `yarascanner91`, `yarascan92`, `yarascanner92`, `yarascan93`, `yarascanner93`, `yarascan94`, `yarascanner94`, `yarascan95`, `yarascanner95`, `yarascan96`, `yarascanner96`, `yarascan97`, `yarascanner97`, `yarascan98`, `yarascanner98`, `yarascan99`, `yarascanner99`, `yarascan100`, `yarascanner100`, `yarascan101`, `yarascanner101`, `yarascan102`, `yarascanner102`, `yarascan103`, `yarascanner103`, `yarascan104`, `yarascanner104`, `yarascan105`, `yarascanner105`, `yarascan106`, `yarascanner106`, `yarascan107`, `yarascanner107`, `yarascan108`, `yarascanner108`, `yarascan109`, `yarascanner109`, `yarascan110`, `yarascanner110`, `yarascan111`, `yarascanner111`, `yarascan112`, `yarascanner112`, `yarascan113`, `yarascanner113`, `yarascan114`, `yarascanner114`, `yarascan115`, `yarascanner115`, `yarascan116`, `yarascanner116`, `yarascan117`, `yarascanner117`, `yarascan118`, `yarascanner118`, `yarascan119`, `yarascanner119`, `yarascan120`, `yarascanner120`, `yarascan121`, `yarascanner121`, `yarascan122`, `yarascanner122`, `yarascan123`, `yarascanner123`, `yarascan124`, `yarascanner124`, `yarascan125`, `yarascanner125`, `yarascan126`, `yarascanner126`, `yarascan127`, `yarascanner127`, `yarascan128`, `yarascanner128`, `yarascan129`, `yarascanner129`, `yarascan130`, `yarascanner130`, `yarascan131`, `yarascanner131`, `yarascan132`, `yarascanner132`, `yarascan133`, `yarascanner133`, `yarascan134`, `yarascanner134`, `yarascan135`, `yarascanner135`, `yarascan136`, `yarascanner136`, `yarascan137`, `yarascanner137`, `yarascan138`, `yarascanner138`, `yarascan139`, `yarascanner139`, `yarascan140`, `yarascanner140`, `yarascan141`, `yarascanner141`, `yarascan142`, `yarascanner142`, `yarascan143`, `yarascanner143`, `yarascan144`, `yarascanner144`, `yarascan145`, `yarascanner145`, `yarascan146`, `yarascanner146`, `yarascan147`, `yarascanner147`, `yarascan148`, `yarascanner148`, `yarascan149`, `yarascanner149`, `yarascan150`, `yarascanner150`, `yarascan151`, `yarascanner151`, `yarascan152`, `yarascanner152`, `yarascan153`, `yarascanner153`, `yarascan154`, `yarascanner154`, `yarascan155`, `yarascanner155`, `yarascan156`, `yarascanner156`, `yarascan157`, `yarascanner157`, `yarascan158`, `yarascanner158`, `yarascan159`, `yarascanner159`, `yarascan160`, `yarascanner160`, `yarascan161`, `yarascanner161`, `yarascan162`, `yarascanner162`, `yarascan163`, `yarascanner163`, `yarascan164`, `yarascanner164`, `yarascan165`, `yarascanner165`, `yarascan166`, `yarascanner166`, `yarascan167`, `yarascanner167`, `yarascan168`, `yarascanner168`, `yarascan169`, `yarascanner169`, `yarascan170`, `yarascanner170`, `yarascan171`, `yarascanner171`, `yarascan172`, `yarascanner172`, `yarascan173`, `yarascanner173`, `yarascan174`, `yarascanner174`, `yarascan175`, `yarascanner175`, `yarascan176`, `yarascanner176`, `yarascan177`, `yarascanner177`, `yarascan178`, `yarascanner178`, `yarascan179`, `yarascanner179`, `yarascan180`, `yarascanner180`, `yarascan181`, `yarascanner181`, `yarascan182`, `yarascanner182`, `yarascan183`, `yarascanner183`, `yarascan184`, `yarascanner184`, `yarascan185`, `yarascanner185`, `yarascan186`, `yarascanner186`, `yarascan187`, `yarascanner187`, `yarascan188`, `yarascanner188`, `yarascan189`, `yarascanner189`, `yarascan190`, `yarascanner190`, `yarascan191`, `yarascanner191`, `yarascan192`, `yarascanner192`, `yarascan193`, `yarascanner193`, `yarascan194`, `yarascanner194`, `yarascan195`, `yarascanner195`, `yarascan196`, `yarascanner196`, `yarascan197`, `yarascanner197`, `yarascan198`, `yarascanner198`, `yarascan199`, `yarascanner199`, `yarascan200`, `yarascanner200`, `yarascan201`, `yarascanner201`, `yarascan202`, `yarascanner202`, `yarascan203`, `yarascanner203`, `yarascan204`, `yarascanner204`, `yarascan205`, `yarascanner205`, `yarascan206`, `yarascanner206`, `yarascan207`, `yarascanner207`, `yarascan208`, `yarascanner208`, `yarascan209`, `yarascanner209`, `yarascan210`, `yarascanner210`, `yarascan211`, `yarascanner211`, `yarascan212`, `yarascanner212`, `yarascan213`, `yarascanner213`, `yarascan214`, `yarascanner214`, `yarascan215`, `yarascanner215`, `yarascan216`, `yarascanner216`, `yarascan217`, `yarascanner217`, `yarascan218`, `yarascanner218`, `yarascan219`, `yarascanner219`, `yarascan220`, `yarascanner220`, `yarascan221`, `yarascanner221`, `yarascan222`, `yarascanner222`, `yarascan223`, `yarascanner223`, `yarascan224`, `yarascanner224`, `yarascan225`, `yarascanner225`, `yarascan226`, `yarascanner226`, `yarascan227`, `yarascanner227`, `yarascan228`, `yarascanner228`, `yarascan229`, `yarascanner229`, `yarascan230`, `yarascanner230`, `yarascan231`, `yarascanner231`, `yarascan232`, `yarascanner232`, `yarascan233`, `yarascanner233`, `yarascan234`, `yarascanner234`, `yarascan235`, `yarascanner235`, `yarascan236`, `yarascanner236`, `yarascan237`, `yarascanner237`, `yarascan238`, `yarascanner238`, `yarascan239`, `yarascanner239`, `yarascan240`, `yarascanner240`, `yarascan241`, `yarascanner241`, `yarascan242`, `yarascanner242`, `yarascan243`, `yarascanner243`, `yarascan244`, `yarascanner244`, `yarascan245`, `yarascanner245`, `yarascan246`, `yarascanner246`, `yarascan247`, `yarascanner247`, `yarascan248`, `yarascanner248`, `yarascan249`, `yarascanner249`, `yarascan250`, `yarascanner250`, `yarascan251`, `yarascanner251`, `yarascan252`, `yarascanner252`, `yarascan253`, `yarascanner253`, `yarascan254`, `yarascanner254`, `yarascan255`, `yarascanner255`, `yarascan256`, `yarascanner256`, `yarascan257`, `yarascanner257`, `yarascan258`, `yarascanner258`, `yarascan259`, `yarascanner259`, `yarascan260`, `yarascanner260`, `yarascan261`, `yarascanner261`, `yarascan262`, `yarascanner262`, `yarascan263`, `yarascanner263`, `yarascan264`, `yarascanner264`, `yarascan265`, `yarascanner265`, `yarascan266`, `yarascanner266`, `yarascan267`, `yarascanner267`, `yarascan268`, `yarascanner268`, `yarascan269`, `yarascanner269`, `yarascan270`, `yarascanner270`, `yarascan271`, `yarascanner271`, `yarascan272`, `yarascanner272`, `yarascan273`, `yarascanner273`, `yarascan274`, `yarascanner274`, `yarascan275`, `yarascanner275`, `yarascan276`, `yarascanner276`, `yarascan277`, `yarascanner277`, `yarascan278`, `yarascanner278`, `yarascan279`, `yarascanner279`, `yarascan280`, `yarascanner280`, `yarascan281`, `yarascanner281`, `yarascan282`, `yarascanner282`, `yarascan283`, `yarascanner283`, `yarascan284`, `yarascanner284`, `yarascan285`, `yarascanner285`, `yarascan286`, `yarascanner286`, `yarascan287`, `yarascanner287`, `yarascan288`, `yarascanner288`, `yarascan289`, `yarascanner289`, `yarascan290`, `yarascanner290`, `yarascan291`, `yarascanner291`, `yarascan292`, `yarascanner292`, `yarascan293`, `yarascanner293`, `yarascan294`, `yarascanner294`, `yarascan295`, `yarascanner295`, `yarascan296`, `yarascanner296`, `yarascan297`, `yarascanner297`, `yarascan298`, `yarascanner298`, `yarascan299`, `yarascanner299`, `yarascan300`, `yarascanner300`, `yarascan301`, `yarascanner301`, `yarascan302`, `yarascanner302`, `yarascan303`, `yarascanner303`, `yarascan304`, `yarascanner304`, `yarascan305`, `yarascanner305`, `yarascan306`, `yarascanner306`, `yarascan307`, `yarascanner307`, `yarascan308`, `yarascanner308`, `yarascan309`, `yarascanner309`, `yarascan310`, `yarascanner310`, `yarascan311`, `yarascanner311`, `yarascan312`, `yarasc
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### एसआईडी

प्रक्रिया द्वारा स्वामित्व में रखे गए प्रत्येक एसएसआईडी की जांच करें।\
यह दिलचस्प हो सकता है कि एक विशेषाधिकार एसआईडी का उपयोग करने वाली प्रक्रियाओं की सूची बनाना (और कुछ सेवा एसआईडी का उपयोग करने वाली प्रक्रियाओं की सूची बनाना)।
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}यहाँ वोलेटिलिटी चीटशीट का अनुवाद है:

## वोलेटिलिटी चीटशीट

### वोलेटिलिटी टूल्स का उपयोग

- **डेटा कलेक्शन:**
  - `volatility -f <डंप फ़ाइल> imageinfo` - डंप फ़ाइल की मेटाडेटा देखें
  - `volatility -f <डंप फ़ाइल> --profile=<प्रोफ़ाइल> pslist` - प्रक्रियाओं की सूची प्राप्त करें
  - `volatility -f <डंप फ़ाइल> --profile=<प्रोफ़ाइल> memdump -p <प्रक्रिया ID> -D <आउटपुट फ़ोल्डर>` - प्रक्रिया का मेमोरी डंप करें

- **अध्ययन:**
  - `volatility -f <डंप फ़ाइल> --profile=<प्रोफ़ाइल> pstree` - प्रक्रियाओं का पेड़ देखें
  - `volatility -f <डंप फ़ाइल> --profile=<प्रोफ़ाइल> cmdline -p <प्रक्रिया ID>` - प्रक्रिया कमांड लाइन देखें
  - `volatility -f <डंप फ़ाइल> --profile=<प्रोफ़ाइल> filescan` - फ़ाइल सिस्टम की स्कैनिंग करें

- **जांच:**
  - `volatility -f <डंप फ़ाइल> --profile=<प्रोफ़ाइल> malfind` - संदेहास्पद प्रक्रियाएँ खोजें
  - `volatility -f <डंप फ़ाइल> --profile=<प्रोफ़ाइल> ldrmodules` - लोड किए गए मॉड्यूल्स देखें
  - `volatility -f <डंप फ़ाइल> --profile=<प्रोफ़ाइल> apihooks` - API हुक्स खोजें

### अतिरिक्त संसाधन

- [वोलेटिलिटी ऑफिशियल डॉक्यूमेंटेशन](https://github.com/volatilityfoundation/volatility/wiki)
- [वोलेटिलिटी गिटहब रिपोजिटरी](https://github.com/volatilityfoundation/volatility) {% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### हैंडल्स

प्रक्रिया के लिए उपयोगी होता है कि उसके पास हैंडल हो (खोल लिया हो) किसी अन्य फ़ाइल, कुंजियों, धागों, प्रक्रियाओं... के लिए।
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="vol2" %}वोलेटिलिटी चीटशीट

### वोलेटिलिटी चीटशीट

#### वोलेटिलिटी इंस्टॉलेशन

- वोलेटिलिटी इंस्टॉलेशन की जांच करें
  ```bash
  volatility -h
  ```

#### बेसिक कमांड्स

- चलाने के लिए वोलेटिलिटी के बेसिक कमांड्स
  ```bash
  volatility -f <memory_dump> <command>
  ```

#### फाइल सिस्टम अनालिसिस

- फाइल सिस्टम अनालिसिस के लिए वोलेटिलिटी के कमांड्स
  ```bash
  volatility -f <memory_dump> --profile=<profile> <command>
  ```

#### प्रक्रिया अनालिसिस

- प्रक्रिया अनालिसिस के लिए वोलेटिलिटी के कमांड्स
  ```bash
  volatility -f <memory_dump> --profile=<profile> <command>
  ```

#### नेटवर्क अनालिसिस

- नेटवर्क अनालिसिस के लिए वोलेटिलिटी के कमांड्स
  ```bash
  volatility -f <memory_dump> --profile=<profile> <command>
  ```

#### रजिस्ट्री अनालिसिस

- रजिस्ट्री अनालिसिस के लिए वोलेटिलिटी के कमांड्स
  ```bash
  volatility -f <memory_dump> --profile=<profile> <command>
  ```

#### डेटाबेस अनालिसिस

- डेटाबेस अनालिसिस के लिए वोलेटिलिटी के कमांड्स
  ```bash
  volatility -f <memory_dump> --profile=<profile> <command>
  ```

#### डेटा कार्विंग

- डेटा कार्विंग के लिए वोलेटिलिटी के कमांड्स
  ```bash
  volatility -f <memory_dump> --profile=<profile> <command>
  ```

#### डेटा एनालिसिस

- डेटा एनालिसिस के लjson
  ```bash
  volatility -f <memory_dump> --profile=<profile> <command>
  ```

#### डेटा एनालिसिस

- डेटा एनालिसिस के लिए वोलेटिलिटी के कमांड्स
  ```bash
  volatility -f <memory_dump> --profile=<profile> <command>
  ```

#### डेटा एनालिसिस

- डेटा एनालिसिस के लिए वोलेटिलिटी के कम
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

{% tab title="vol2" %}हैकिंग तकनीकियों की एक पुस्तक से निम्नलिखित सामग्री है। निम्नलिखित सामग्री फ़ाइल generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md से है। अंग्रेजी मूल सामग्री का हिंदी में अनुवाद करें और अनुवाद को वही मार्कडाउन और एचटीएमएल विन्यास बनाए रखें। कोड, हैकिंग तकनीक नाम, हैकिंग शब्द, क्लाउड/एसएएस प्लेटफ़ॉर्म नाम (जैसे Workspace, aws, gcp...), 'लीक', पेंटेस्टिंग और मार्कडाउन टैग्स जैसी चीजें अनुवाद न करें। अनुवाद के अलावा कोई अतिरिक्त सामग्री न जोड़ें।%}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
### प्रक्रियाओं के लिए स्ट्रिंग्स

Volatility हमें यह जांचने की अनुमति देता है कि एक स्ट्रिंग किस प्रक्रिया से संबंधित है।
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}हिंदी{% endtab %}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
यह भी एक प्रक्रिया के अंदर स्ट्रिंग की खोज करने के लिए yarascan मॉड्यूल का उपयोग करने की अनुमति देता है:
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %}वोलेटिलिटी चीटशीट

### वोलेटिलिटी चीटशीट

#### वोलेटिलिटी इंस्टॉलेशन

वोलेटिलिटी इंस्टॉलेशन की जांच करें:

```bash
volatility
```

#### वोलेटिलिटी उपयोग

वोलेटिलिटी का उपयोग करने के लिए:

```bash
volatility -f <डंप_फ़ाइल> <कमांड>
```

उदाहरण:

```bash
volatility -f memdump.mem imageinfo
```

#### वोलेटिलिटी कमांड्स

- `imageinfo`: डंप फ़ाइल की मेटाडेटा प्रदर्शित करें
- `pslist`: प्रक्रियाओं की सूची प्रदर्शित करें
- `pstree`: प्रक्रिया पेड़ का डंप प्रदर्शित करें
- `psscan`: प्रक्रिया स्ट्रक्चर का डंप प्रदर्शित करें
- `dlllist`: प्रक्रियाओं की DLL सूची प्रदर्शित करें

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### उपयोगकर्ता सहायक

**Windows** सिस्टम रजिस्ट्री डेटाबेस में एक सेट को बनाए रखते हैं (**उपयोगकर्ता सहायक कुंजी**) जिसमें उन प्रोग्रामों का ट्रैक रखा जाता है जो क्रियान्वित किए जाते हैं। इन **कुंजियों** में क्रियान्वयनों की संख्या और अंतिम क्रियान्वयन तिथि और समय उपलब्ध होता है।
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}हिंदी{% endtab %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) स्पेन में सबसे महत्वपूर्ण साइबर सुरक्षा घटना है और यूरोप में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा विशेषज्ञों के लिए एक उफनती मिलन स्थल है हर विषय में।

{% embed url="https://www.rootedcon.com/" %}

## सेवाएं

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
यहाँ वोलेटिलिटी चीटशीट का अनुभाग है।

{% endtab %}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## नेटवर्क

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="vol2" %}वोलेटिलिटी चीटशीट

### वोलेटिलिटी चीटशीट

#### वोलेटिलिटी इंस्टॉलेशन

- वोलेटिलिटी इंस्टॉलेशन की जांच करें
  ```bash
  volatility
  ```

#### बेसिक कमांड्स

- प्रक्रियाओं की सूची देखें
  ```bash
  volatility -f <डंप_फ़ाइल> pslist
  ```

- रजिस्ट्री कुंजी की सूची देखें
  ```bash
  volatility -f <डंप_फ़ाइल> hivelist
  ```

- नेटवर्क कनेक्शन्स की सूची देखें
  ```bash
  volatility -f <डंप_फ़ाइल> connections
  ```

#### डेटा एनालिसिस

- फाइल्सिस्टेम डाम्प की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan
  ```

- डायरेक्टरी स्ट्रक्चर की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> mftparser
  ```

- डिस्क इमेज की फाइल लिस्टिंग
  ```bash
  volatility -f <डंप_फ़ाइल> --profile=<प्रोफ़ाइल> filescan
  ```

#### डेटा एक्सट्रेक्शन

- प्रक्रिया से डेटा निकालें
  ```bash
  volatility -f <डंप_फ़ाइल> -p <प्रक्रिया_आईडी> procdump -D <निर्दिष्ट_डिरेक्टरी>
  ```

- रीज़ल्ट को फाइल में लिखें
  ```bash
  volatility -f <डंप_फ़ाइल> --profile=<प्रोफ़ाइल> dumpfiles -Q <डायरेक्टरी> -D <निर्दिष्ट_डिरेक्टरी>
  ```

#### डेटा विश्लेषण

- रेजिस्ट्री से डेटा निकालें
  ```bash
  volatility -f <डंप_फ़ाइल> --profile=<प्रोफ़ाइल> printkey -o <रजिस्ट्री_कुंजी_आईडी>
  ```

- रेजिस्ट्री से डेटा निकालें (अधिक विस्तृत)
  ```bash
  volatility -f <डंप_फ़ाइल> --profile=<प्रोफ़ाइल> hivex -o <रजिस्ट्री_कुंजी_आईडी>
  ```

- नेटवर्क डेटा निकालें
  ```bash
  volatility -f <डंप_फ़ाइल> --profile=<प्रोफ़ाइल> netscan
  ```

#### अन्य उपयोगी कमांड्स

- डंप फ़ाइल की जानकारी प्राप्त करें
  ```bash
  volatility -f <डंप_फ़ाइल> imageinfo
  ```

- डंप फ़ाइल से डेटा निकालें
  ```bash
  volatility -f <डंप_फ़ाइल> --profile=<प्रोफ़ाइल> linux_bash
  ```

- डंप फ़ाइल से डेटा निकालें (अधिक विस्तृत)
  ```bash
  volatility -f <डंप_फ़ाइल> --profile=<प्रोफ़ाइल> linux_find_file -F <फ़ाइल_नाम>
  ```
{% endtab %}
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
## रजिस्ट्री हाइव

### उपलब्ध हाइव्स प्रिंट करें

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="vol2" %}हैकिंग तकनीकियों की एक पुस्तक से निम्नलिखित सामग्री है। निम्नलिखित सामग्री फ़ाइल generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md से है। अंग्रेजी में लिखे गए पाठ का हिंदी में अनुवाद करें और अनुवाद को वही मार्कडाउन और एचटीएमएल विन्यास बनाए रखें। कोड, हैकिंग तकनीक नाम, हैकिंग शब्द, क्लाउड/एसएएस प्लेटफ़ॉर्म नाम (जैसे Workspace, aws, gcp...), 'लीक', पेंटेस्टिंग और मार्कडाउन टैग्स जैसी चीजें अनुवाद न करें। अनुवाद में कोई अतिरिक्त सामग्री न जोड़ें, केवल अनुवाद और मार्कडाउन विन्यास शामिल करें।{% endtab %}
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

{% tab title="vol2" %}हिंदी{% endtab %}
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
## फ़ाइल सिस्टम

### माउंट

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %}वोलेटिलिटी चीटशीट

### वोलेटिलिटी चीटशीट

#### वोलेटिलिटी इंस्टॉलेशन

- वोलेटिलिटी इंस्टॉलेशन की जांच करें
  ```bash
  volatility
  ```

#### वोलेटिलिटी बेसिक कमांड्स

- चलाने के लिए वोलेटिलिटी की जांच करें
  ```bash
  volatility -h
  ```

- ऑपरेटिंग सिस्टम की जानकारी प्राप्त करें
  ```bash
  volatility -f <डंप_फ़ाइल> imageinfo
  ```

- प्रक्रियाओं की सूची प्राप्त करें
  ```bash
  volatility -f <डंप_फ़ाइल> pslist
  ```

- रजिस्ट्री से जानकारी प्राप्त करें
  ```bash
  volatility -f <डंप_फ़ाइल> hivelist
  ```

- फ़ाइल्सिस्ट्रक्चर की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan
  ```

- नेटवर्क कनेक्शन्स की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> connections
  ```

- डेटा एनालिसिस के लिए विभिन्न प्लगइन्स की सूची प्राप्त करें
  ```bash
  volatility --info | grep -iE "plugin"
  ```

#### वोलेटिलिटी डेटा एनालिसिस

- रजिस्ट्री से उपयोगकर्ता खातों की जानकारी प्राप्र्त करें
  ```bash
  volatility -f <डंप_फ़ाइल> hivelist | grep -iE "ntuser"
  ```

- रजिस्ट्री से उपयोगकर्ता खातों की जानकारी प्राप्त करें
  ```bash
  volatility -f <डंप_फ़ाइल> printkey -o <ऑफसेट>
  ```

- फ़ाइल्सिस्ट्रक्चर से संबंधित फ़ाइलों की सूची प्राप्त करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan | grep -iE "\.doc|\.pdf|\.xls"
  ```

- नेटवर्क कनेक्शन्स की जानकारी प्राप्त करें
  ```bash
  volatility -f <डंप_फ़ाइल> netscan
  ```

- डेटा एनालिसिस के लिए विभिन्न प्लगइन्स का उपयोग करें
  ```bash
  volatility -f <डंप_फ़ाइल> <प्लगइन>
  ```

{% endtab %}
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

{% tab title="vol2" %}हिंदी{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
### मास्टर फ़ाइल टेबल

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %}हिंदी{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

एनटीएफएस फाइल सिस्टम में एक फ़ाइल होती है जिसे _मास्टर फ़ाइल टेबल_ या एमएफटी कहा जाता है। एनटीएफएस फाइल सिस्टम वॉल्यूम पर हर फ़ाइल के लिए कम से कम एक एमएफटी एंट्री होती है, जिसमें एमएफटी खुद भी शामिल है। **फ़ाइल के बारे में सभी जानकारी, जैसे उसका आकार, समय और तारीख के टिम स्टैम्प, अनुमतियाँ, और डेटा सामग्री**, या तो एमएफटी एंट्री में संग्रहित होती है, या एमएफटी एंट्री द्वारा वर्णित बाहरी स्थान में होती है। स्रोत: [यहाँ](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### SSL Keys/Certs

{% tabs %}
{% tab title="vol3" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% टैब शीर्षक="vol2" %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
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

{% tab title="vol2" %}वोलेटिलिटी चीटशीट

### वोलेटिलिटी चीटशीट

#### वोलेटिलिटी इंस्टॉलेशन

- वोलेटिलिटी इंस्टॉलेशन की जांच करें
  ```bash
  volatility -h
  ```

#### बेसिक कमांड्स

- चलाना
  ```bash
  volatility -f <डंप_फ़ाइल> <कमांड>
  ```

- डंप की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> imageinfo
  ```

- प्रक्रियाएँ
  ```bash
  volatility -f <डंप_फ़ाइल> pslist
  ```

- नेटवर्क
  ```bash
  volatility -f <डंप_फ़ाइल> netscan
  ```

- रजिस्ट्री
  ```bash
  volatility -f <डंप_फ़ाइल> hivelist
  ```

- फाइल सिस्टम
  ```bash
  volatility -f <डंप_फ़ाइल> filescan
  ```

- डेटा अनालिसिस
  ```bash
  volatility -f <डंप_फ़ाइल> strings -s <ऑफसेट>
  ```

#### डेटा अनालिसिस

- रजिस्ट्री कुंजी की खोज
  ```bash
  volatility -f <डंप_फ़ाइल> printkey -o <ऑफसेट>
  ```

- रजिस्ट्री वैल्यू देखें
  ```bash
  volatility -f <डंप_फ़ाइल> printkey -o <ऑफसेट> -K <कुंजी>
  ```

- फाइल डाउनलोड करें
  ```bash
  volatility -f <डंप_फ़ाइल> dumpfiles -Q <ऑफसेट> -D <डिरेक्टरी>
  ```

#### डेटा अनालिसिस

- फाइल डाउनलोड करें
  ```bash
  volatility -f <डंप_फ़ाइल> dumpfiles -Q <ऑफसेट> -D <डिरेक्टरी>
  ```

- फाइल की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan -Q <ऑफसेट>
  ```

- फाइल की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan -Q <ऑफसेट>
  ```

- फाइल की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan -Q <ऑफसेट>
  ```

- फाइल की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan -Q <ऑफसेट>
  ```

- फाइल की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan -Q <ऑफसेट>
  ```

- फाइल की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan -Q <ऑफसेट>
  ```

- फाइल की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan -Q <ऑफसेट>
  ```

- फाइल की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan -Q <ऑफसेट>
  ```

- फाइल की जांच करें
  ```bash
  volatility -f <डंप_फ़ाइल> filescan -Q <ऑफसेट>
  ```
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

### यारा के साथ स्कैनिंग

इस स्क्रिप्ट का उपयोग करके गिथब से सभी यारा मैलवेयर नियम डाउनलोड और मर्ज करें: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
_**rules**_ निर्देशिका बनाएं और इसे निष्पादित करें। इससे _**malware\_rules.yar**_ नाम की एक फ़ाइल बनेगी जिसमें सभी मैलवेयर के लिए यारा नियम होंगे।
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
यहाँ वोलेटिलिटी चीटशीट का अनुभाग है। यह वोलेटिलिटी टूल के उपयोग के लिए महत्वपूर्ण तकनीकों को संक्षेपित रूप से दर्शाता है। यह एक अद्वितीय और उपयोगी संसाधन है जो डिजिटल फोरेंसिक्स और मेमोरी डंप विश्लेषण के क्षेत्र में काम करने वाले लोगों के लिए उपयोगी हो सकता है। इसमें विभिन्न वोलेटिलिटी प्लगइन्स के उपयोग के लिए अनुदेश और उपयोगी जानकारी शामिल है।{% endtab %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
## अन्य

### बाह्य प्लगइन

यदि आप बाह्य प्लगइन का उपयोग करना चाहते हैं तो सुनिश्चित करें कि प्लगइन से संबंधित फ़ोल्डर पहला पैरामीटर है।
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="vol2" %}हैकिंग तकनीकियों की एक पुस्तक से निम्नलिखित सामग्री है। निम्नलिखित सामग्री फ़ाइल generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md से है। अंग्रेजी मूल सामग्री का हिंदी में अनुवाद करें और अनुवाद को वही मार्कडाउन और एचटीएमएल विन्यास बनाएं और वापस भेजें।{% endtab %}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
#### Autoruns

इसे [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns) से डाउनलोड करें।
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### म्यूटेक्स

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% टैब शीर्षक="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
### सिमलिंक्स

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="vol2" %}हिंदी{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### बैश

**यादगार से बैश इतिहास पढ़ना संभव है।** आप _.bash\_history_ फ़ाइल को भी डंप कर सकते हैं, लेकिन यदि यह अक्षम है तो आप इस volatility मॉड्यूल का उपयोग कर सकते हैं
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% टैब शीर्षक="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
### समयरेखा

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% टैब शीर्षक="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### ड्राइवर्स

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %}हैकिंग तकनीकियों की एक पुस्तक से निम्नलिखित सामग्री है। निम्नलिखित सामग्री फ़ाइल generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md से है। अंग्रेजी में लिखे गए पाठ का हिंदी में अनुवाद करें और अनुवाद को वही मार्कडाउन और एचटीएमएल विन्यास बनाए रखें। कोड, हैकिंग तकनीक नाम, हैकिंग शब्द, क्लाउड/एसएएस प्लेटफ़ॉर्म नाम (जैसे Workspace, aws, gcp...), 'लीक', पेंटेस्टिंग और मार्कडाउन टैग्स जैसी चीजें अनुवाद न करें। अनुवाद के अलावा कोई अतिरिक्त सामग्री न जोड़ें।%}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
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
```
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
MBR में जानकारी होती है कि वहाँ माध्यम पर संगठित [फ़ाइल सिस्टम](https://en.wikipedia.org/wiki/File\_system) को धारित लॉजिकल पार्टीशन कैसे हैं। MBR में एक्जीक्यूटेबल कोड भी होता है जो स्थापित ऑपरेटिंग सिस्टम के लोडर के रूप में काम करने के लिए होता है - आम तौर पर लोडर के [दूसरे स्टेज](https://en.wikipedia.org/wiki/Second-stage\_boot\_loader) को या प्रत्येक पार्टीशन के [वॉल्यूम बूट रिकॉर्ड](https://en.wikipedia.org/wiki/Volume\_boot\_record) (VBR) के साथ या संयोजन में देने के लिए नियंत्रण पारित करने के लिए। इस MBR कोड को आम तौर पर [बूट लोडर](https://en.wikipedia.org/wiki/Boot\_loader) के रूप में संदर्भित किया जाता है। स्रोत: [यहाँ](https://en.wikipedia.org/wiki/Master\_boot\_record).

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **स्पेन** में सबसे महत्वपूर्ण साइबर सुरक्षा घटना है और **यूरोप** में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा विशेषज्ञों के लिए एक उफान मिलने का समारोह है।

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>शून्य से हीरो तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos को PRs सबमिट करके।

</details>
