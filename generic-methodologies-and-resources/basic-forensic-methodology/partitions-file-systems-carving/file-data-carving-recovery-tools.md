# File/Data Carving & Recovery Tools

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

## Carving & Recovery tools

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

फोरेंसिक्स में छवियों से फ़ाइलें निकालने के लिए सबसे सामान्य उपकरण [**Autopsy**](https://www.autopsy.com/download/) है। इसे डाउनलोड करें, इंस्टॉल करें और "छिपी" फ़ाइलें खोजने के लिए इसे फ़ाइल को इनजेस्ट करने दें। ध्यान दें कि Autopsy डिस्क छवियों और अन्य प्रकार की छवियों का समर्थन करने के लिए बनाया गया है, लेकिन साधारण फ़ाइलों के लिए नहीं।

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** एक उपकरण है जो बाइनरी फ़ाइलों का विश्लेषण करने के लिए अंतर्निहित सामग्री खोजने के लिए है। इसे `apt` के माध्यम से इंस्टॉल किया जा सकता है और इसका स्रोत [GitHub](https://github.com/ReFirmLabs/binwalk) पर है।

**Useful commands**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

छिपी हुई फ़ाइलों को खोजने के लिए एक और सामान्य उपकरण **foremost** है। आप foremost की कॉन्फ़िगरेशन फ़ाइल `/etc/foremost.conf` में पा सकते हैं। यदि आप केवल कुछ विशिष्ट फ़ाइलों के लिए खोज करना चाहते हैं, तो उन्हें अनकमेंट करें। यदि आप कुछ भी अनकमेंट नहीं करते हैं, तो foremost अपनी डिफ़ॉल्ट कॉन्फ़िगर की गई फ़ाइल प्रकारों के लिए खोज करेगा।
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** एक और उपकरण है जिसका उपयोग **फाइल में एम्बेडेड फाइलों** को खोजने और निकालने के लिए किया जा सकता है। इस मामले में, आपको कॉन्फ़िगरेशन फ़ाइल (_/etc/scalpel/scalpel.conf_) से उन फ़ाइल प्रकारों को अनकमेंट करना होगा जिन्हें आप निकालना चाहते हैं।
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

यह उपकरण काली के अंदर आता है लेकिन आप इसे यहाँ पा सकते हैं: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

यह उपकरण एक इमेज को स्कैन कर सकता है और इसके अंदर **pcaps** को **निकालेगा**, **नेटवर्क जानकारी (URLs, domains, IPs, MACs, mails)** और अधिक **फाइलें**। आपको केवल यह करना है:
```
bulk_extractor memory.img -o out_folder
```
Navigate through **सभी जानकारी** that the tool has gathered (passwords?), **विश्लेषण करें** the **पैकेट** (read[ **Pcaps analysis**](../pcap-inspection/)), search for **अजीब डोमेन** (domains related to **malware** or **गैर-मौजूद**).

### PhotoRec

You can find it in [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

It comes with GUI and CLI versions. You can select the **फाइल-प्रकार** you want PhotoRec to search for.

![](<../../../.gitbook/assets/image (242).png>)

### binvis

Check the [code](https://code.google.com/archive/p/binvis/) and the [web page tool](https://binvis.io/#/).

#### Features of BinVis

* Visual and active **संरचना दर्शक**
* Multiple plots for different focus points
* Focusing on portions of a sample
* **स्ट्रिंग्स और संसाधनों** को देखना, in PE or ELF executables e. g.
* Getting **पैटर्न** for cryptanalysis on files
* **स्पॉटिंग** packer or encoder algorithms
* **पहचानें** Steganography by patterns
* **दृश्य** binary-diffing

BinVis is a great **शुरुआत बिंदु to get familiar with an unknown target** in a black-boxing scenario.

## Specific Data Carving Tools

### FindAES

Searches for AES keys by searching for their key schedules. Able to find 128. 192, and 256 bit keys, such as those used by TrueCrypt and BitLocker.

Download [यहाँ](https://sourceforge.net/projects/findaes/).

## Complementary tools

You can use [**viu** ](https://github.com/atanunq/viu)to see images from the terminal.\
You can use the linux command line tool **pdftotext** to transform a pdf into text and read it.

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
