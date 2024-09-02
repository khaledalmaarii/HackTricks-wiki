# macOS Dirty NIB

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

**For further detail about the technique check the original post from:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) and the following post by [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Here is a summary:

### What are Nib files

Nib (NeXT इंटरफेस बिल्डर के लिए संक्षिप्त) फ़ाइलें, एप्पल के विकास पारिस्थितिकी तंत्र का हिस्सा, अनुप्रयोगों में **UI तत्वों** और उनके इंटरैक्शन को परिभाषित करने के लिए होती हैं। इनमें विंडो और बटन जैसे अनुक्रमित वस्तुएं शामिल होती हैं, और इन्हें रनटाइम पर लोड किया जाता है। उनके निरंतर उपयोग के बावजूद, एप्पल अब अधिक व्यापक UI प्रवाह दृश्यता के लिए स्टोरीबोर्ड का समर्थन करता है।

मुख्य Nib फ़ाइल को अनुप्रयोग के `Info.plist` फ़ाइल के अंदर **`NSMainNibFile`** मान में संदर्भित किया गया है और इसे अनुप्रयोग के `main` फ़ंक्शन में निष्पादित **`NSApplicationMain`** फ़ंक्शन द्वारा लोड किया जाता है।

### Dirty Nib Injection Process

#### Creating and Setting Up a NIB File

1. **Initial Setup**:
* XCode का उपयोग करके एक नया NIB फ़ाइल बनाएं।
* इंटरफ़ेस में एक ऑब्जेक्ट जोड़ें, इसकी कक्षा को `NSAppleScript` सेट करें।
* उपयोगकर्ता परिभाषित रनटाइम विशेषताओं के माध्यम से प्रारंभिक `source` प्रॉपर्टी को कॉन्फ़िगर करें।
2. **Code Execution Gadget**:
* सेटअप मांग पर AppleScript चलाने की सुविधा प्रदान करता है।
* `Apple Script` ऑब्जेक्ट को सक्रिय करने के लिए एक बटन एकीकृत करें, विशेष रूप से `executeAndReturnError:` चयनकर्ता को ट्रिगर करना।
3. **Testing**:
* परीक्षण उद्देश्यों के लिए एक सरल Apple Script:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```
* XCode डिबगर में चलाकर और बटन पर क्लिक करके परीक्षण करें।

#### Targeting an Application (Example: Pages)

1. **Preparation**:
* लक्षित ऐप (जैसे, Pages) को एक अलग निर्देशिका (जैसे, `/tmp/`) में कॉपी करें।
* गेटकीपर समस्याओं से बचने के लिए ऐप को प्रारंभ करें और इसे कैश करें।
2. **Overwriting NIB File**:
* एक मौजूदा NIB फ़ाइल (जैसे, About Panel NIB) को तैयार किए गए DirtyNIB फ़ाइल से बदलें।
3. **Execution**:
* ऐप के साथ इंटरैक्ट करके निष्पादन को ट्रिगर करें (जैसे, `About` मेनू आइटम का चयन करना)।

#### Proof of Concept: Accessing User Data

* उपयोगकर्ता की सहमति के बिना फ़ोटो जैसे उपयोगकर्ता डेटा तक पहुँचने और निकालने के लिए AppleScript को संशोधित करें।

### Code Sample: Malicious .xib File

* मनमाने कोड को निष्पादित करने का प्रदर्शन करने वाले [**दुष्ट .xib फ़ाइल के एक नमूने**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) तक पहुँचें और समीक्षा करें।

### Other Example

पोस्ट [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) में आप एक गंदे nib बनाने के लिए ट्यूटोरियल पा सकते हैं।&#x20;

### Addressing Launch Constraints

* लॉन्च प्रतिबंध ऐप के निष्पादन को अप्रत्याशित स्थानों (जैसे, `/tmp`) से रोकते हैं।
* यह पहचानना संभव है कि कौन से ऐप लॉन्च प्रतिबंधों से सुरक्षित नहीं हैं और उन्हें NIB फ़ाइल इंजेक्शन के लिए लक्षित करें।

### Additional macOS Protections

macOS सोनोमा से आगे, ऐप बंडलों के अंदर संशोधन प्रतिबंधित हैं। हालाँकि, पहले के तरीकों में शामिल थे:

1. ऐप को एक अलग स्थान (जैसे, `/tmp/`) में कॉपी करना।
2. प्रारंभिक सुरक्षा को बायपास करने के लिए ऐप बंडल के भीतर निर्देशिकाओं का नाम बदलना।
3. गेटकीपर के साथ पंजीकरण करने के लिए ऐप को चलाने के बाद, ऐप बंडल में संशोधन करना (जैसे, MainMenu.nib को Dirty.nib से बदलना)।
4. निर्देशिकाओं का नाम वापस बदलना और इंजेक्ट की गई NIB फ़ाइल को निष्पादित करने के लिए ऐप को फिर से चलाना।

**Note**: हाल के macOS अपडेट ने गेटकीपर कैशिंग के बाद ऐप बंडलों के भीतर फ़ाइल संशोधनों को रोककर इस शोषण को कम कर दिया है, जिससे यह शोषण अप्रभावी हो गया है।

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
