# macOS Kernel Extensions

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

## Basic Information

कर्नेल एक्सटेंशन (Kexts) **पैकेज** हैं जिनका **`.kext`** एक्सटेंशन होता है जो **macOS कर्नेल स्पेस में सीधे लोड** किए जाते हैं, मुख्य ऑपरेटिंग सिस्टम को अतिरिक्त कार्यक्षमता प्रदान करते हैं।

### Requirements

स्पष्ट रूप से, यह इतना शक्तिशाली है कि **कर्नेल एक्सटेंशन लोड करना जटिल है**। ये **आवश्यकताएँ** हैं जो एक कर्नेल एक्सटेंशन को लोड करने के लिए पूरी करनी चाहिए:

* जब **रिकवरी मोड में प्रवेश करते हैं**, कर्नेल **एक्सटेंशन को लोड करने की अनुमति होनी चाहिए**:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* कर्नेल एक्सटेंशन को **कर्नेल कोड साइनिंग सर्टिफिकेट के साथ साइन** किया जाना चाहिए, जिसे केवल **Apple द्वारा दिया जा सकता है**। जो कंपनी की समीक्षा करेगा और यह क्यों आवश्यक है।
* कर्नेल एक्सटेंशन को भी **नोटराइज** किया जाना चाहिए, Apple इसे मैलवेयर के लिए जांच सकेगा।
* फिर, **रूट** उपयोगकर्ता ही **कर्नेल एक्सटेंशन को लोड कर सकता है** और पैकेज के अंदर की फ़ाइलें **रूट की होनी चाहिए**।
* अपलोड प्रक्रिया के दौरान, पैकेज को **संरक्षित नॉन-रूट स्थान** में तैयार किया जाना चाहिए: `/Library/StagedExtensions` (इसके लिए `com.apple.rootless.storage.KernelExtensionManagement` ग्रांट की आवश्यकता होती है)।
* अंत में, जब इसे लोड करने का प्रयास किया जाता है, तो उपयोगकर्ता [**एक पुष्टि अनुरोध प्राप्त करेगा**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) और, यदि स्वीकार किया गया, तो कंप्यूटर को इसे लोड करने के लिए **रीस्टार्ट** करना होगा।

### Loading process

कैटालिना में यह इस प्रकार था: यह ध्यान देने योग्य है कि **सत्यापन** प्रक्रिया **यूजरलैंड** में होती है। हालाँकि, केवल वे एप्लिकेशन जिनके पास **`com.apple.private.security.kext-management`** ग्रांट है, वे **कर्नेल से एक्सटेंशन लोड करने का अनुरोध कर सकते हैं**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI **एक्सटेंशन लोड करने के लिए सत्यापन** प्रक्रिया शुरू करता है
* यह **`kextd`** से **Mach सेवा** का उपयोग करके बात करेगा।
2. **`kextd`** कई चीजों की जांच करेगा, जैसे **हस्ताक्षर**
* यह **`syspolicyd`** से बात करेगा ताकि यह **जांच सके** कि क्या एक्सटेंशन को **लोड किया जा सकता है**।
3. **`syspolicyd`** **उपयोगकर्ता** से **प्रॉम्प्ट** करेगा यदि एक्सटेंशन पहले लोड नहीं किया गया है।
* **`syspolicyd`** **`kextd`** को परिणाम रिपोर्ट करेगा
4. अंततः **`kextd`** कर्नेल को एक्सटेंशन को **लोड करने के लिए बता सकेगा**

यदि **`kextd`** उपलब्ध नहीं है, तो **`kextutil`** वही जांच कर सकता है।

## Referencias

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
