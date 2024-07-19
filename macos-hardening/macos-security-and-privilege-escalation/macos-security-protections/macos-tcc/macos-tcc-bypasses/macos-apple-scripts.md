# macOS Apple Scripts

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

## Apple Scripts

यह एक स्क्रिप्टिंग भाषा है जो कार्य स्वचालन के लिए **दूरस्थ प्रक्रियाओं के साथ बातचीत** करने के लिए उपयोग की जाती है। यह **अन्य प्रक्रियाओं से कुछ क्रियाएँ करने के लिए पूछना** काफी आसान बनाता है। **Malware** इन सुविधाओं का दुरुपयोग कर सकता है ताकि अन्य प्रक्रियाओं द्वारा निर्यातित कार्यों का दुरुपयोग किया जा सके।\
उदाहरण के लिए, एक malware **ब्राउज़र में खोले गए पृष्ठों में मनमाना JS कोड इंजेक्ट कर सकता है**। या **कुछ अनुमति अनुरोधों पर स्वचालित क्लिक** कर सकता है;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
यहाँ कुछ उदाहरण हैं: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScripts का उपयोग करके मैलवेयर के बारे में अधिक जानकारी [**यहाँ**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) प्राप्त करें।

Apple scripts को आसानी से "**संकलित**" किया जा सकता है। इन संस्करणों को आसानी से "**डीकंपाइल**" किया जा सकता है `osadecompile` के साथ।

हालांकि, ये स्क्रिप्ट को **"केवल पढ़ने के लिए" निर्यात** भी किया जा सकता है ( "निर्यात..." विकल्प के माध्यम से):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
और इस मामले में सामग्री को `osadecompile` के साथ भी डिकंपाइल नहीं किया जा सकता।

हालांकि, कुछ उपकरण हैं जिनका उपयोग इस प्रकार के निष्पादन योग्य को समझने के लिए किया जा सकता है, [**अधिक जानकारी के लिए इस शोध को पढ़ें**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/))। उपकरण [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) और [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) स्क्रिप्ट के काम करने के तरीके को समझने के लिए बहुत उपयोगी होंगे।

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
