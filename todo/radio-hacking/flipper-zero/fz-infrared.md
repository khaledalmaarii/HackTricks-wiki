# FZ - इन्फ्रारेड

<details>

<summary><strong>जीरो से हीरो तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित देखना चाहते हैं**? या क्या आप **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) की जाँच करें!
* [**द पीएस फैमिली**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **ट्विटर** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **अपने हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स रेपो** (https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud रेपो**](https://github.com/carlospolop/hacktricks-cloud) **को PR जमा करके**।

</details>

## परिचय <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

इन्फ्रारेड कैसे काम करता है के बारे में अधिक जानकारी के लिए देखें:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## फ्लिपर जीरो में आईआर सिग्नल रिसीवर <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

फ्लिपर एक डिजिटल आईआर सिग्नल रिसीवर TSOP का उपयोग करता है, जो **आईआर रिमोट से सिग्नल अंतरण करने की अनुमति देता है**। कुछ **स्मार्टफोन** जैसे Xiaomi, जिनमें भी एक आईआर पोर्ट होता है, लेकिन ध्यान रखें कि **अधिकांश उनमें केवल सिग्नल भेज सकते हैं** और **प्राप्त नहीं कर सकते**।

फ्लिपर इन्फ्रारेड **रिसीवर काफी संवेदनशील है**। आप तब भी **सिग्नल को पकड़ सकते हैं** जब आप दूरी में होते हुए रिमोट और टीवी के बीच कहीं रहते हैं। फ्लिपर के आईआर पोर्ट की ओर सीधे रिमोट करना अनावश्यक है। यह उस समय उपयोगी होता है जब कोई टीवी के पास खड़ा होकर चैनल बदल रहा हो, और आप और फ्लिपर दोनों दूरी पर हैं।

इन्फ्रारेड का **डिकोडिंग** सिग्नल **सॉफ़्टवेयर** द्वारा होता है, इसलिए फ्लिपर जीरो संभावित रूप से किसी भी आईआर रिमोट कोड का **प्राप्ति और प्रेषण समर्थन** करता है। **अज्ञात** प्रोटोकॉल के मामले में जो पहचान नहीं किया जा सकता था - यह **रॉ सिग्नल को बिल्कुल वैसे ही रिकॉर्ड और प्लेबैक** करता है जैसे कि प्राप्त हुआ।
## Actions

### Universal Remotes

Flipper Zero can be used as a **universal remote to control any TV, air conditioner, or media center**. In this mode, Flipper **bruteforces** all **known codes** of all supported manufacturers **according to the dictionary from the SD card**. You don't need to choose a particular remote to turn off a restaurant TV.

It is enough to press the power button in the Universal Remote mode, and Flipper will **sequentially send "Power Off"** commands of all the TVs it knows: Sony, Samsung, Panasonic... and so on. When the TV receives its signal, it will react and turn off.

Such brute-force takes time. The larger the dictionary, the longer it will take to finish. It is impossible to find out which signal exactly the TV recognized since there is no feedback from the TV.

### Learn New Remote

It's possible to **capture an infrared signal** with Flipper Zero. If it **finds the signal in the database** Flipper will automatically **know which device this is** and will let you interact with it.\
If it doesn't, Flipper can **store** the **signal** and will allow you to **replay it**.

## References

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
