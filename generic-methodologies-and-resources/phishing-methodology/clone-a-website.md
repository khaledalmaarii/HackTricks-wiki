<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड** करने का उपयोग करना है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT संग्रह**](https://opensea.io/collection/the-peass-family)

- प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **अपने हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में PR जमा करके।**

</details>


फिशिंग मूल्यांकन के लिए कभी-कभी पूरी तरह से **वेबसाइट क्लोन** करना उपयोगी हो सकता है।

ध्यान दें कि आप इसके साथ कुछ पेलोड भी जोड़ सकते हैं, जैसे एक BeEF हुक ताकि उपयोगकर्ता के टैब को "नियंत्रित" किया जा सके।

इस उद्देश्य के लिए आप विभिन्न उपकरणों का उपयोग कर सकते हैं:

## wget
```text
wget -mk -nH
```
## गोक्लोन

गोक्लोन एक खोज और वेबसाइट की नकल बनाने के लिए एक उपयोगी उपकरण है। यह आपको किसी भी वेबसाइट की सामग्री, लेआउट और डिजाइन की नकल बनाने में मदद करता है। इसका उपयोग फिशिंग हमलों के लिए किया जा सकता है, जहां आप वास्तविक वेबसाइट की नकल बनाकर उपयोगकर्ताओं को धोखा देने का प्रयास कर सकते हैं।

गोक्लोन का उपयोग करने के लिए, आपको वेबसाइट के स्रोत को डाउनलोड करना होगा और उसे अपने स्थानीय सर्वर पर होस्ट करना होगा। इसके बाद, आपको वेबसाइट के लिंक, फॉर्म और अन्य तत्वों को अपने नकली वेबसाइट के साथ अद्यतित करना होगा। इस तरीके से, जब उपयोगकर्ता आपकी नकली वेबसाइट पर जाता है, उन्हें लगता है कि वे वास्तविक वेबसाइट पर हैं और वे अपनी गोपनीयता और प्रमाणीकरण जानकारी को देते हैं।

गोक्लोन एक शक्तिशाली और अवैध उपकरण हो सकता है, इसलिए इसका उपयोग केवल नैतिक हैकिंग और सुरक्षा परीक्षण के लिए ही करें। इसका उपयोग किसी अन्य गैरकानूनी गतिविधा के लिए नहीं किया जाना चाहिए।
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## सामाजिक इंजीनियरिंग टूलकिट

The Social Engineering Toolkit (SET) is a powerful framework that allows hackers to perform various social engineering attacks. It is a collection of tools and scripts that automate the process of phishing, credential harvesting, and other social engineering techniques.

SET provides a user-friendly interface and supports multiple attack vectors, making it an effective tool for both beginners and experienced hackers. It includes features like website cloning, email spoofing, and creating malicious payloads.

With SET, hackers can clone websites to create convincing phishing pages that mimic legitimate websites. This allows them to trick unsuspecting users into entering their login credentials or other sensitive information.

To clone a website using SET, follow these steps:

1. Start SET by running the command `setoolkit` in the terminal.
2. Select the "Website Attack Vectors" option from the main menu.
3. Choose the "Credential Harvester Attack Method" option.
4. Select the "Site Cloner" option.
5. Enter the URL of the website you want to clone.
6. Choose a template for the cloned website.
7. Specify the IP address and port for the cloned website.
8. Start the cloning process.

Once the website is cloned, SET will provide you with a link that you can share with your target. When the target visits the cloned website and enters their credentials, SET will capture the information and store it for further analysis.

It is important to note that using SET for malicious purposes is illegal and unethical. This toolkit should only be used for educational and authorized penetration testing purposes.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **हैकट्रिक्स में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)

- प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें।**

</details>
