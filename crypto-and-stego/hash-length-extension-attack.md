# Hash Length Extension Attack

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


## Summary of the attack

Fikiria seva ambayo inasaini baadhi ya data kwa kuunganisha siri na baadhi ya data ya wazi inayojulikana na kisha kuhashi data hiyo. Ikiwa unajua:

* **Urefu wa siri** (hii inaweza pia kufanywa kwa nguvu kutoka kwa anuwai ya urefu iliyotolewa)
* **Data ya wazi**
* **Algorithimu (na inahatarishwa kwa shambulio hili)**
* **Padding inajulikana**
* Kawaida padding ya chaguo-msingi hutumiwa, hivyo ikiwa mahitaji mengine 3 yanakidhi, hii pia inakidhi
* Padding hubadilika kulingana na urefu wa siri + data, ndivyo maana urefu wa siri unahitajika

Basi, inawezekana kwa **mshambuliaji** ku **ongeza** **data** na **kuunda** **sahihi** halali kwa **data ya awali + data iliyoongezwa**.

### How?

Kimsingi algorithimu zinazohatarishwa zinaweza kuunda hash kwa kwanza **kuhashi block ya data**, na kisha, **kutoka** kwa **hash** iliyoundwa **awali** (hali), wana **ongeza block inayofuata ya data** na **kuhashi**.

Basi, fikiria kwamba siri ni "siri" na data ni "data", MD5 ya "siri data" ni 6036708eba0d11f6ef52ad44e8b74d5b.\
Ikiwa mshambuliaji anataka kuongeza mfuatano "ongeza" anaweza:

* Kuunda MD5 ya "A" 64
* Kubadilisha hali ya hash iliyowekwa awali kuwa 6036708eba0d11f6ef52ad44e8b74d5b
* Kuongeza mfuatano "ongeza"
* Kumaliza hash na hash inayotokana itakuwa **halali kwa "siri" + "data" + "padding" + "ongeza"**

### **Tool**

{% embed url="https://github.com/iagox86/hash_extender" %}

### References

Unaweza kupata shambulio hili limeelezwa vizuri katika [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)



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
