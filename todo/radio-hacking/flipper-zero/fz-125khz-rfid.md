# FZ - 125kHz RFID

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Intro

Kwa maelezo zaidi kuhusu jinsi vitambulisho vya 125kHz vinavyofanya kazi angalia:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Actions

Kwa maelezo zaidi kuhusu aina hizi za vitambulisho [**soma utangulizi huu**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

Inajaribu **kusoma** taarifa za kadi. Kisha inaweza **kuiga** hizo.

{% hint style="warning" %}
Kumbuka kwamba baadhi ya intercoms zinajaribu kujilinda kutokana na nakala za funguo kwa kutuma amri ya kuandika kabla ya kusoma. Ikiwa kuandika kunafanikiwa, vitambulisho hivyo vinachukuliwa kuwa vya uwongo. Wakati Flipper inapoiga RFID, hakuna njia kwa msomaji kutofautisha kati yake na ile ya asili, hivyo matatizo kama hayo hayatokea.
{% endhint %}

### Add Manually

Unaweza kuunda **kadi za uwongo katika Flipper Zero ukionyesha data** unazozingatia kwa mikono kisha uige.

#### IDs on cards

Wakati mwingine, unapopata kadi utapata ID (au sehemu) yake imeandikwa kwenye kadi inayoonekana.

* **EM Marin**

Kwa mfano katika kadi hii ya EM-Marin kwenye kadi halisi inawezekana **kusoma byte 3 za mwisho kati ya 5 wazi**.\
Byte 2 nyingine zinaweza kujaribiwa kwa nguvu ikiwa huwezi kuzisoma kutoka kwenye kadi.

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* **HID**

Vivyo hivyo inatokea katika kadi hii ya HID ambapo byte 2 kati ya 3 zinaweza kupatikana zimeandikwa kwenye kadi

<figure><img src="../../../.gitbook/assets/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Baada ya **kunakili** kadi au **kuingiza** ID **kwa mikono** inawezekana **kuiga** hiyo na Flipper Zero au **kuandika** kwenye kadi halisi.

## References

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
