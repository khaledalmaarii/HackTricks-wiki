# FZ - 125kHz RFID

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Intro

Vir meer inligting oor hoe 125kHz etikette werk, kyk:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Aksies

Vir meer inligting oor hierdie tipes etikette [**lees hierdie inleiding**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lees

Probeer om die **kaartinligting** te **lees**. Dan kan dit **emuleer** word.

{% hint style="warning" %}
Let daarop dat sommige interkoms probeer om hulself te beskerm teen sleutelduplisering deur 'n skryfopdrag te stuur voordat hulle lees. As die skryf suksesvol is, word daardie etiket as vals beskou. Wanneer Flipper RFID emuleer, is daar geen manier vir die leser om dit van die oorspronklike een te onderskei nie, so sulke probleme ontstaan nie.
{% endhint %}

### Voeg Handmatig By

Jy kan **vals kaarte in Flipper Zero skep deur die data** wat jy handmatig invoer, en dit dan emuleer.

#### ID's op kaarte

Soms, wanneer jy 'n kaart kry, sal jy die ID (of deel daarvan) op die kaart sigbaar vind.

* **EM Marin**

Byvoorbeeld, in hierdie EM-Marin kaart is dit moontlik om die **laaste 3 van 5 bytes in duidelik** te **lees**.\
Die ander 2 kan brute-forced word as jy dit nie van die kaart kan lees nie.

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* **HID**

Dieselfde gebeur in hierdie HID kaart waar slegs 2 van die 3 bytes op die kaart gedruk kan word.

<figure><img src="../../../.gitbook/assets/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emuleer/Skryf

Na **kopieer** 'n kaart of **invoer** die ID **handmatig** is dit moontlik om dit met Flipper Zero te **emuleer** of dit in 'n werklike kaart te **skryf**.

## Verwysings

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
