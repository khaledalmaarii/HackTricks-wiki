# FZ - 125kHz RFID

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Intro

Pour plus d'infos sur le fonctionnement des tags 125kHz, consultez :

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Actions

Pour plus d'infos sur ces types de tags, [**lisez cette introduction**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lire

Essaye de **lire** les informations de la carte. Ensuite, il peut **l'imiter**.

{% hint style="warning" %}
Notez que certains interphones essaient de se protéger contre la duplication de clés en envoyant une commande d'écriture avant de lire. Si l'écriture réussit, ce tag est considéré comme faux. Lorsque Flipper imite RFID, il n'y a aucun moyen pour le lecteur de le distinguer de l'original, donc aucun problème de ce type ne se produit.
{% endhint %}

### Ajouter Manuellement

Vous pouvez créer des **cartes fausses dans Flipper Zero en indiquant les données** manuellement, puis l'imiter.

#### IDs sur les cartes

Parfois, lorsque vous obtenez une carte, vous trouverez l'ID (ou une partie) écrit sur la carte de manière visible.

* **EM Marin**

Par exemple, dans cette carte EM-Marin, il est possible de **lire les 3 derniers des 5 octets en clair**.\
Les 2 autres peuvent être brute-forcés si vous ne pouvez pas les lire sur la carte.

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* **HID**

Il en va de même pour cette carte HID où seulement 2 des 3 octets peuvent être trouvés imprimés sur la carte.

<figure><img src="../../../.gitbook/assets/image (1014).png" alt=""><figcaption></figcaption></figure>

### Émuler/Écrire

Après avoir **copié** une carte ou **entré** l'ID **manuellement**, il est possible de **l'imiter** avec Flipper Zero ou de **l'écrire** sur une carte réelle.

## Références

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
