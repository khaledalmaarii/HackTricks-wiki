# FZ - NFC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Intro <a href="#9wrzi" id="9wrzi"></a>

Pour des informations sur les RFID et les NFC, consultez la page suivante :

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Cartes NFC prises en charge <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
En plus des cartes NFC, Flipper Zero prend en charge **d'autres types de cartes haute fréquence** telles que plusieurs cartes **Mifare** Classic et Ultralight et **NTAG**.
{% endhint %}

De nouveaux types de cartes NFC seront ajoutés à la liste des cartes prises en charge. Flipper Zero prend en charge les cartes NFC de type A suivantes (ISO 14443A) :

* ﻿**Cartes bancaires (EMV)** — ne lit que l'UID, le SAK et l'ATQA sans les enregistrer.
* ﻿**Cartes inconnues** — lit (UID, SAK, ATQA) et émule un UID.

Pour les cartes NFC de type B, type F et type V, Flipper Zero est capable de lire un UID sans l'enregistrer.

### Cartes NFC de type A <a href="#uvusf" id="uvusf"></a>

#### Carte bancaire (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero ne peut lire que l'UID, le SAK, l'ATQA et les données stockées sur les cartes bancaires **sans les enregistrer**.

Écran de lecture de carte bancairePour les cartes bancaires, Flipper Zero ne peut lire que les données **sans les enregistrer et les émuler**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Cartes inconnues <a href="#37eo8" id="37eo8"></a>

Lorsque Flipper Zero est **incapable de déterminer le type de carte NFC**, seuls un **UID, un SAK et un ATQA** peuvent être **lus et enregistrés**.

Écran de lecture de carte inconnuePour les cartes NFC inconnues, Flipper Zero ne peut émuler qu'un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Cartes NFC de types B, F et V <a href="#wyg51" id="wyg51"></a>

Pour les cartes NFC de types B, F et V, Flipper Zero ne peut que **lire et afficher un UID** sans l'enregistrer.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Actions

Pour une introduction aux NFC, [**lisez cette page**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lecture

Flipper Zero peut **lire les cartes NFC**, cependant, il **ne comprend pas tous les protocoles** basés sur ISO 14443. Cependant, étant donné que **l'UID est un attribut de bas niveau**, vous pourriez vous retrouver dans une situation où **l'UID est déjà lu, mais le protocole de transfert de données de haut niveau est encore inconnu**. Vous pouvez lire, émuler et saisir manuellement l'UID à l'aide de Flipper pour les lecteurs primitifs qui utilisent l'UID pour l'autorisation.

#### Lecture de l'UID VS Lecture des données à l'intérieur <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure
