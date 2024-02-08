# FZ - NFC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de les corriger plus rapidement. Intruder suit votre surface d'attaque, lance des analyses de menaces proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Introduction <a href="#9wrzi" id="9wrzi"></a>

Pour des informations sur les RFID et NFC, consultez la page suivante :

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Cartes NFC prises en charge <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
En plus des cartes NFC, Flipper Zero prend en charge **d'autres types de cartes haute fréquence** telles que plusieurs cartes **Mifare** Classic et Ultralight et **NTAG**.
{% endhint %}

De nouveaux types de cartes NFC seront ajoutés à la liste des cartes prises en charge. Flipper Zero prend en charge les cartes NFC de type A suivantes (ISO 14443A) :

* **Cartes bancaires (EMV)** — lit uniquement l'UID, le SAK et l'ATQA sans les sauvegarder.
* **Cartes inconnues** — lit (UID, SAK, ATQA) et émule un UID.

Pour les **cartes NFC de type B, type F et type V**, Flipper Zero est capable de lire un UID sans le sauvegarder.

### Cartes NFC de type A <a href="#uvusf" id="uvusf"></a>

#### Carte bancaire (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero peut seulement lire un UID, SAK, ATQA et les données stockées sur les cartes bancaires **sans les sauvegarder**.

Écran de lecture de carte bancairePour les cartes bancaires, Flipper Zero peut seulement lire les données **sans les sauvegarder et les émuler**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Cartes inconnues <a href="#37eo8" id="37eo8"></a>

Lorsque Flipper Zero est **incapable de déterminer le type de carte NFC**, seuls un **UID, SAK et ATQA** peuvent être **lus et sauvegardés**.

Écran de lecture de carte inconnuePour les cartes NFC inconnues, Flipper Zero peut émuler uniquement un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Cartes NFC de types B, F et V <a href="#wyg51" id="wyg51"></a>

Pour les **cartes NFC de types B, F et V**, Flipper Zero peut seulement **lire et afficher un UID** sans le sauvegarder.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Actions

Pour une introduction sur les NFC [**lisez cette page**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lecture

Flipper Zero peut **lire les cartes NFC**, cependant, il **ne comprend pas tous les protocoles** basés sur l'ISO 14443. Cependant, comme **l'UID est un attribut de bas niveau**, vous pourriez vous retrouver dans une situation où **l'UID est déjà lu, mais le protocole de transfert de données de haut niveau est encore inconnu**. Vous pouvez lire, émuler et saisir manuellement l'UID en utilisant Flipper pour les lecteurs primitifs qui utilisent l'UID pour l'autorisation.

#### Lecture de l'UID VS Lecture des données à l'intérieur <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Dans Flipper, la lecture des tags à 13,56 MHz peut être divisée en deux parties :

* **Lecture de bas niveau** — lit uniquement l'UID, SAK et ATQA. Flipper tente de deviner le protocole de haut niveau en se basant sur ces données lues sur la carte. Vous ne pouvez pas être sûr à 100 % avec cela, car il s'agit simplement d'une hypothèse basée sur certains facteurs.
* **Lecture de haut niveau** — lit les données de la mémoire de la carte en utilisant un protocole de haut niveau spécifique. Cela consisterait à lire les données sur un Mifare Ultralight, lire les secteurs d'un Mifare Classic, ou lire les attributs de la carte de PayPass/Apple Pay.

### Lecture Spécifique

Dans le cas où Flipper Zero n'est pas capable de trouver le type de carte à partir des données de bas niveau, dans `Actions supplémentaires` vous pouvez sélectionner `Lire un type de carte spécifique` et **indiquer manuellement** **le type de carte que vous souhaitez lire**.

#### Cartes bancaires EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

En plus de simplement lire l'UID, vous pouvez extraire beaucoup plus de données d'une carte bancaire. Il est possible d'**obtenir le numéro complet de la carte** (les 16 chiffres à l'avant de la carte), la **date de validité**, et dans certains cas même le **nom du propriétaire** ainsi qu'une liste des **transactions les plus récentes**.\
Cependant, vous **ne pouvez pas lire le CVV de cette manière** (les 3 chiffres à l'arrière de la carte). De plus, **les cartes bancaires sont protégées contre les attaques de rejeu**, donc les copier avec Flipper et essayer ensuite de les émuler pour payer quelque chose ne fonctionnera pas.

## Références

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de les corriger plus rapidement. Intruder suit votre surface d'attaque, lance des analyses de menaces proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
