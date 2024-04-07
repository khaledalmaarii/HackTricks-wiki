# FZ - 125kHz RFID

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Introduction

Pour plus d'informations sur le fonctionnement des balises 125 kHz, consultez :

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Actions

Pour plus d'informations sur ces types de balises, [**lisez cette introduction**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lire

Essaie de **lire** les informations de la carte. Ensuite, il peut les **émuler**.

{% hint style="warning" %}
Notez que certains interphones tentent de se protéger contre la duplication de clés en envoyant une commande d'écriture avant la lecture. Si l'écriture réussit, cette balise est considérée comme fausse. Lorsque Flipper émule le RFID, il n'y a aucun moyen pour le lecteur de le distinguer de l'original, donc de tels problèmes ne se produisent pas.
{% endhint %}

### Ajouter manuellement

Vous pouvez créer des **cartes factices dans Flipper Zero en indiquant les données** manuellement, puis les émuler.

#### IDs sur les cartes

Parfois, lorsque vous obtenez une carte, vous trouverez l'ID (ou une partie) écrit sur la carte de manière visible.

- **EM Marin**

Par exemple, sur cette carte EM-Marin, il est possible de **lire les 3 derniers octets sur 5 en clair**.\
Les 2 autres peuvent être forcés si vous ne pouvez pas les lire sur la carte.

<figure><img src="../../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

- **HID**

Il en va de même pour cette carte HID où seuls 2 octets sur 3 peuvent être trouvés imprimés sur la carte

<figure><img src="../../../.gitbook/assets/image (1011).png" alt=""><figcaption></figcaption></figure>

### Émuler/Écrire

Après avoir **copié** une carte ou **entré** l'ID **manuellement**, il est possible de **l'émuler** avec Flipper Zero ou de **l'écrire** sur une vraie carte.

## Références

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
