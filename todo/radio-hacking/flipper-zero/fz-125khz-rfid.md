# FZ - RFID 125kHz

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Intro

Pour plus d'informations sur le fonctionnement des tags RFID 125kHz, consultez :

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Actions

Pour plus d'informations sur ces types de tags, [**lisez cette introduction**](../../../radio-hacking/pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lire

Essaie de **lire** les informations de la carte. Ensuite, il peut les **émuler**.

{% hint style="warning" %}
Notez que certains interphones essaient de se protéger contre la duplication de clés en envoyant une commande d'écriture avant la lecture. Si l'écriture réussit, ce tag est considéré comme faux. Lorsque Flipper émule un RFID, il n'y a aucun moyen pour le lecteur de le distinguer de l'original, donc aucun problème de ce type ne se produit.
{% endhint %}

### Ajouter Manuellement

Vous pouvez créer des **cartes factices dans Flipper Zero en indiquant les données** que vous entrez manuellement, puis les émuler.

#### IDs sur les cartes

Parfois, lorsque vous obtenez une carte, vous trouverez l'ID (ou une partie) écrit sur la carte visible.

* **EM Marin**

Par exemple, sur cette carte EM-Marin, il est possible de **lire les 3 derniers octets sur 5 en clair** sur la carte physique.\
Les 2 autres peuvent être forcés par brute-force si vous ne pouvez pas les lire sur la carte.

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

Il en va de même pour cette carte HID où seulement 2 octets sur 3 peuvent être trouvés imprimés sur la carte

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### Émuler/Écrire

Après avoir **copié** une carte ou **entré** l'ID **manuellement**, il est possible de **l'émuler** avec Flipper Zero ou de **l'écrire** sur une vraie carte.

## Références

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
