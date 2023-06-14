# iButton

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Intro

iButton est un nom générique pour une clé d'identification électronique emballée dans un **conteneur métallique en forme de pièce de monnaie**. On l'appelle également mémoire tactile Dallas ou mémoire de contact. Bien qu'on l'appelle souvent à tort une clé "magnétique", il n'y a **rien de magnétique** en elle. En fait, une **micro-puce** complète fonctionnant sur un protocole numérique est cachée à l'intérieur.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### Qu'est-ce que iButton ? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Généralement, iButton implique la forme physique de la clé et du lecteur - une pièce ronde avec deux contacts. Pour le cadre qui l'entoure, il existe de nombreuses variations, du support en plastique le plus courant avec un trou aux bagues, pendentifs, etc.

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

Lorsque la clé atteint le lecteur, les **contacts se touchent** et la clé est alimentée pour **transmettre** son ID. Parfois, la clé n'est **pas lue** immédiatement parce que le **PSD de contact d'un interphone est plus grand** qu'il ne devrait l'être. Ainsi, les contours extérieurs de la clé et du lecteur ne peuvent pas se toucher. Si c'est le cas, vous devrez appuyer sur la clé sur l'un des murs du lecteur.

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **Protocole 1-Wire** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Les clés Dallas échangent des données en utilisant le protocole 1-wire. Avec un seul contact pour le transfert de données (!!) dans les deux sens, du maître à l'esclave et vice versa. Le protocole 1-wire fonctionne selon le modèle Maître-Esclave. Dans cette topologie, le Maître initie toujours la communication et l'Esclave suit ses instructions.

Lorsque la clé (Esclave) contacte l'interphone (Maître), la puce à l'intérieur de la clé s'allume, alimentée par l'interphone, et la clé est initialisée. Ensuite, l'interphone demande l'ID de la clé. Ensuite, nous examinerons ce processus plus en détail.

Flipper peut fonctionner à la fois en mode Maître et Esclave. En mode lecture de clé, Flipper agit en tant que lecteur, c'est-à-dire qu'il fonctionne en tant que Maître. Et en mode émulation de clé, le flipper prétend être une clé, il est en mode Esclave.

### Clés Dallas, Cyfral & Metakom

Pour des informations sur le fonctionnement de ces clés, consultez la page [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attaques

Les iButtons peuvent être attaqués avec Flipper Zero :

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Références

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
