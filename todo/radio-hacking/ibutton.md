# iButton

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous voulez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Introduction

iButton est un nom générique pour une clé d'identification électronique emballée dans un **conteneur métallique en forme de pièce de monnaie**. Il est également appelé **Mémoire tactile Dallas** ou mémoire de contact. Bien qu'il soit souvent incorrectement appelé une clé "magnétique", il n'y a **rien de magnétique** en lui. En fait, une puce électronique complète fonctionnant sur un protocole numérique est cachée à l'intérieur.

<figure><img src="../../.gitbook/assets/image (912).png" alt=""><figcaption></figcaption></figure>

### Qu'est-ce que iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Généralement, iButton implique la forme physique de la clé et du lecteur - une pièce ronde avec deux contacts. Pour le cadre qui l'entoure, il existe de nombreuses variations allant du support en plastique le plus courant avec un trou aux bagues, pendentifs, etc.

<figure><img src="../../.gitbook/assets/image (1075).png" alt=""><figcaption></figcaption></figure>

Lorsque la clé atteint le lecteur, les **contacts se touchent** et la clé est alimentée pour **transmettre** son ID. Parfois, la clé n'est **pas lue** immédiatement car le **PSD de contact d'un interphone est plus grand** qu'il ne devrait l'être. Ainsi, les contours extérieurs de la clé et du lecteur ne peuvent pas se toucher. Si c'est le cas, vous devrez appuyer sur la clé contre l'une des parois du lecteur.

<figure><img src="../../.gitbook/assets/image (287).png" alt=""><figcaption></figcaption></figure>

### **Protocole 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Les clés Dallas échangent des données en utilisant le protocole 1-Wire. Avec un seul contact pour le transfert de données (!!) dans les deux sens, du maître à l'esclave et vice versa. Le protocole 1-Wire fonctionne selon le modèle Maître-Esclave. Dans cette topologie, le Maître initie toujours la communication et l'Esclave suit ses instructions.

Lorsque la clé (Esclave) entre en contact avec l'interphone (Maître), la puce à l'intérieur de la clé s'allume, alimentée par l'interphone, et la clé est initialisée. Ensuite, l'interphone demande l'ID de la clé. Ensuite, nous examinerons ce processus plus en détail.

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
