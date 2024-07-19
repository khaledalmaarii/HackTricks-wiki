# iButton

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

## Intro

iButton est un nom générique pour une clé d'identification électronique emballée dans un **conteneur en métal en forme de pièce**. Il est également appelé **Dallas Touch** Memory ou mémoire de contact. Bien qu'il soit souvent mal appelé clé « magnétique », il n'y a **rien de magnétique** à l'intérieur. En fait, un **microchip** complet fonctionnant sur un protocole numérique est caché à l'intérieur.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### Qu'est-ce que l'iButton ? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

En général, l'iButton implique la forme physique de la clé et du lecteur - une pièce ronde avec deux contacts. Pour le cadre qui l'entoure, il existe de nombreuses variations, du support en plastique le plus courant avec un trou aux anneaux, pendentifs, etc.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Lorsque la clé atteint le lecteur, les **contacts se touchent** et la clé est alimentée pour **transmettre** son ID. Parfois, la clé n'est **pas lue** immédiatement car le **PSD de contact d'un interphone est plus grand** qu'il ne devrait l'être. Ainsi, les contours extérieurs de la clé et du lecteur ne pouvaient pas se toucher. Si c'est le cas, vous devrez appuyer la clé contre l'un des murs du lecteur.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocole 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Les clés Dallas échangent des données en utilisant le protocole 1-wire. Avec un seul contact pour le transfert de données (!!) dans les deux sens, du maître à l'esclave et vice versa. Le protocole 1-wire fonctionne selon le modèle Maître-Esclave. Dans cette topologie, le Maître initie toujours la communication et l'Esclave suit ses instructions.

Lorsque la clé (Esclave) entre en contact avec l'interphone (Maître), la puce à l'intérieur de la clé s'allume, alimentée par l'interphone, et la clé est initialisée. Ensuite, l'interphone demande l'ID de la clé. Nous allons maintenant examiner ce processus plus en détail.

Flipper peut fonctionner à la fois en modes Maître et Esclave. En mode de lecture de clé, Flipper agit comme un lecteur, c'est-à-dire qu'il fonctionne comme un Maître. Et en mode d'émulation de clé, le flipper fait semblant d'être une clé, il est en mode Esclave.

### Clés Dallas, Cyfral & Metakom

Pour des informations sur le fonctionnement de ces clés, consultez la page [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attaques

Les iButtons peuvent être attaqués avec Flipper Zero :

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Références

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
