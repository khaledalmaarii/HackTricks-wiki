# FZ - Infrarouge

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Vous voulez voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introduction <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Pour plus d'informations sur le fonctionnement de l'infrarouge, consultez :

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Récepteur de signal IR dans Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utilise un récepteur de signal IR numérique TSOP, qui **permet d'intercepter les signaux des télécommandes IR**. Certains **smartphones** comme Xiaomi ont également un port IR, mais gardez à l'esprit que **la plupart d'entre eux ne peuvent que transmettre** des signaux et sont **incapables de les recevoir**.

Le récepteur infrarouge de Flipper est assez sensible. Vous pouvez même **capturer le signal** en restant **quelque part entre** la télécommande et la télévision. Il n'est pas nécessaire de pointer la télécommande directement vers le port IR de Flipper. Cela est pratique lorsque quelqu'un change de chaîne en étant près de la télévision, et que vous et Flipper êtes à une certaine distance.

Comme le **décodage du signal infrarouge** se fait du côté **logiciel**, Flipper Zero prend en charge potentiellement la **réception et la transmission de codes de télécommande IR**. En cas de **protocoles inconnus** qui ne peuvent pas être reconnus, il **enregistre et rejoue** le signal brut tel qu'il a été reçu.

## Actions

### Télécommandes Universelles

Flipper Zero peut être utilisé comme une **télécommande universelle pour contrôler n'importe quelle télévision, climatiseur ou centre multimédia**. Dans ce mode, Flipper **force brute** tous les **codes connus** de tous les fabricants pris en charge **selon le dictionnaire de la carte SD**. Vous n'avez pas besoin de choisir une télécommande particulière pour éteindre une télévision de restaurant.

Il suffit d'appuyer sur le bouton d'alimentation en mode Télécommande Universelle, et Flipper enverra **séquentiellement des commandes "Éteindre"** de toutes les télévisions qu'il connaît : Sony, Samsung, Panasonic... et ainsi de suite. Lorsque la télévision reçoit son signal, elle réagira et s'éteindra.

Une telle attaque en force brute prend du temps. Plus le dictionnaire est grand, plus il faudra de temps pour terminer. Il est impossible de savoir quel signal exactement la télévision a reconnu, car il n'y a pas de retour d'information de la télévision.

### Apprendre une Nouvelle Télécommande

Il est possible de **capturer un signal infrarouge** avec Flipper Zero. S'il **trouve le signal dans la base de données**, Flipper saura automatiquement **quel appareil il s'agit** et vous permettra d'interagir avec lui.\
Sinon, Flipper peut **stocker** le **signal** et vous permettra de le **rejouer**.

## Références

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Vous voulez voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
