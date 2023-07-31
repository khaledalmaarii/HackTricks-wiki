# Sub-GHz RF

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Portes de garage

Les ouvre-portes de garage fonctionnent généralement à des fréquences comprises entre 300 et 190 MHz, les fréquences les plus courantes étant de 300 MHz, 310 MHz, 315 MHz et 390 MHz. Cette plage de fréquences est couramment utilisée pour les ouvre-portes de garage car elle est moins encombrée que d'autres bandes de fréquences et est moins susceptible de subir des interférences d'autres appareils.

## Portes de voiture

La plupart des télécommandes de voiture fonctionnent soit sur **315 MHz soit sur 433 MHz**. Ce sont toutes deux des fréquences radio, et elles sont utilisées dans différentes applications. La principale différence entre les deux fréquences est que 433 MHz a une portée plus longue que 315 MHz. Cela signifie que 433 MHz est plus adapté aux applications nécessitant une portée plus longue, comme l'ouverture sans clé à distance.\
En Europe, on utilise couramment la fréquence de 433,92 MHz et aux États-Unis et au Japon, c'est la fréquence de 315 MHz.

## **Attaque par force brute**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Si au lieu d'envoyer chaque code 5 fois (envoyé de cette manière pour s'assurer que le récepteur le reçoit), vous l'envoyez une seule fois, le temps est réduit à 6 minutes :

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

et si vous **supprimez la période d'attente de 2 ms** entre les signaux, vous pouvez **réduire le temps à 3 minutes**.

De plus, en utilisant la séquence de De Bruijn (une façon de réduire le nombre de bits nécessaires pour envoyer tous les nombres binaires potentiels à forcer), ce **temps est réduit à seulement 8 secondes** :

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Un exemple de cette attaque a été implémenté dans [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

L'utilisation d'un **préambule évitera l'optimisation de la séquence de De Bruijn** et les **codes tournants empêcheront cette attaque** (en supposant que le code soit suffisamment long pour ne pas être forcé).

## Attaque Sub-GHz

Pour attaquer ces signaux avec Flipper Zero, consultez :

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Protection des codes tournants

Les ouvre-portes de garage automatiques utilisent généralement une télécommande sans fil pour ouvrir et fermer la porte de garage. La télécommande **envoie un signal radio (RF)** à l'ouvre-porte de garage, qui active le moteur pour ouvrir ou fermer la porte.

Il est possible pour quelqu'un d'utiliser un appareil appelé un codeur pour intercepter le signal RF et l'enregistrer pour une utilisation ultérieure. C'est ce qu'on appelle une **attaque de rejeu**. Pour prévenir ce type d'attaque, de nombreux ouvre-portes de garage modernes utilisent une méthode de chiffrement plus sécurisée appelée **code tournant**.

Le **signal RF est généralement transmis à l'aide d'un code tournant**, ce qui signifie que le code change à chaque utilisation. Cela rend **difficile** pour quelqu'un d'**intercepter** le signal et de l'utiliser pour **accéder sans autorisation** au garage.

Dans un système de code tournant, la télécommande et l'ouvre-porte de garage ont un **algorithme partagé** qui **génère un nouveau code** à chaque utilisation de la télécommande. L'ouvre-porte de garage ne répondra qu'au **code correct**, ce qui rend beaucoup plus difficile pour quelqu'un d'accéder sans autorisation au garage simplement en capturant un code.

### **Attaque du maillon manquant**

Essentiellement, vous écoutez le bouton et **capturez le signal pendant que la télécommande est hors de portée** de l'appareil (par exemple la voiture ou le garage). Vous vous déplacez ensuite vers l'appareil et **utilisez le code capturé pour l'ouvrir**.

### Attaque de brouillage de lien complet

Un attaquant pourrait **brouiller le signal près du véhicule ou du récepteur** de sorte que le **récepteur ne puisse pas "entendre" le code**, et une fois que cela se produit, vous pouvez simplement **capturer et rejouer** le code lorsque vous avez arrêté de brouiller.

La victime à un moment donné utilisera les **clés pour verrouiller la voiture**, mais ensuite l'attaque aura **enregistré suffisamment de codes de "fermeture de porte"** qui pourraient être renvoyés pour ouvrir la porte (un **changement de fréquence pourrait être nécessaire** car il y a des voitures qui utilisent les mêmes codes pour ouvrir et fermer mais écoutent les deux commandes à des fréquences différentes).

{% hint style="warning" %}
Le brouillage fonctionne, mais il est perceptible car si la **personne qui verrouille la voiture teste simplement les portes** pour s'assurer qu'elles sont verrouillées, elle remarquera que la voiture est déverrouillée. De plus, si elle était consciente de telles attaques, elle pourrait même écouter le fait que les portes n'ont jamais fait le **bruit** de verrouillage ou que les **feux** de la voiture n'ont jamais clignoté lorsqu'elle a appuyé sur le bouton "verrouiller".
{% endhint %}
### **Attaque de récupération de code (alias 'RollJam')**

Il s'agit d'une technique de brouillage plus **furtive**. L'attaquant va brouiller le signal, de sorte que lorsque la victime essaie de verrouiller la porte, cela ne fonctionne pas, mais l'attaquant va **enregistrer ce code**. Ensuite, la victime va **essayer de verrouiller la voiture à nouveau** en appuyant sur le bouton et la voiture va **enregistrer ce deuxième code**.\
Immédiatement après cela, l'**attaquant peut envoyer le premier code** et la **voiture se verrouillera** (la victime pensera que la deuxième pression l'a fermée). Ensuite, l'attaquant pourra **envoyer le deuxième code volé pour ouvrir** la voiture (en supposant qu'un **code de "fermeture de voiture" peut également être utilisé pour l'ouvrir**). Un changement de fréquence peut être nécessaire (car il y a des voitures qui utilisent les mêmes codes pour ouvrir et fermer mais écoutent les deux commandes à des fréquences différentes).

L'attaquant peut **brouiller le récepteur de la voiture et non son propre récepteur** car si le récepteur de la voiture écoute par exemple une bande passante de 1 MHz, l'attaquant ne **brouillera pas** la fréquence exacte utilisée par la télécommande mais **une fréquence proche dans ce spectre** tandis que le **récepteur de l'attaquant écoutera dans une plage plus petite** où il peut écouter le signal de la télécommande **sans le signal de brouillage**.

{% hint style="warning" %}
D'autres implémentations vues dans les spécifications montrent que le **code tournant est une partie** du code total envoyé. Par exemple, le code envoyé est une **clé de 24 bits** où les **12 premiers sont le code tournant**, les **8 suivants sont la commande** (comme verrouiller ou déverrouiller) et les 4 derniers sont le **checksum**. Les véhicules qui implémentent ce type sont également naturellement vulnérables car l'attaquant n'a qu'à remplacer le segment du code tournant pour pouvoir **utiliser n'importe quel code tournant sur les deux fréquences**.
{% endhint %}

{% hint style="danger" %}
Notez que si la victime envoie un troisième code pendant que l'attaquant envoie le premier, le premier et le deuxième code seront invalidés.
{% endhint %}

### Attaque de brouillage avec déclenchement d'alarme

Lors des tests effectués sur un système de code tournant après-vente installé sur une voiture, **l'envoi du même code deux fois** a immédiatement **activé l'alarme** et l'antidémarrage, offrant ainsi une **opportunité de déni de service** unique. Ironiquement, la façon de **désactiver l'alarme** et l'antidémarrage était de **presser** la **télécommande**, offrant ainsi à un attaquant la possibilité de **réaliser continuellement une attaque par déni de service**. Ou combiner cette attaque avec la **précédente pour obtenir plus de codes**, car la victime voudrait arrêter l'attaque au plus vite.

## Références

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
