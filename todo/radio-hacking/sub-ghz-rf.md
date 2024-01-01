# Sub-GHz RF

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Portes de Garage

Les ouvre-portes de garage fonctionnent généralement à des fréquences dans la plage de 300-190 MHz, les fréquences les plus courantes étant 300 MHz, 310 MHz, 315 MHz et 390 MHz. Cette gamme de fréquences est couramment utilisée pour les ouvre-portes de garage car elle est moins encombrée que d'autres bandes de fréquences et est moins susceptible de subir des interférences d'autres appareils.

## Portières de Voiture

La plupart des clés de voiture fonctionnent soit sur **315 MHz ou 433 MHz**. Ce sont toutes les deux des fréquences radio, et elles sont utilisées dans une variété d'applications différentes. La principale différence entre les deux fréquences est que 433 MHz a une portée plus longue que 315 MHz. Cela signifie que 433 MHz est mieux pour les applications nécessitant une portée plus longue, comme l'entrée sans clé à distance.\
En Europe, le 433.92MHz est couramment utilisé et aux États-Unis et au Japon, c'est le 315MHz.

## **Attaque par Brute-force**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Si au lieu d'envoyer chaque code 5 fois (envoyé ainsi pour s'assurer que le récepteur le reçoit) on l'envoie une seule fois, le temps est réduit à 6 minutes :

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

et si vous **supprimez les 2 ms d'attente** entre les signaux, vous pouvez **réduire le temps à 3 minutes.**

De plus, en utilisant la Séquence de De Bruijn (une manière de réduire le nombre de bits nécessaires pour envoyer tous les nombres binaires potentiels pour le brute-force), ce **temps est réduit à seulement 8 secondes** :

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Un exemple de cette attaque a été implémenté dans [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Exiger **un préambule évitera l'optimisation de la Séquence de De Bruijn** et **les codes tournants empêcheront cette attaque** (en supposant que le code soit assez long pour ne pas être brute-forcé).

## Attaque Sub-GHz

Pour attaquer ces signaux avec Flipper Zero, consultez :

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Protection par Codes Tournants

Les ouvre-portes de garage automatiques utilisent généralement une télécommande sans fil pour ouvrir et fermer la porte de garage. La télécommande **envoie un signal de fréquence radio (RF)** à l'ouvre-porte de garage, qui active le moteur pour ouvrir ou fermer la porte.

Il est possible pour quelqu'un d'utiliser un appareil connu sous le nom de code grabber pour intercepter le signal RF et l'enregistrer pour une utilisation ultérieure. Cela est connu sous le nom d'**attaque par replay**. Pour prévenir ce type d'attaque, de nombreux ouvre-portes de garage modernes utilisent une méthode de chiffrement plus sécurisée connue sous le nom de système de **codes tournants**.

Le **signal RF est généralement transmis en utilisant un code tournant**, ce qui signifie que le code change à chaque utilisation. Cela rend **difficile** pour quelqu'un d'**intercepter** le signal et de l'**utiliser** pour obtenir un accès **non autorisé** au garage.

Dans un système de codes tournants, la télécommande et l'ouvre-porte de garage ont un **algorithme partagé** qui **génère un nouveau code** à chaque fois que la télécommande est utilisée. L'ouvre-porte de garage ne répondra qu'au **bon code**, rendant beaucoup plus difficile pour quelqu'un d'obtenir un accès non autorisé au garage juste en capturant un code.

### **Attaque par Manque de Liaison**

En gros, vous écoutez le bouton et **capturez le signal pendant que la télécommande est hors de portée** de l'appareil (disons la voiture ou le garage). Vous vous déplacez ensuite vers l'appareil et **utilisez le code capturé pour l'ouvrir**.

### Attaque par Brouillage de Liaison Complète

Un attaquant pourrait **brouiller le signal près du véhicule ou du récepteur** de sorte que le **récepteur ne puisse pas réellement 'entendre' le code**, et une fois cela fait, vous pouvez simplement **capturer et rejouer** le code lorsque vous avez arrêté de brouiller.

La victime à un moment donné utilisera les **clés pour verrouiller la voiture**, mais ensuite l'attaque aura **enregistré suffisamment de codes "fermer la porte"** qui pourraient être renvoyés pour ouvrir la porte (un **changement de fréquence pourrait être nécessaire** car il y a des voitures qui utilisent les mêmes codes pour ouvrir et fermer mais écoutent les deux commandes sur des fréquences différentes).

{% hint style="warning" %}
**Le brouillage fonctionne**, mais c'est perceptible car si la **personne verrouillant la voiture teste simplement les portes** pour s'assurer qu'elles sont verrouillées, elle remarquerait que la voiture est déverrouillée. De plus, s'ils étaient conscients de telles attaques, ils pourraient même écouter le fait que les portes n'ont jamais émis le **son** de verrouillage ou que les **lumières** de la voiture n'ont jamais clignoté lorsqu'ils ont appuyé sur le bouton de verrouillage.
{% endhint %}

### **Attaque par Capture de Code (alias 'RollJam')**

C'est une technique de brouillage plus **furtive**. L'attaquant va brouiller le signal, donc lorsque la victime essaie de verrouiller la porte, cela ne fonctionnera pas, mais l'attaquant va **enregistrer ce code**. Ensuite, la victime va **essayer de verrouiller la voiture à nouveau** en appuyant sur le bouton et la voiture va **enregistrer ce second code**.\
Immédiatement après cela, l'**attaquant peut envoyer le premier code** et la **voiture se verrouillera** (la victime pensera que la deuxième pression l'a fermée). Ensuite, l'attaquant pourra **envoyer le deuxième code volé pour ouvrir** la voiture (en supposant qu'un **code "fermer la voiture" puisse aussi être utilisé pour l'ouvrir**). Un changement de fréquence pourrait être nécessaire (car il y a des voitures qui utilisent les mêmes codes pour ouvrir et fermer mais écoutent les deux commandes sur des fréquences différentes).

L'attaquant peut **brouiller le récepteur de la voiture et non son récepteur** parce que si le récepteur de la voiture écoute par exemple une bande passante de 1MHz, l'attaquant ne va pas **brouiller** la fréquence exacte utilisée par la télécommande mais **une proche dans ce spectre** tandis que le **récepteur de l'attaquant écoutera dans une plage plus petite** où il peut entendre le signal de la télécommande **sans le signal de brouillage**.

{% hint style="warning" %}
D'autres implémentations vues dans les spécifications montrent que le **code tournant est une portion** du code total envoyé. C'est-à-dire que le code envoyé est une **clé de 24 bits** où les premiers **12 sont le code tournant**, les **8 suivants sont la commande** (comme verrouiller ou déverrouiller) et les 4 derniers sont le **checksum**. Les véhicules mettant en œuvre ce type sont également naturellement susceptibles car l'attaquant a juste besoin de remplacer le segment de code tournant pour pouvoir **utiliser n'importe quel code tournant sur les deux fréquences**.
{% endhint %}

{% hint style="danger" %}
Notez que si la victime envoie un troisième code pendant que l'attaquant envoie le premier, le premier et le deuxième code seront invalidés.
{% endhint %}

### Attaque par Brouillage avec Alarme

En testant contre un système de codes tournants après-vente installé sur une voiture, **envoyer le même code deux fois** a immédiatement **activé l'alarme** et l'immobilisateur offrant une opportunité unique de **déni de service**. Ironiquement, le moyen de **désactiver l'alarme** et l'immobilisateur était de **presser** la **télécommande**, offrant à un attaquant la possibilité de **continuer à effectuer une attaque DoS**. Ou combinez cette attaque avec la **précédente pour obtenir plus de codes** car la victime voudrait arrêter l'attaque au plus vite.

## Références

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
