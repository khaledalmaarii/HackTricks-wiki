# RF Sub-GHz

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Portes de garage

Les ouvre-portes de garage fonctionnent généralement à des fréquences comprises entre 300 et 190 MHz, les fréquences les plus courantes étant 300 MHz, 310 MHz, 315 MHz et 390 MHz. Cette plage de fréquences est couramment utilisée pour les ouvre-portes de garage car elle est moins encombrée que d'autres bandes de fréquences et est moins susceptible de subir des interférences d'autres appareils.

## Portes de voiture

La plupart des télécommandes de voiture fonctionnent soit sur **315 MHz soit sur 433 MHz**. Ce sont toutes deux des fréquences radio, et elles sont utilisées dans diverses applications. La principale différence entre les deux fréquences est que 433 MHz a une portée plus longue que 315 MHz. Cela signifie que 433 MHz est mieux adapté aux applications nécessitant une portée plus longue, comme l'entrée sans clé à distance.\
En Europe, le 433,92 MHz est couramment utilisé et aux États-Unis et au Japon, c'est le 315 MHz.

## **Attaque par force brute**

<figure><img src="../../.gitbook/assets/image (1081).png" alt=""><figcaption></figcaption></figure>

Si au lieu d'envoyer chaque code 5 fois (envoyé de cette manière pour s'assurer que le récepteur le reçoit), vous l'envoyez une seule fois, le temps est réduit à 6 minutes :

<figure><img src="../../.gitbook/assets/image (616).png" alt=""><figcaption></figcaption></figure>

et si vous **supprimez la période d'attente de 2 ms** entre les signaux, vous pouvez **réduire le temps à 3 minutes**.

De plus, en utilisant la séquence de De Bruijn (une façon de réduire le nombre de bits nécessaires pour envoyer tous les nombres binaires potentiels à forcer), ce **temps est réduit à seulement 8 secondes** :

<figure><img src="../../.gitbook/assets/image (580).png" alt=""><figcaption></figcaption></figure>

Un exemple de cette attaque a été implémenté dans [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Exiger **un préambule évitera la séquence de De Bruijn** et les **codes tournants empêcheront cette attaque** (en supposant que le code soit suffisamment long pour ne pas être forcé).

## Attaque Sub-GHz

Pour attaquer ces signaux avec Flipper Zero, vérifiez :

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Protection des codes tournants

Les ouvre-portes de garage automatiques utilisent généralement une télécommande sans fil pour ouvrir et fermer la porte de garage. La télécommande **envoie un signal radiofréquence (RF)** à l'ouvre-porte de garage, qui active le moteur pour ouvrir ou fermer la porte.

Il est possible pour quelqu'un d'utiliser un dispositif appelé un intercepteur de code pour intercepter le signal RF et l'enregistrer pour une utilisation ultérieure. C'est ce qu'on appelle une **attaque de rejeu**. Pour prévenir ce type d'attaque, de nombreux ouvre-portes de garage modernes utilisent une méthode de cryptage plus sécurisée appelée système de **code tournant**.

Le **signal RF est généralement transmis en utilisant un code tournant**, ce qui signifie que le code change à chaque utilisation. Cela rend **difficile** pour quelqu'un d'**intercepter** le signal et de l'utiliser pour **accéder de manière non autorisée** au garage.

Dans un système de code tournant, la télécommande et l'ouvre-porte de garage ont un **algorithme partagé** qui **génère un nouveau code** à chaque utilisation de la télécommande. L'ouvre-porte de garage ne répondra qu'au **code correct**, ce qui rend beaucoup plus difficile pour quelqu'un d'accéder de manière non autorisée au garage simplement en capturant un code.

### **Attaque du maillon manquant**

Essentiellement, vous écoutez le bouton et **capturez le signal pendant que la télécommande est hors de portée** du dispositif (par exemple la voiture ou le garage). Ensuite, vous vous déplacez vers le dispositif et **utilisez le code capturé pour l'ouvrir**.

### Attaque de brouillage de lien complet

Un attaquant pourrait **brouiller le signal près du véhicule ou du récepteur** afin que le **récepteur ne puisse pas réellement ‘entendre’ le code**, et une fois que cela se produit, vous pouvez simplement **capturer et rejouer** le code une fois que vous avez arrêté de brouiller.

La victime à un moment donné utilisera les **clés pour verrouiller la voiture**, mais ensuite l'attaque aura **enregistré suffisamment de codes de "fermeture de porte"** qui, espérons-le, pourraient être renvoyés pour ouvrir la porte (un **changement de fréquence pourrait être nécessaire** car il y a des voitures qui utilisent les mêmes codes pour ouvrir et fermer mais écoutent les deux commandes sur des fréquences différentes).

{% hint style="warning" %}
**Le brouillage fonctionne**, mais il est perceptible car si la **personne verrouillant la voiture teste simplement les portes** pour s'assurer qu'elles sont verrouillées, elle remarquerait que la voiture est déverrouillée. De plus, s'ils étaient conscients de telles attaques, ils pourraient même écouter le fait que les portes n'ont jamais fait le **bruit de verrouillage** ou que les **feux de la voiture** n'ont jamais clignoté lorsqu'ils ont appuyé sur le bouton ‘verrouiller’.
{% endhint %}

### **Attaque de capture de code (alias ‘RollJam’)**

Il s'agit d'une technique de brouillage plus **furtive**. L'attaquant brouillera le signal, donc lorsque la victime essaiera de verrouiller la porte, cela ne fonctionnera pas, mais l'attaquant **enregistrera ce code**. Ensuite, la victime **essaiera de verrouiller la voiture à nouveau** en appuyant sur le bouton et la voiture **enregistrera ce deuxième code**.\
Immédiatement après cela, l'**attaquant peut envoyer le premier code** et la **voiture se verrouillera** (la victime pensera que la deuxième pression l'a fermée). Ensuite, l'attaquant pourra **envoyer le deuxième code volé pour ouvrir** la voiture (en supposant qu'un **code de "fermeture de voiture" peut également être utilisé pour l'ouvrir**). Un changement de fréquence pourrait être nécessaire (car il y a des voitures qui utilisent les mêmes codes pour ouvrir et fermer mais écoutent les deux commandes sur des fréquences différentes).

L'attaquant peut **brouiller le récepteur de la voiture et non son récepteur** car si le récepteur de la voiture écoute par exemple sur une large bande de 1 MHz, l'attaquant ne **brouillera pas** la fréquence exacte utilisée par la télécommande mais **une proche dans ce spectre** tandis que le **récepteur de l'attaquant écoutera dans une plage plus restreinte** où il peut écouter le signal de la télécommande **sans le signal de brouillage**.

{% hint style="warning" %}
D'autres implémentations vues dans les spécifications montrent que le **code tournant est une partie** du code total envoyé. Par exemple, le code envoyé est une **clé de 24 bits** où les **12 premiers sont le code tournant**, les **8 suivants sont la commande** (comme verrouiller ou déverrouiller) et les 4 derniers sont le **checksum**. Les véhicules implémentant ce type sont également naturellement vulnérables car l'attaquant n'a qu'à remplacer le segment de code tournant pour pouvoir **utiliser n'importe quel code tournant sur les deux fréquences**.
{% endhint %}

{% hint style="danger" %}
Notez que si la victime envoie un troisième code pendant que l'attaquant envoie le premier, le premier et le deuxième code seront invalidés.
{% endhint %}
### Attaque de brouillage de déclenchement d'alarme

Tester contre un système de code roulant après-vente installé sur une voiture, **envoyer le même code deux fois** immédiatement **activait l'alarme** et l'immobilisateur offrant une opportunité de **déni de service** unique. Ironiquement, le moyen de **désactiver l'alarme** et l'immobilisateur était de **presser** la **télécommande**, offrant à un attaquant la possibilité de **continuer à effectuer des attaques DoS**. Ou combiner cette attaque avec la **précédente pour obtenir plus de codes** car la victime voudrait arrêter l'attaque le plus rapidement possible.

## Références

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
