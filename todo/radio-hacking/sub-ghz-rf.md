# Sub-GHz RF

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com).
* **Rejoignez** le [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Portes de garage

Les ouvre-portes de garage fonctionnent généralement à des fréquences comprises entre 300 et 190 MHz, les fréquences les plus courantes étant 300 MHz, 310 MHz, 315 MHz et 390 MHz. Cette plage de fréquences est couramment utilisée pour les ouvre-portes de garage car elle est moins encombrée que d'autres bandes de fréquences et est moins susceptible de subir des interférences d'autres appareils.

## Portes de voiture

La plupart des télécommandes de voiture fonctionnent soit sur **315 MHz soit sur 433 MHz**. Ce sont toutes deux des fréquences radio, et elles sont utilisées dans une variété d'applications différentes. La principale différence entre les deux fréquences est que 433 MHz a une portée plus longue que 315 MHz. Cela signifie que 433 MHz est mieux adapté aux applications qui nécessitent une portée plus longue, telles que l'entrée sans clé à distance.\
En Europe, la fréquence de 433,92 MHz est couramment utilisée et aux États-Unis et au Japon, c'est la fréquence de 315 MHz.

## Attaque par force brute

<figure><img src="../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

Si au lieu d'envoyer chaque code 5 fois (envoyé de cette manière pour s'assurer que le récepteur le reçoit), vous l'envoyez une seule fois, le temps est réduit à 6 minutes :

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

et si vous **supprimez la période d'attente de 2 ms** entre les signaux, vous pouvez **réduire le temps à 3 minutes**.

De plus, en utilisant la séquence de De Bruijn (une façon de réduire le nombre de bits nécessaires pour envoyer tous les nombres binaires potentiels à bruteforce), ce temps est réduit à seulement 8 secondes :

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Un exemple de cette attaque a été implémenté dans [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

L'exigence d'un **préambule évitera l'optimisation de la séquence de De Bruijn** et les **codes tournants empêcheront cette attaque** (en supposant que le code est suffisamment long pour ne pas être bruteforcé).

## Attaque Sub-GHz

Pour attaquer ces signaux avec Flipper Zero, consultez :

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{%
