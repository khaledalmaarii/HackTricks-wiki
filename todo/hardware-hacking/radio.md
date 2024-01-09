# Radio

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) est un analyseur de signal numérique gratuit pour GNU/Linux et macOS, conçu pour extraire des informations de signaux radio inconnus. Il prend en charge une variété de dispositifs SDR via SoapySDR et permet la démodulation ajustable des signaux FSK, PSK et ASK, décode la vidéo analogique, analyse les signaux saccadés et écoute les canaux vocaux analogiques (le tout en temps réel).

### Configuration de base

Après l'installation, il y a quelques éléments que vous pourriez envisager de configurer.\
Dans les paramètres (le deuxième bouton de l'onglet), vous pouvez sélectionner le **dispositif SDR** ou **sélectionner un fichier** à lire et quelle fréquence syntoniser ainsi que le taux d'échantillonnage (il est recommandé de monter jusqu'à 2,56Msps si votre PC le supporte)\\

![](<../../.gitbook/assets/image (655) (1).png>)

Dans le comportement de l'interface utilisateur, il est recommandé d'activer quelques options si votre PC le supporte :

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
Si vous réalisez que votre PC ne capture pas les choses, essayez de désactiver OpenGL et de réduire le taux d'échantillonnage.
{% endhint %}

### Utilisations

* Juste pour **capturer un moment d'un signal et l'analyser**, maintenez le bouton "Push to capture" aussi longtemps que nécessaire.

![](<../../.gitbook/assets/image (631).png>)

* Le **Tuner** de SigDigger aide à **capturer de meilleurs signaux** (mais il peut aussi les dégrader). Idéalement, commencez avec 0 et continuez à **augmenter jusqu'à ce que** vous trouviez que le **bruit** introduit est **plus important** que l'**amélioration du signal** dont vous avez besoin).

![](<../../.gitbook/assets/image (658).png>)

### Synchroniser avec le canal radio

Avec [**SigDigger**](https://github.com/BatchDrake/SigDigger) synchronisez avec le canal que vous souhaitez entendre, configurez l'option "Aperçu audio de base", configurez la bande passante pour obtenir toutes les informations envoyées, puis réglez le Tuner au niveau avant que le bruit ne commence vraiment à augmenter :

![](<../../.gitbook/assets/image (389).png>)

## Astuces intéressantes

* Lorsqu'un dispositif envoie des rafales d'informations, généralement la **première partie va être un préambule** donc vous **n'avez pas à vous inquiéter** si vous **ne trouvez pas d'informations** là ou s'il y a des **erreurs**.
* Dans les trames d'informations, vous devriez généralement **trouver différentes trames bien alignées entre elles** :

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Après avoir récupéré les bits, vous pourriez avoir besoin de les traiter d'une certaine manière**. Par exemple, dans la codification de Manchester, un haut+bas sera un 1 ou un 0 et un bas+haut sera l'autre. Ainsi, des paires de 1 et de 0 (hauts et bas) seront un vrai 1 ou un vrai 0.
* Même si un signal utilise la codification de Manchester (il est impossible de trouver plus de deux 0 ou 1 de suite), vous pourriez **trouver plusieurs 1 ou 0 ensemble dans le préambule** !

### Découvrir le type de modulation avec IQ

Il y a 3 façons de stocker des informations dans les signaux : Moduler l'**amplitude**, la **fréquence** ou la **phase**.\
Si vous analysez un signal, il existe différentes façons d'essayer de déterminer ce qui est utilisé pour stocker des informations (trouvez plus de méthodes ci-dessous), mais une bonne méthode est de vérifier le graphique IQ.

![](<../../.gitbook/assets/image (630).png>)

* **Détecter AM** : Si dans le graphique IQ apparaissent par exemple **2 cercles** (probablement un à 0 et l'autre à une amplitude différente), cela pourrait signifier qu'il s'agit d'un signal AM. Cela est dû au fait que dans le graphique IQ, la distance entre le 0 et le cercle est l'amplitude du signal, il est donc facile de visualiser différentes amplitudes utilisées.
* **Détecter PM** : Comme dans l'image précédente, si vous trouvez de petits cercles non reliés entre eux, cela signifie probablement qu'une modulation de phase est utilisée. Cela est dû au fait que dans le graphique IQ, l'angle entre le point et le 0,0 est la phase du signal, ce qui signifie que 4 phases différentes sont utilisées.
* Notez que si l'information est cachée dans le fait qu'une phase est changée et non dans la phase elle-même, vous ne verrez pas différentes phases clairement différenciées.
* **Détecter FM** : IQ n'a pas de champ pour identifier les fréquences (la distance au centre est l'amplitude et l'angle est la phase).\
Par conséquent, pour identifier FM, vous devriez **voir essentiellement un cercle** dans ce graphique.\
De plus, une fréquence différente est "représentée" par le graphique IQ par une **accélération de la vitesse à travers le cercle** (donc dans SysDigger en sélectionnant le signal, le graphique IQ est peuplé, si vous trouvez une accélération ou un changement de direction dans le cercle créé, cela pourrait signifier que c'est FM) :

## Exemple AM

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Découvrir AM

#### Vérifier l'enveloppe

Vérifier les informations AM avec [**SigDigger**](https://github.com/BatchDrake/SigDigger) et en regardant simplement l'**enveloppe**, vous pouvez voir différents niveaux d'amplitude clairs. Le signal utilisé envoie des impulsions avec des informations en AM, voici à quoi ressemble une impulsion :

![](<../../.gitbook/assets/image (636).png>)

Et voici à quoi ressemble une partie du symbole avec la forme d'onde :

![](<../../.gitbook/assets/image (650) (1).png>)

#### Vérifier l'histogramme

Vous pouvez **sélectionner l'ensemble du signal** où se trouvent les informations, sélectionner le mode **Amplitude** et **Sélection** et cliquer sur **Histogramme**. Vous pouvez observer que seuls 2 niveaux clairs sont trouvés

![](<../../.gitbook/assets/image (647) (1) (1).png>)

Par exemple, si vous sélectionnez Fréquence au lieu d'Amplitude dans ce signal AM, vous ne trouvez qu'une fréquence (aucune information modulée en fréquence n'utilise qu'une seule fréq).

![](<../../.gitbook/assets/image (637) (1) (1).png>)

Si vous trouvez beaucoup de fréquences, potentiellement ce ne sera pas un FM, probablement la fréquence du signal a juste été modifiée à cause du canal.

#### Avec IQ

Dans cet exemple, vous pouvez voir comment il y a un **grand cercle** mais aussi **beaucoup de points au centre**.

![](<../../.gitbook/assets/image (640).png>)

### Obtenir le taux de symboles

#### Avec un symbole

Sélectionnez le plus petit symbole que vous pouvez trouver (pour être sûr qu'il n'y en a qu'un) et vérifiez la "fréquence de sélection". Dans ce cas, ce serait 1.013kHz (donc 1kHz).

![](<../../.gitbook/assets/image (638) (1).png>)

#### Avec un groupe de symboles

Vous pouvez également indiquer le nombre de symboles que vous allez sélectionner et SigDigger calculera la fréquence d'un symbole (plus vous sélectionnez de symboles, mieux c'est probablement). Dans ce scénario, j'ai sélectionné 10 symboles et la "fréquence de sélection" est de 1.004 Khz :

![](<../../.gitbook/assets/image (635).png>)

### Obtenir les bits

Ayant trouvé qu'il s'agit d'un signal **modulé en AM** et le **taux de symboles** (et sachant que dans ce cas quelque chose en haut signifie 1 et quelque chose en bas signifie 0), il est très facile d'**obtenir les bits** encodés dans le signal. Donc, sélectionnez le signal avec info et configurez l'échantillonnage et la décision et appuyez sur échantillon (vérifiez que **Amplitude** est sélectionné, le **taux de symboles découvert** est configuré et la **récupération d'horloge Gadner** est sélectionnée) :

![](<../../.gitbook/assets/image (642) (1).png>)

* **Synchroniser avec les intervalles de sélection** signifie que si vous avez précédemment sélectionné des intervalles pour trouver le taux de symboles, ce taux de symboles sera utilisé.
* **Manuel** signifie que le taux de symboles indiqué va être utilisé
* Dans **Sélection d'intervalle fixe**, vous indiquez le nombre d'intervalles qui doivent être sélectionnés et il calcule le taux de symboles à partir de cela
* **La récupération d'horloge Gadner** est généralement la meilleure option, mais vous devez toujours indiquer un taux de symboles approximatif.

En appuyant sur échantillon, cela apparaît :

![](<../../.gitbook/assets/image (659).png>)

Maintenant, pour faire comprendre à SigDigger **où se trouve la plage** du niveau portant l'information, vous devez cliquer sur le **niveau inférieur** et maintenir cliqué jusqu'au niveau le plus élevé :

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

S'il y avait eu par exemple **4 niveaux d'amplitude différents**, vous auriez dû configurer les **Bits par symbole à 2** et sélectionner du plus petit au plus grand.

Finalement, en **augmentant** le **Zoom** et en **changeant la taille de la ligne**, vous pouvez voir les bits (et vous pouvez tout sélectionner et copier pour obtenir tous les bits) :

![](<../../.gitbook/assets/image (649) (1).png>)

Si le signal a plus d'1 bit par symbole (par exemple 2), SigDigger **ne peut pas savoir quel symbole est** 00, 01, 10, 11, donc il utilisera différentes **échelles de gris** pour les représenter (et si vous copiez les bits, il utilisera des **nombres de 0 à 3**, vous devrez les traiter).

De plus, utilisez des **codifications** telles que **Manchester**, et un **haut+bas** peut être **1 ou 0** et un bas+haut peut être un 1 ou un 0. Dans ces cas, vous devez **traiter les hauts (1) et les bas (0) obtenus** pour substituer les paires de 01 ou 10 par des 0 ou des 1.

## Exemple FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Découvrir FM

#### Vérifier les fréquences et la forme d'onde

Exemple de signal envoyant des informations modulées en FM :

![](<../../.gitbook/assets/image (661) (1).png>)

Dans l'image précédente, vous pouvez observer assez bien que **2 fréquences sont utilisées** mais si vous **observez** la **forme d'onde**, vous pourriez **ne pas être capable d'identifier correctement les 2 différentes fréquences** :

![](<../../.gitbook/assets/image (653).png>)

C'est parce que j'ai capturé le signal dans les deux fréquences, donc l'une est approximativement l'autre en négatif :

![](<../../.gitbook/assets/image (656).png>)

Si la fréquence synchronisée est **plus proche d'une fréquence que de l'autre**, vous pouvez facilement voir les 2 différentes fréquences :

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Vérifier l'histogramme

En vérifiant l'histogramme de fréquence du signal avec des informations, vous pouvez facilement voir 2 signaux différents :

![](<../../.gitbook/assets/image (657).png>)

Dans ce cas, si vous vérifiez l'**histogramme d'Amplitude**, vous trouverez **une seule amplitude**, donc cela **ne peut pas être AM** (si vous trouvez beaucoup d'amplitudes, cela pourrait être parce que le signal a perdu de la puissance le long du canal) :

![](<../../.gitbook/assets/image (646).png>)

Et ceci serait l'histogramme de phase (qui rend très clair que le signal n'est pas modulé en phase) :

![](<../../.gitbook/assets/image (201) (2).png>)

#### Avec IQ

IQ n'a pas de champ pour identifier les fréquences (la distance au centre est l'amplitude et l'angle est la phase).\
Par conséquent, pour identifier FM, vous devriez **voir essentiellement un cercle** dans ce graphique.\
De plus, une fréquence différente est "représentée" par le graphique IQ par une **accélération de la vitesse à travers le cercle** (donc dans SysDigger en sélectionnant le signal, le graphique IQ est peuplé, si vous trouvez une accélération ou un changement de direction dans le cercle créé, cela pourrait signifier que c'est FM) :

![](<../../.gitbook/assets/image (643) (1).png>)

### Obtenir le taux de symboles

Vous pouvez utiliser la **même technique que celle utilisée dans l'exemple AM** pour obtenir le taux de symboles une fois que vous avez trouvé les fréquences portant les symboles.

### Obtenir les bits

Vous pouvez utiliser la **même technique que celle utilisée dans l'exemple AM** pour obtenir les bits une fois que vous avez **trouvé que le signal est modulé en fréquence** et le **taux de symboles**.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https
