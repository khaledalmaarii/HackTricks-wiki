# Radio

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)est un analyseur de signal numérique gratuit pour GNU/Linux et macOS, conçu pour extraire des informations de signaux radio inconnus. Il prend en charge une variété de dispositifs SDR via SoapySDR, et permet une démodulation ajustable des signaux FSK, PSK et ASK, décode la vidéo analogique, analyse les signaux bursty et écoute les canaux vocaux analogiques (tout en temps réel).

### Configuration de base

Après l'installation, il y a quelques éléments que vous pourriez envisager de configurer.\
Dans les paramètres (le deuxième onglet), vous pouvez sélectionner le **dispositif SDR** ou **sélectionner un fichier** à lire et quelle fréquence syntoniser et le taux d'échantillonnage (recommandé jusqu'à 2,56 Msps si votre PC le supporte)\\

![](<../../.gitbook/assets/image (245).png>)

Dans le comportement de l'interface graphique, il est recommandé d'activer quelques éléments si votre PC le supporte :

![](<../../.gitbook/assets/image (472).png>)

{% hint style="info" %}
Si vous réalisez que votre PC ne capture pas les choses, essayez de désactiver OpenGL et de réduire le taux d'échantillonnage.
{% endhint %}

### Utilisations

* Juste pour **capturer un certain temps d'un signal et l'analyser**, maintenez simplement le bouton "Push to capture" aussi longtemps que nécessaire.

![](<../../.gitbook/assets/image (960).png>)

* Le **Tuner** de SigDigger aide à **capturer de meilleurs signaux** (mais cela peut aussi les dégrader). Idéalement, commencez à 0 et continuez à **l'augmenter jusqu'à** ce que vous trouviez que le **bruit** introduit est **plus grand** que l'**amélioration du signal** dont vous avez besoin).

![](<../../.gitbook/assets/image (1099).png>)

### Synchroniser avec le canal radio

Avec [**SigDigger** ](https://github.com/BatchDrake/SigDigger), synchronisez-vous avec le canal que vous souhaitez entendre, configurez l'option "Aperçu audio de bande de base", configurez la bande passante pour obtenir toutes les informations envoyées, puis réglez le Tuner au niveau avant que le bruit ne commence vraiment à augmenter :

![](<../../.gitbook/assets/image (585).png>)

## Astuces intéressantes

* Lorsqu'un appareil envoie des rafales d'informations, généralement la **première partie sera un préambule**, donc vous **n'avez pas** besoin de **vous inquiéter** si vous **ne trouvez pas d'informations** là-dedans **ou s'il y a des erreurs**.
* Dans les trames d'informations, vous devriez généralement **trouver différentes trames bien alignées entre elles** :

![](<../../.gitbook/assets/image (1076).png>)

![](<../../.gitbook/assets/image (597).png>)

* **Après avoir récupéré les bits, vous devrez peut-être les traiter d'une certaine manière**. Par exemple, dans la codification Manchester, un up+down sera un 1 ou 0 et un down+up sera l'autre. Ainsi, des paires de 1s et 0s (ups et downs) seront un vrai 1 ou un vrai 0.
* Même si un signal utilise la codification Manchester (il est impossible de trouver plus de deux 0s ou 1s consécutifs), vous pourriez **trouver plusieurs 1s ou 0s ensemble dans le préambule** !

### Découverte du type de modulation avec IQ

Il existe 3 façons de stocker des informations dans des signaux : moduler l'**amplitude**, la **fréquence** ou la **phase**.\
Si vous vérifiez un signal, il existe différentes façons d'essayer de déterminer ce qui est utilisé pour stocker des informations (trouvez plus de façons ci-dessous), mais une bonne méthode est de vérifier le graphique IQ.

![](<../../.gitbook/assets/image (788).png>)

* **Détection AM** : Si dans le graphique IQ apparaissent par exemple **2 cercles** (probablement un à 0 et l'autre à une amplitude différente), cela pourrait signifier qu'il s'agit d'un signal AM. Cela est dû au fait que dans le graphique IQ, la distance entre le 0 et le cercle est l'amplitude du signal, donc il est facile de visualiser différentes amplitudes utilisées.
* **Détection PM** : Comme dans l'image précédente, si vous trouvez de petits cercles non liés entre eux, cela signifie probablement qu'une modulation de phase est utilisée. Cela est dû au fait que dans le graphique IQ, l'angle entre le point et le 0,0 est la phase du signal, ce qui signifie que 4 phases différentes sont utilisées.
* Notez que si l'information est cachée dans le fait qu'une phase est changée et non dans la phase elle-même, vous ne verrez pas différentes phases clairement différenciées.
* **Détection FM** : IQ n'a pas de champ pour identifier les fréquences (la distance au centre est l'amplitude et l'angle est la phase).\
Par conséquent, pour identifier FM, vous devriez **voir essentiellement un cercle** dans ce graphique.\
De plus, une fréquence différente est "représentée" par le graphique IQ par une **accélération de vitesse à travers le cercle** (donc dans SysDigger, en sélectionnant le signal, le graphique IQ est peuplé, si vous trouvez une accélération ou un changement de direction dans le cercle créé, cela pourrait signifier qu'il s'agit de FM) :

## Exemple AM

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Découverte de l'AM

#### Vérification de l'enveloppe

Vérifiant les informations AM avec [**SigDigger** ](https://github.com/BatchDrake/SigDigger) et en regardant simplement l'**enveloppe**, vous pouvez voir différents niveaux d'amplitude clairs. Le signal utilisé envoie des impulsions avec des informations en AM, voici à quoi ressemble une impulsion :

![](<../../.gitbook/assets/image (590).png>)

Et voici à quoi ressemble une partie du symbole avec la forme d'onde :

![](<../../.gitbook/assets/image (734).png>)

#### Vérification de l'histogramme

Vous pouvez **sélectionner l'ensemble du signal** où les informations sont situées, sélectionner le mode **Amplitude** et **Sélection** et cliquer sur **Histogramme**. Vous pouvez observer que 2 niveaux clairs ne sont trouvés que

![](<../../.gitbook/assets/image (264).png>)

Par exemple, si vous sélectionnez la Fréquence au lieu de l'Amplitude dans ce signal AM, vous ne trouvez qu'une seule fréquence (aucune information modulée en fréquence n'utilise juste 1 fréquence).

![](<../../.gitbook/assets/image (732).png>)

Si vous trouvez beaucoup de fréquences, cela ne sera probablement pas une FM, probablement la fréquence du signal a juste été modifiée à cause du canal.

#### Avec IQ

Dans cet exemple, vous pouvez voir comment il y a un **grand cercle** mais aussi **beaucoup de points au centre.**

![](<../../.gitbook/assets/image (222).png>)

### Obtenir le taux de symbole

#### Avec un symbole

Sélectionnez le plus petit symbole que vous pouvez trouver (pour être sûr qu'il s'agit juste de 1) et vérifiez la "Fréquence de sélection". Dans ce cas, ce serait 1,013 kHz (donc 1 kHz).

![](<../../.gitbook/assets/image (78).png>)

#### Avec un groupe de symboles

Vous pouvez également indiquer le nombre de symboles que vous allez sélectionner et SigDigger calculera la fréquence d'un symbole (plus de symboles sélectionnés, mieux c'est probablement). Dans ce scénario, j'ai sélectionné 10 symboles et la "Fréquence de sélection" est de 1,004 kHz :

![](<../../.gitbook/assets/image (1008).png>)

### Obtenir des bits

Ayant trouvé qu'il s'agit d'un signal **modulé AM** et du **taux de symbole** (et sachant que dans ce cas quelque chose en haut signifie 1 et quelque chose en bas signifie 0), il est très facile d'**obtenir les bits** encodés dans le signal. Donc, sélectionnez le signal avec des informations et configurez l'échantillonnage et la décision et appuyez sur échantillon (vérifiez que **l'Amplitude** est sélectionnée, le **taux de symbole** découvert est configuré et la **récupération d'horloge Gadner** est sélectionnée) :

![](<../../.gitbook/assets/image (965).png>)

* **Synchroniser aux intervalles de sélection** signifie que si vous avez précédemment sélectionné des intervalles pour trouver le taux de symbole, ce taux de symbole sera utilisé.
* **Manuel** signifie que le taux de symbole indiqué sera utilisé.
* Dans **Sélection d'intervalle fixe**, vous indiquez le nombre d'intervalles qui doivent être sélectionnés et il calcule le taux de symbole à partir de cela.
* **La récupération d'horloge Gadner** est généralement la meilleure option, mais vous devez encore indiquer un taux de symbole approximatif.

En appuyant sur échantillon, cela apparaît :

![](<../../.gitbook/assets/image (644).png>)

Maintenant, pour faire comprendre à SigDigger **où se trouve la plage** du niveau portant des informations, vous devez cliquer sur le **niveau inférieur** et maintenir cliqué jusqu'au plus grand niveau :

![](<../../.gitbook/assets/image (439).png>)

S'il y avait par exemple **4 niveaux d'amplitude différents**, vous devriez avoir besoin de configurer les **Bits par symbole à 2** et sélectionner du plus petit au plus grand.

Enfin, **en augmentant** le **Zoom** et **en changeant la taille de la ligne**, vous pouvez voir les bits (et vous pouvez tout sélectionner et copier pour obtenir tous les bits) :

![](<../../.gitbook/assets/image (276).png>)

Si le signal a plus d'1 bit par symbole (par exemple 2), SigDigger n'a **aucune façon de savoir quel symbole est** 00, 01, 10, 11, donc il utilisera différentes **échelles de gris** pour représenter chacun (et si vous copiez les bits, il utilisera **des nombres de 0 à 3**, vous devrez les traiter).

De plus, utilisez des **codifications** telles que **Manchester**, et **up+down** peut être **1 ou 0** et un down+up peut être un 1 ou 0. Dans ces cas, vous devez **traiter les ups (1) et downs (0) obtenus** pour substituer les paires de 01 ou 10 par des 0s ou 1s.

## Exemple FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Découverte de la FM

#### Vérification des fréquences et de la forme d'onde

Exemple de signal envoyant des informations modulées en FM :

![](<../../.gitbook/assets/image (725).png>)

Dans l'image précédente, vous pouvez observer assez bien que **2 fréquences sont utilisées**, mais si vous **observez** la **forme d'onde**, vous pourriez **ne pas être en mesure d'identifier correctement les 2 fréquences différentes** :

![](<../../.gitbook/assets/image (717).png>)

C'est parce que j'ai capturé le signal dans les deux fréquences, donc l'une est approximativement l'autre en négatif :

![](<../../.gitbook/assets/image (942).png>)

Si la fréquence synchronisée est **plus proche d'une fréquence que de l'autre**, vous pouvez facilement voir les 2 fréquences différentes :

![](<../../.gitbook/assets/image (422).png>)

![](<../../.gitbook/assets/image (488).png>)

#### Vérification de l'histogramme

En vérifiant l'histogramme de fréquence du signal avec des informations, vous pouvez facilement voir 2 signaux différents :

![](<../../.gitbook/assets/image (871).png>)

Dans ce cas, si vous vérifiez l'**histogramme d'Amplitude**, vous ne trouverez **qu'une seule amplitude**, donc cela **ne peut pas être de l'AM** (si vous trouvez beaucoup d'amplitudes, cela pourrait être parce que le signal a perdu de la puissance le long du canal) :

![](<../../.gitbook/assets/image (817).png>)

Et cela serait l'histogramme de phase (ce qui rend très clair que le signal n'est pas modulé en phase) :

![](<../../.gitbook/assets/image (996).png>)

#### Avec IQ

IQ n'a pas de champ pour identifier les fréquences (la distance au centre est l'amplitude et l'angle est la phase).\
Par conséquent, pour identifier FM, vous devriez **voir essentiellement un cercle** dans ce graphique.\
De plus, une fréquence différente est "représentée" par le graphique IQ par une **accélération de vitesse à travers le cercle** (donc dans SysDigger, en sélectionnant le signal, le graphique IQ est peuplé, si vous trouvez une accélération ou un changement de direction dans le cercle créé, cela pourrait signifier qu'il s'agit de FM) :

![](<../../.gitbook/assets/image (81).png>)

### Obtenir le taux de symbole

Vous pouvez utiliser la **même technique que celle utilisée dans l'exemple AM** pour obtenir le taux de symbole une fois que vous avez trouvé les fréquences portant des symboles.

### Obtenir des bits

Vous pouvez utiliser la **même technique que celle utilisée dans l'exemple AM** pour obtenir les bits une fois que vous avez **trouvé que le signal est modulé en fréquence** et le **taux de symbole**.

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
