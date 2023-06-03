# Radio

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)est un analyseur de signal numérique gratuit pour GNU/Linux et macOS, conçu pour extraire des informations de signaux radio inconnus. Il prend en charge une variété de périphériques SDR via SoapySDR, permet une démodulation ajustable des signaux FSK, PSK et ASK, décode la vidéo analogique, analyse les signaux en rafale et écoute les canaux vocaux analogiques (le tout en temps réel).

### Configuration de base

Après l'installation, il y a quelques choses que vous pourriez considérer configurer.\
Dans les paramètres (le deuxième bouton de l'onglet), vous pouvez sélectionner le **périphérique SDR** ou **sélectionner un fichier** à lire et quelle fréquence syntoniser et le taux d'échantillonnage (recommandé jusqu'à 2,56 Msps si votre PC le supporte)\\

![](<../../.gitbook/assets/image (655) (1).png>)

Dans le comportement de l'interface graphique, il est recommandé d'activer quelques choses si votre PC le supporte :

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
Si vous réalisez que votre PC ne capture pas les choses, essayez de désactiver OpenGL et de baisser le taux d'échantillonnage.
{% endhint %}

### Utilisations

* Juste pour **capturer un certain temps d'un signal et l'analyser**, maintenez simplement le bouton "Push to capture" aussi longtemps que vous en avez besoin.

![](<../../.gitbook/assets/image (631).png>)

* Le **Tuner** de SigDigger aide à **capturer de meilleurs signaux** (mais peut également les dégrader). Idéalement, commencez par 0 et continuez à **l'augmenter jusqu'à** ce que le **bruit** introduit soit **plus grand** que l'**amélioration du signal** dont vous avez besoin).

![](<../../.gitbook/assets/image (658).png>)

### Synchronisation avec le canal radio

Avec [**SigDigger** ](https://github.com/BatchDrake/SigDigger)synchronisez avec le canal que vous voulez entendre, configurez l'option "Baseband audio preview", configurez la bande passante pour obtenir toutes les informations envoyées, puis réglez le Tuner au niveau avant que le bruit ne commence vraiment à augmenter :

![](<../../.gitbook/assets/image (389).png>)

## Astuces intéressantes

* Lorsqu'un appareil envoie des rafales d'informations, généralement la **première partie sera un préambule** donc vous **n'avez pas besoin de vous inquiéter** si vous **ne trouvez pas d'informations** là-dedans **ou s'il y a des erreurs**.
* Dans les trames d'informations, vous devriez **trouver des trames différentes bien alignées entre elles** :

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Après avoir récupéré les bits, vous devrez peut-être les
## Exemple FM

{% file src = "../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Découverte de FM

#### Vérification des fréquences et de la forme d'onde

Exemple de signal envoyant des informations modulées en FM :

![](<../../.gitbook/assets/image (661) (1).png>)

Dans l'image précédente, vous pouvez observer que **2 fréquences sont utilisées**, mais si vous **observez** la **forme d'onde**, vous pourriez **ne pas être en mesure d'identifier correctement les 2 fréquences différentes** :

![](<../../.gitbook/assets/image (653).png>)

Cela est dû au fait que j'ai capturé le signal dans les deux fréquences, donc l'une est approximativement l'autre en négatif :

![](<../../.gitbook/assets/image (656).png>)

Si la fréquence synchronisée est **plus proche d'une fréquence que de l'autre**, vous pouvez facilement voir les 2 fréquences différentes :

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Vérification de l'histogramme

En vérifiant l'histogramme de fréquence du signal avec des informations, vous pouvez facilement voir 2 signaux différents :

![](<../../.gitbook/assets/image (657).png>)

Dans ce cas, si vous vérifiez l'**histogramme d'amplitude**, vous ne trouverez **qu'une seule amplitude**, donc ce **ne peut pas être de l'AM** (si vous trouvez beaucoup d'amplitudes, cela peut être parce que le signal a perdu de la puissance le long du canal) :

![](<../../.gitbook/assets/image (646).png>)

Et voici l'histogramme de phase (qui rend très clair que le signal n'est pas modulé en phase) :

![](<../../.gitbook/assets/image (201) (2).png>)

#### Avec IQ

IQ n'a pas de champ pour identifier les fréquences (la distance au centre est l'amplitude et l'angle est la phase).\
Par conséquent, pour identifier FM, vous devriez **seulement voir essentiellement un cercle** dans ce graphique.\
De plus, une fréquence différente est "représentée" par le graphique IQ par une **accélération de vitesse à travers le cercle** (donc dans SysDigger, en sélectionnant le signal, le graphique IQ est peuplé, si vous trouvez une accélération ou un changement de direction dans le cercle créé, cela pourrait signifier que c'est FM) :

![](<../../.gitbook/assets/image (643) (1).png>)

### Obtenir le taux de symboles

Vous pouvez utiliser la **même technique que celle utilisée dans l'exemple AM** pour obtenir le taux de symboles une fois que vous avez trouvé les fréquences portant des symboles.

### Obtenir des bits

Vous pouvez utiliser la **même technique que celle utilisée dans l'exemple AM** pour obtenir les bits une fois que vous avez **trouvé que le signal est modulé en fréquence** et le **taux de symboles**.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
