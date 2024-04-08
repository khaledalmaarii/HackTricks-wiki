# SPI

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Informations de base

SPI (Serial Peripheral Interface) est un protocole de communication série synchrone utilisé dans les systèmes embarqués pour la communication à courte distance entre les CI (Circuits Intégrés). Le protocole de communication SPI utilise l'architecture maître-esclave qui est orchestrée par le signal d'horloge et de sélection de puce. Une architecture maître-esclave se compose d'un maître (généralement un microprocesseur) qui gère les périphériques externes tels que les EEPROM, les capteurs, les dispositifs de contrôle, etc. qui sont considérés comme des esclaves.

Plusieurs esclaves peuvent être connectés à un maître mais les esclaves ne peuvent pas communiquer entre eux. Les esclaves sont administrés par deux broches, l'horloge et la sélection de puce. Comme le SPI est un protocole de communication synchrone, les broches d'entrée et de sortie suivent les signaux d'horloge. La sélection de puce est utilisée par le maître pour sélectionner un esclave et interagir avec lui. Lorsque la sélection de puce est haute, le périphérique esclave n'est pas sélectionné tandis que lorsqu'elle est basse, la puce a été sélectionnée et le maître interagirait avec l'esclave.

Les broches MOSI (Master Out, Slave In) et MISO (Master In, Slave Out) sont responsables de l'envoi et de la réception de données. Les données sont envoyées au périphérique esclave via la broche MOSI tandis que la sélection de puce est maintenue basse. Les données d'entrée contiennent des instructions, des adresses mémoire ou des données selon la fiche technique du fournisseur du périphérique esclave. Après une entrée valide, la broche MISO est responsable de la transmission des données vers le maître. Les données de sortie sont envoyées exactement au cycle d'horloge suivant après la fin de l'entrée. Les broches MISO transmettent des données jusqu'à ce que les données soient entièrement transmises ou que le maître définisse la broche de sélection de puce haute (dans ce cas, l'esclave cesserait de transmettre et le maître n'écouterait plus après ce cycle d'horloge).

## Extraction du firmware des EEPROM

L'extraction du firmware peut être utile pour analyser le firmware et trouver des vulnérabilités. Souvent, le firmware n'est pas disponible sur Internet ou est sans importance en raison de divers facteurs tels que le numéro de modèle, la version, etc. Ainsi, extraire le firmware directement du périphérique physique peut être utile pour être spécifique lors de la recherche de menaces.

Obtenir une console série peut être utile, mais il arrive souvent que les fichiers soient en lecture seule. Cela limite l'analyse pour diverses raisons. Par exemple, des outils nécessaires pour envoyer et recevoir des paquets ne seraient pas présents dans le firmware. Ainsi, extraire les binaires pour les rétro-ingénierer n'est pas réalisable. Avoir tout le firmware extrait sur le système et extraire les binaires pour les analyser peut donc être très utile.

De plus, lors du rétro-ingénierie et de l'obtention d'un accès physique aux appareils, l'extraction du firmware peut aider à modifier les fichiers ou à injecter des fichiers malveillants, puis à les reprogrammer dans la mémoire, ce qui pourrait être utile pour implanter une porte dérobée dans l'appareil. Ainsi, de nombreuses possibilités peuvent être débloquées avec l'extraction du firmware.

### Programmeur et lecteur d'EEPROM CH341A

Cet appareil est un outil peu coûteux pour extraire des firmwares des EEPROM et également les reprogrammer avec des fichiers de firmware. Cela a été un choix populaire pour travailler avec les puces BIOS d'ordinateur (qui ne sont que des EEPROM). Cet appareil se connecte via USB et nécessite des outils minimaux pour démarrer. De plus, il accomplit généralement la tâche rapidement, il peut donc être utile pour l'accès aux appareils physiques également.

<img src="../../.gitbook/assets/board_image_ch341a.jpg" alt="drawing" width="400" align="center"/>

Connectez la mémoire EEPROM au programmeur CH341a et branchez l'appareil sur l'ordinateur. Si l'appareil n'est pas détecté, essayez d'installer les pilotes sur l'ordinateur. Assurez-vous également que l'EEPROM est connectée dans la bonne orientation (généralement, placez la broche VCC en orientation inverse du connecteur USB) sinon, le logiciel ne pourra pas détecter la puce. Référez-vous au schéma si nécessaire :

<img src="../../.gitbook/assets/connect_wires_ch341a.jpg" alt="drawing" width="350"/>

<img src="../../.gitbook/assets/eeprom_plugged_ch341a.jpg" alt="drawing" width="350"/>

Enfin, utilisez des logiciels comme flashrom, G-Flash (GUI), etc. pour extraire le firmware. G-Flash est un outil GUI minimal rapide et détecte automatiquement l'EEPROM. Cela peut être utile si le firmware doit être extrait rapidement, sans trop de bidouillage avec la documentation.

<img src="../../.gitbook/assets/connected_status_ch341a.jpg" alt="drawing" width="350"/>

Après avoir extrait le firmware, l'analyse peut être effectuée sur les fichiers binaires. Des outils comme strings, hexdump, xxd, binwalk, etc. peuvent être utilisés pour extraire de nombreuses informations sur le firmware ainsi que sur l'ensemble du système de fichiers également.

Pour extraire le contenu du firmware, binwalk peut être utilisé. Binwalk analyse les signatures hexadécimales et identifie les fichiers dans le fichier binaire et est capable de les extraire.
```
binwalk -e <filename>
```
Le <filename> peut être .bin ou .rom selon les outils et configurations utilisés.

{% hint style="danger" %} Notez que l'extraction du micrologiciel est un processus délicat et nécessite beaucoup de patience. Toute manipulation incorrecte peut potentiellement corrompre le micrologiciel ou même l'effacer complètement et rendre le dispositif inutilisable. Il est recommandé d'étudier l'appareil spécifique avant de tenter d'extraire le micrologiciel. {% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (907).png>)

Notez que même si le PINOUT du Bus Pirate indique des broches pour **MOSI** et **MISO** à connecter à SPI, cependant certains SPI peuvent indiquer les broches comme DI et DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (357).png>)

Sous Windows ou Linux, vous pouvez utiliser le programme [**`flashrom`**](https://www.flashrom.org/Flashrom) pour sauvegarder le contenu de la mémoire flash en exécutant quelque chose comme :
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge HackTricks AWS)</strong></a><strong>!</strong></summary>

D'autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
