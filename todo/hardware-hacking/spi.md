# SPI

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Informations de base

SPI (Serial Peripheral Interface) est un protocole de communication série synchrone utilisé dans les systèmes embarqués pour la communication à courte distance entre les CI (circuits intégrés). Le protocole de communication SPI utilise une architecture maître-esclave orchestrée par le signal d'horloge et le signal de sélection de puce. Une architecture maître-esclave se compose d'un maître (généralement un microprocesseur) qui gère des périphériques externes comme l'EEPROM, des capteurs, des dispositifs de contrôle, etc., qui sont considérés comme des esclaves.

Plusieurs esclaves peuvent être connectés à un maître, mais les esclaves ne peuvent pas communiquer entre eux. Les esclaves sont administrés par deux broches, l'horloge et la sélection de puce. Comme SPI est un protocole de communication synchrone, les broches d'entrée et de sortie suivent les signaux d'horloge. La sélection de puce est utilisée par le maître pour sélectionner un esclave et interagir avec lui. Lorsque la sélection de puce est haute, le dispositif esclave n'est pas sélectionné, tandis que lorsqu'elle est basse, la puce a été sélectionnée et le maître interagira avec l'esclave.

Le MOSI (Master Out, Slave In) et le MISO (Master In, Slave Out) sont responsables de l'envoi et de la réception des données. Les données sont envoyées au dispositif esclave via la broche MOSI pendant que la sélection de puce est maintenue basse. Les données d'entrée contiennent des instructions, des adresses mémoire ou des données selon la fiche technique du fournisseur du dispositif esclave. Lors d'une entrée valide, la broche MISO est responsable de la transmission des données au maître. Les données de sortie sont envoyées exactement au prochain cycle d'horloge après la fin de l'entrée. Les broches MISO transmettent des données jusqu'à ce que les données soient entièrement transmises ou que le maître mette la broche de sélection de puce en haute (dans ce cas, l'esclave cesserait de transmettre et le maître ne écouterait plus après ce cycle d'horloge).

## Dumping du firmware des EEPROM

Le dumping du firmware peut être utile pour analyser le firmware et trouver des vulnérabilités. Souvent, le firmware n'est pas disponible sur Internet ou est sans rapport en raison de variations de facteurs tels que le numéro de modèle, la version, etc. Par conséquent, extraire le firmware directement du dispositif physique peut être utile pour être spécifique lors de la recherche de menaces.

Obtenir une console série peut être utile, mais il arrive souvent que les fichiers soient en lecture seule. Cela limite l'analyse pour diverses raisons. Par exemple, des outils nécessaires pour envoyer et recevoir des paquets ne seraient pas présents dans le firmware. Donc, extraire les binaires pour les rétro-ingénierie n'est pas faisable. Par conséquent, avoir tout le firmware dumpé sur le système et extraire les binaires pour analyse peut être très utile.

De plus, lors de la lecture rouge et de l'accès physique aux dispositifs, le dumping du firmware peut aider à modifier les fichiers ou à injecter des fichiers malveillants, puis à les re-flasher dans la mémoire, ce qui pourrait être utile pour implanter une porte dérobée dans le dispositif. Ainsi, il existe de nombreuses possibilités qui peuvent être débloquées avec le dumping de firmware.

### Programmateur et lecteur EEPROM CH341A

Cet appareil est un outil peu coûteux pour dumper des firmwares des EEPROM et les re-flasher avec des fichiers de firmware. Cela a été un choix populaire pour travailler avec des puces BIOS d'ordinateur (qui ne sont que des EEPROM). Cet appareil se connecte via USB et nécessite peu d'outils pour commencer. De plus, il accomplit généralement la tâche rapidement, ce qui peut également être utile pour l'accès physique au dispositif.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Connectez la mémoire EEPROM avec le programmateur CH341a et branchez l'appareil à l'ordinateur. Si l'appareil n'est pas détecté, essayez d'installer des pilotes sur l'ordinateur. Assurez-vous également que l'EEPROM est connectée dans la bonne orientation (généralement, placez la broche VCC dans l'orientation inverse du connecteur USB), sinon, le logiciel ne pourra pas détecter la puce. Référez-vous au diagramme si nécessaire :

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Enfin, utilisez des logiciels comme flashrom, G-Flash (GUI), etc. pour dumper le firmware. G-Flash est un outil GUI minimal, rapide et détecte automatiquement l'EEPROM. Cela peut être utile si le firmware doit être extrait rapidement, sans trop de modifications de la documentation.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Après avoir dumpé le firmware, l'analyse peut être effectuée sur les fichiers binaires. Des outils comme strings, hexdump, xxd, binwalk, etc. peuvent être utilisés pour extraire beaucoup d'informations sur le firmware ainsi que sur l'ensemble du système de fichiers.

Pour extraire le contenu du firmware, binwalk peut être utilisé. Binwalk analyse les signatures hexadécimales et identifie les fichiers dans le fichier binaire et est capable de les extraire.
```
binwalk -e <filename>
```
Le fichier peut être .bin ou .rom selon les outils et configurations utilisés.

{% hint style="danger" %}
Notez que l'extraction du firmware est un processus délicat et nécessite beaucoup de patience. Toute mauvaise manipulation peut potentiellement corrompre le firmware ou même l'effacer complètement et rendre l'appareil inutilisable. Il est recommandé d'étudier l'appareil spécifique avant d'essayer d'extraire le firmware.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Notez que même si le PINOUT du Bus Pirate indique des broches pour **MOSI** et **MISO** à connecter à SPI, certains SPIs peuvent indiquer des broches comme DI et DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

Sous Windows ou Linux, vous pouvez utiliser le programme [**`flashrom`**](https://www.flashrom.org/Flashrom) pour dumper le contenu de la mémoire flash en exécutant quelque chose comme :
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
