# SPI

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informations de base

SPI (Interface Périphérique Série) est un protocole de communication série synchrone utilisé dans les systèmes embarqués pour la communication à courte distance entre les CI (Circuits Intégrés). Le protocole de communication SPI utilise l'architecture maître-esclave qui est orchestrée par le signal d'horloge et de sélection de puce. Une architecture maître-esclave se compose d'un maître (généralement un microprocesseur) qui gère des périphériques externes tels que les EEPROM, les capteurs, les dispositifs de contrôle, etc., qui sont considérés comme des esclaves.

Plusieurs esclaves peuvent être connectés à un maître mais les esclaves ne peuvent pas communiquer entre eux. Les esclaves sont administrés par deux broches, l'horloge et la sélection de puce. Comme la communication SPI est synchrone, les broches d'entrée et de sortie suivent les signaux d'horloge. La sélection de puce est utilisée par le maître pour sélectionner un esclave et interagir avec lui. Lorsque la sélection de puce est haute, le périphérique esclave n'est pas sélectionné, tandis que lorsqu'elle est basse, la puce a été sélectionnée et le maître interagirait avec l'esclave.

Les broches MOSI (Master Out, Slave In) et MISO (Master In, Slave Out) sont responsables de l'envoi et de la réception de données. Les données sont envoyées au périphérique esclave via la broche MOSI tandis que la sélection de puce est maintenue basse. Les données d'entrée contiennent des instructions, des adresses mémoire ou des données selon la fiche technique du fournisseur du périphérique esclave. Après une entrée valide, la broche MISO est responsable de la transmission des données vers le maître. Les données de sortie sont envoyées exactement au cycle d'horloge suivant après la fin de l'entrée. Les broches MISO transmettent des données jusqu'à ce que les données soient entièrement transmises ou que le maître définisse la broche de sélection de puce haute (dans ce cas, l'esclave cesserait de transmettre et le maître n'écouterait plus après ce cycle d'horloge).

## Dump Flash

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (907).png>)

Notez que même si le PINOUT du Pirate Bus indique des broches pour **MOSI** et **MISO** à connecter à SPI, cependant certains SPI peuvent indiquer des broches comme DI et DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (357).png>)

Sur Windows ou Linux, vous pouvez utiliser le programme [**`flashrom`**](https://www.flashrom.org/Flashrom) pour extraire le contenu de la mémoire flash en exécutant quelque chose comme :
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
