# UART

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **logiciels malveillants voleurs**.

Le but principal de WhiteIntel est de lutter contre les prises de contrôle de compte et les attaques de ransomware résultant de logiciels malveillants volant des informations.

Vous pouvez consulter leur site Web et essayer leur moteur **gratuitement** sur :

{% embed url="https://whiteintel.io" %}

---

## Informations de base

UART est un protocole série, ce qui signifie qu'il transfère des données entre les composants un bit à la fois. En revanche, les protocoles de communication parallèle transmettent des données simultanément via plusieurs canaux. Les protocoles série courants incluent RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express et USB.

Généralement, la ligne est maintenue haute (à une valeur logique 1) lorsque l'UART est à l'état inactif. Ensuite, pour signaler le début d'un transfert de données, l'émetteur envoie un bit de démarrage au récepteur, pendant lequel le signal est maintenu bas (à une valeur logique 0). Ensuite, l'émetteur envoie cinq à huit bits de données contenant le message réel, suivi éventuellement d'un bit de parité et d'un ou deux bits d'arrêt (avec une valeur logique 1), selon la configuration. Le bit de parité, utilisé pour la vérification des erreurs, est rarement vu en pratique. Le bit d'arrêt (ou les bits) signifient la fin de la transmission.

Nous appelons la configuration la plus courante 8N1 : huit bits de données, pas de parité et un bit d'arrêt. Par exemple, si nous voulions envoyer le caractère C, ou 0x43 en ASCII, dans une configuration UART 8N1, nous enverrions les bits suivants : 0 (le bit de démarrage) ; 0, 1, 0, 0, 0, 0, 1, 1 (la valeur de 0x43 en binaire), et 0 (le bit d'arrêt).

![](<../../.gitbook/assets/image (761).png>)

Outils matériels pour communiquer avec UART :

* Adaptateur USB vers série
* Adaptateurs avec les puces CP2102 ou PL2303
* Outil polyvalent tel que : Bus Pirate, l'Adafruit FT232H, le Shikra ou le badge Attify

### Identification des ports UART

UART a 4 ports : **TX** (Transmettre), **RX** (Recevoir), **Vcc** (Tension) et **GND** (Masse). Vous pourriez trouver 4 ports avec les lettres **`TX`** et **`RX`** **écrites** sur le PCB. Mais s'il n'y a pas d'indication, vous pourriez devoir essayer de les trouver vous-même en utilisant un **multimètre** ou un **analyseur logique**.

Avec un **multimètre** et l'appareil éteint :

* Pour identifier la broche **GND**, utilisez le mode **Test de continuité**, placez la sonde noire dans la masse et testez avec la sonde rouge jusqu'à ce que vous entendiez un son du multimètre. Plusieurs broches GND peuvent être trouvées sur le PCB, donc vous pourriez avoir trouvé ou non celle appartenant à l'UART.
* Pour identifier la broche **VCC**, réglez le mode **tension continue** et réglez-le sur 20 V de tension. Sonde noire sur la masse et sonde rouge sur la broche. Allumez l'appareil. Si le multimètre mesure une tension constante de 3,3 V ou 5 V, vous avez trouvé la broche Vcc. Si vous obtenez d'autres tensions, réessayez avec d'autres ports.
* Pour identifier la broche **TX**, mode **tension continue** jusqu'à 20 V de tension, sonde noire sur la masse et sonde rouge sur la broche, et allumez l'appareil. Si vous trouvez que la tension fluctue pendant quelques secondes puis se stabilise à la valeur Vcc, vous avez probablement trouvé la broche TX. C'est parce que lors de la mise sous tension, il envoie quelques données de débogage.
* La **broche RX** serait la plus proche des 3 autres, elle a la plus faible fluctuation de tension et la valeur globale la plus basse de toutes les broches UART.

Vous pouvez confondre les broches TX et RX et rien ne se passera, mais si vous confondez la broche GND et la broche VCC, vous pourriez endommager le circuit.

Dans certains appareils cibles, le port UART est désactivé par le fabricant en désactivant RX ou TX ou même les deux. Dans ce cas, il peut être utile de retracer les connexions sur la carte de circuit imprimé et de trouver un point de rupture. Un indice fort confirmant l'absence de détection de l'UART et la rupture du circuit est de vérifier la garantie de l'appareil. Si l'appareil a été expédié avec une garantie, le fabricant laisse quelques interfaces de débogage (dans ce cas, UART) et a donc dû déconnecter l'UART et le reconnecter lors du débogage. Ces broches de rupture peuvent être connectées par soudure ou fils de cavalier.

### Identification du débit binaire UART

La manière la plus simple d'identifier le débit binaire correct est d'examiner la **sortie de la broche TX et d'essayer de lire les données**. Si les données que vous recevez ne sont pas lisibles, passez au débit binaire possible suivant jusqu'à ce que les données deviennent lisibles. Vous pouvez utiliser un adaptateur USB vers série ou un appareil polyvalent comme Bus Pirate pour cela, associé à un script d'aide, tel que [baudrate.py](https://github.com/devttys0/baudrate/). Les débits binaires les plus courants sont 9600, 38400, 19200, 57600 et 115200.

{% hint style="danger" %}
Il est important de noter que dans ce protocole, vous devez connecter le TX d'un appareil au RX de l'autre !
{% endhint %}

## Adaptateur CP210X UART vers TTY

La puce CP210X est utilisée dans de nombreuses cartes de prototypage comme NodeMCU (avec esp8266) pour la communication série. Ces adaptateurs sont relativement peu coûteux et peuvent être utilisés pour se connecter à l'interface UART de la cible. L'appareil a 5 broches : 5V, GND, RXD, TXD, 3.3V. Assurez-vous de connecter la tension prise en charge par la cible pour éviter tout dommage. Enfin, connectez la broche RXD de l'adaptateur à TXD de la cible et la broche TXD de l'adaptateur à RXD de la cible.

Si l'adaptateur n'est pas détecté, assurez-vous que les pilotes CP210X sont installés dans le système hôte. Une fois l'adaptateur détecté et connecté, des outils comme picocom, minicom ou screen peuvent être utilisés.

Pour répertorier les appareils connectés aux systèmes Linux/MacOS :
```
ls /dev/
```
Pour une interaction de base avec l'interface UART, utilisez la commande suivante :
```
picocom /dev/<adapter> --baud <baudrate>
```
Pour minicom, utilisez la commande suivante pour le configurer :
```
minicom -s
```
Configurez les paramètres tels que le débit en bauds et le nom du périphérique dans l'option `Configuration du port série`.

Après la configuration, utilisez la commande `minicom` pour démarrer la console UART.

## UART Via Arduino UNO R3 (Cartes à puce Atmel 328p amovibles)

Si les adaptateurs UART Serial vers USB ne sont pas disponibles, l'Arduino UNO R3 peut être utilisé avec une astuce rapide. Comme l'Arduino UNO R3 est généralement disponible partout, cela peut faire gagner beaucoup de temps.

L'Arduino UNO R3 possède un adaptateur USB vers série intégré sur la carte elle-même. Pour obtenir une connexion UART, il suffit de retirer la puce microcontrôleur Atmel 328p de la carte. Cette astuce fonctionne sur les variantes de l'Arduino UNO R3 ayant l'Atmel 328p non soudé sur la carte (la version CMS est utilisée). Connectez la broche RX de l'Arduino (Broche numérique 0) à la broche TX de l'interface UART et la broche TX de l'Arduino (Broche numérique 1) à la broche RX de l'interface UART.

Enfin, il est recommandé d'utiliser l'IDE Arduino pour obtenir la console série. Dans la section `outils` du menu, sélectionnez l'option `Console série` et définissez le débit en bauds selon l'interface UART.

## Bus Pirate

Dans ce scénario, nous allons intercepter la communication UART de l'Arduino qui envoie toutes les impressions du programme au Moniteur série.
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## Extraction de Firmware avec la Console UART

La console UART offre un excellent moyen de travailler avec le firmware sous-jacent dans l'environnement d'exécution. Cependant, lorsque l'accès à la console UART est en lecture seule, cela peut introduire de nombreuses contraintes. Dans de nombreux appareils embarqués, le firmware est stocké dans des EEPROM et exécuté dans des processeurs ayant une mémoire volatile. Par conséquent, le firmware est conservé en lecture seule car le firmware d'origine lors de la fabrication se trouve à l'intérieur de l'EEPROM lui-même et tout nouveau fichier serait perdu en raison de la mémoire volatile. Ainsi, l'extraction du firmware est un effort précieux lors du travail avec des firmwares embarqués.

Il existe de nombreuses façons de le faire et la section SPI couvre les méthodes pour extraire le firmware directement de l'EEPROM avec divers appareils. Bien qu'il soit recommandé d'essayer d'abord d'extraire le firmware avec UART, car extraire le firmware avec des appareils physiques et des interactions externes peut être risqué.

L'extraction du firmware à partir de la console UART nécessite d'abord d'accéder aux chargeurs d'amorçage. De nombreux fabricants populaires utilisent <b>uboot</b> (Universal Bootloader) comme chargeur d'amorçage pour charger Linux. Par conséquent, il est nécessaire d'accéder à <b>uboot</b>.

Pour accéder au chargeur d'amorçage <b>boot</b>, connectez le port UART à l'ordinateur et utilisez l'un des outils de console série tout en maintenant l'alimentation du dispositif déconnectée. Une fois la configuration prête, appuyez sur la touche Entrée et maintenez-la enfoncée. Enfin, connectez l'alimentation au dispositif et laissez-le démarrer.

Cela interrompra le chargement de <b>uboot</b> et affichera un menu. Il est recommandé de comprendre les commandes <b>uboot</b> et d'utiliser le menu d'aide pour les répertorier. Il pourrait s'agir de la commande `help`. Comme différents fabricants utilisent différentes configurations, il est nécessaire de les comprendre séparément.

Généralement, la commande pour extraire le firmware est :
```
md
```
qui signifie "dump de mémoire". Cela va vider la mémoire (contenu de l'EEPROM) sur l'écran. Il est recommandé de journaliser la sortie de la console série avant de commencer la procédure pour capturer le dump de mémoire.

Enfin, supprimez simplement toutes les données inutiles du fichier journal et enregistrez le fichier sous le nom `nomfichier.rom` et utilisez binwalk pour extraire le contenu:
```
binwalk -e <filename.rom>
```
Cela listera les contenus possibles de l'EEPROM selon les signatures trouvées dans le fichier hexadécimal.

Cependant, il est nécessaire de noter que ce n'est pas toujours le cas que le <b>uboot</b> soit déverrouillé même s'il est utilisé. Si la touche Entrée ne fait rien, vérifiez les différentes touches comme la touche Espace, etc. Si le chargeur d'amorçage est verrouillé et n'est pas interrompu, cette méthode ne fonctionnerait pas. Pour vérifier si <b>uboot</b> est le chargeur d'amorçage du périphérique, vérifiez la sortie sur la console UART lors du démarrage du périphérique. Il pourrait mentionner <b>uboot</b> lors du démarrage.


## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **logiciels malveillants voleurs**.

Leur objectif principal est de lutter contre les prises de contrôle de compte et les attaques de ransomware résultant de logiciels malveillants volant des informations.

Vous pouvez consulter leur site Web et essayer leur moteur **gratuitement** sur :

{% embed url="https://whiteintel.io" %}


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
