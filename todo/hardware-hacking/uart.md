# Informations de base

UART est un protocole série, ce qui signifie qu'il transfère des données entre les composants un bit à la fois. En revanche, les protocoles de communication parallèles transmettent des données simultanément via plusieurs canaux. Les protocoles série courants comprennent RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express et USB.

Généralement, la ligne est maintenue haute (à une valeur logique 1) pendant que UART est à l'état inactif. Ensuite, pour signaler le début d'un transfert de données, l'émetteur envoie un bit de départ au récepteur, pendant lequel le signal est maintenu bas (à une valeur logique 0). Ensuite, l'émetteur envoie cinq à huit bits de données contenant le message réel, suivis d'un bit de parité facultatif et d'un ou deux bits d'arrêt (avec une valeur logique 1), selon la configuration. Le bit de parité, utilisé pour la vérification des erreurs, est rarement vu en pratique. Le bit d'arrêt (ou les bits) signifient la fin de la transmission.

Nous appelons la configuration la plus courante 8N1 : huit bits de données, pas de parité et un bit d'arrêt. Par exemple, si nous voulions envoyer le caractère C, ou 0x43 en ASCII, dans une configuration UART 8N1, nous enverrions les bits suivants : 0 (le bit de départ) ; 0, 1, 0, 0, 0, 0, 1, 1 (la valeur de 0x43 en binaire), et 0 (le bit d'arrêt).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Outils matériels pour communiquer avec UART :

* Adaptateur USB vers série
* Adaptateurs avec les puces CP2102 ou PL2303
* Outil polyvalent tel que : Bus Pirate, Adafruit FT232H, Shikra ou Attify Badge

## Identification des ports UART

UART a 4 ports : **TX** (Transmettre), **RX** (Recevoir), **Vcc** (Tension) et **GND** (Masse). Vous pourriez être en mesure de trouver 4 ports avec les lettres **`TX`** et **`RX`** **écrites** sur le PCB. Mais s'il n'y a pas d'indication, vous devrez peut-être essayer de les trouver vous-même à l'aide d'un **multimètre** ou d'un **analyseur logique**.

Avec un **multimètre** et l'appareil éteint :

* Pour identifier la broche **GND**, utilisez le mode **Test de continuité**, placez la sonde arrière dans la masse et testez avec la sonde rouge jusqu'à ce que vous entendiez un son provenant du multimètre. Plusieurs broches GND peuvent être trouvées sur le PCB, vous avez donc peut-être trouvé ou non celle appartenant à UART.
* Pour identifier le port **VCC**, réglez le mode **tension continue** et réglez-le jusqu'à 20 V de tension. Sonde noire sur la masse et sonde rouge sur la broche. Allumez l'appareil. Si le multimètre mesure une tension constante de 3,3 V ou 5 V, vous avez trouvé la broche Vcc. Si vous obtenez d'autres tensions, réessayez avec d'autres ports.
* Pour identifier le port **TX**, mode **tension continue** jusqu'à 20 V de tension, sonde noire sur la masse et sonde rouge sur la broche, et allumez l'appareil. Si vous trouvez que la tension fluctue pendant quelques secondes puis se stabilise à la valeur Vcc, vous avez probablement trouvé le port TX. C'est parce que lors de la mise sous tension, il envoie des données de débogage.
* Le **port RX** serait le plus proche des trois autres, il a la plus faible fluctuation de tension et la valeur globale la plus faible de toutes les broches UART.

Vous pouvez confondre les ports TX et RX et rien ne se passera, mais si vous confondez la broche GND et la broche VCC, vous pourriez endommager le circuit.

Avec un analyseur logique :

## Identification du débit binaire UART

La façon la plus simple d'identifier le débit binaire correct est de regarder la sortie de la broche **TX et d'essayer de lire les données**. Si les données que vous recevez ne sont pas lisibles, passez au débit binaire possible suivant jusqu'à ce que les données deviennent lisibles. Vous pouvez utiliser un adaptateur USB vers série ou un appareil polyvalent comme Bus Pirate pour cela, associé à un script d'aide, tel que [baudrate.py](https://github.com/devttys0/baudrate/). Les débits binaires les plus courants sont 9600, 38400, 19200, 57600 et 115200.

{% hint style="danger" %}
Il est important de noter que dans ce protocole, vous devez connecter le TX d'un appareil au RX de l'autre !
{% endhint %}

# Bus Pirate

Dans ce scénario, nous allons intercepter la communication UART de l'Arduino qui envoie toutes les impressions du programme au moniteur série.
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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
