# Proxmark 3

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Groupe de sécurité Try Hard**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Attaquer les systèmes RFID avec Proxmark3

La première chose à faire est d'avoir un [**Proxmark3**](https://proxmark.com) et [**d'installer le logiciel et ses dépendances**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Attaquer les systèmes MIFARE Classic 1KB

Il a **16 secteurs**, chacun ayant **4 blocs** et chaque bloc contient **16B**. L'UID se trouve dans le secteur 0 bloc 0 (et ne peut pas être modifié).\
Pour accéder à chaque secteur, vous avez besoin de **2 clés** (**A** et **B**) qui sont stockées dans **le bloc 3 de chaque secteur** (secteur de verrouillage). Le secteur de verrouillage stocke également les **bits d'accès** qui donnent les permissions de **lecture et d'écriture** sur **chaque bloc** en utilisant les 2 clés.\
2 clés sont utiles pour donner des permissions de lecture si vous connaissez la première et d'écriture si vous connaissez la deuxième (par exemple).

Plusieurs attaques peuvent être réalisées
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Le Proxmark3 permet d'effectuer d'autres actions comme **écouter** une **communication Tag à Lecteur** pour essayer de trouver des données sensibles. Sur cette carte, vous pourriez simplement écouter la communication et calculer la clé utilisée car les **opérations cryptographiques utilisées sont faibles** et en connaissant le texte en clair et le texte chiffré, vous pouvez le calculer (outil `mfkey64`).

### Commandes Brutes

Les systèmes IoT utilisent parfois des **étiquettes non marquées ou non commerciales**. Dans ce cas, vous pouvez utiliser le Proxmark3 pour envoyer des **commandes brutes personnalisées aux étiquettes**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Avec ces informations, vous pourriez essayer de rechercher des informations sur la carte et sur la manière de communiquer avec elle. Proxmark3 permet d'envoyer des commandes brutes comme: `hf 14a raw -p -b 7 26`

### Scripts

Le logiciel Proxmark3 est livré avec une liste préchargée de **scripts d'automatisation** que vous pouvez utiliser pour effectuer des tâches simples. Pour récupérer la liste complète, utilisez la commande `script list`. Ensuite, utilisez la commande `script run`, suivie du nom du script:
```
proxmark3> script run mfkeys
```
Vous pouvez créer un script pour **fuzzer les lecteurs de tags**, en copiant les données d'une **carte valide**, il suffit d'écrire un **script Lua** qui **randomise** un ou plusieurs **octets aléatoires** et de vérifier si le **lecteur plante** avec chaque itération.

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Vous souhaitez voir votre **entreprise annoncée dans HackTricks**? ou souhaitez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
