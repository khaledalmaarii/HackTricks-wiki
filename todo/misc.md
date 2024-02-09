<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


Dans une réponse ping TTL :\
127 = Windows\
254 = Cisco\
Le reste, un peu de Linux

$1$- md5\
$2$ou $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Si vous ne savez pas ce qui se cache derrière un service, essayez de faire une requête HTTP GET.

**Scans UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Un paquet UDP vide est envoyé à un port spécifique. Si le port UDP est ouvert, aucune réponse n'est renvoyée par la machine cible. Si le port UDP est fermé, un paquet ICMP de port inaccessible devrait être renvoyé par la machine cible.\

Le balayage de ports UDP est souvent peu fiable, car les pare-feu et les routeurs peuvent rejeter les paquets ICMP. Cela peut entraîner des faux positifs dans votre analyse, et vous verrez régulièrement des balayages de ports UDP montrant tous les ports UDP ouverts sur une machine scannée.\
o La plupart des scanners de ports ne scannent pas tous les ports disponibles, et ont généralement une liste prédéfinie de "ports intéressants" qui sont scannés.

# CTF - Astuces

Dans **Windows**, utilisez **Winzip** pour rechercher des fichiers.\
**Flux de données alternatifs** : _dir /r | find ":$DATA"_
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\

**Base64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Commence par "_begin \<mode> \<filename>_" et des caractères bizarres\
**Xxencoding** --> Commence par "_begin \<mode> \<filename>_" et B64\
\
**Vigenere** (analyse de fréquence) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (décalage des caractères) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Cacher des messages en utilisant des espaces et des tabulations

# Characters

%E2%80%AE => Caractère RTL (écrit les charges utiles à l'envers)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
