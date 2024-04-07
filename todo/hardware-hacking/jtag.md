# JTAG

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)est un outil qui peut être utilisé avec un Raspberry PI ou un Arduino pour essayer de trouver les broches JTAG d'une puce inconnue.\
Dans l'**Arduino**, connectez les **broches de 2 à 11 aux 10 broches potentiellement appartenant à un JTAG**. Chargez le programme dans l'Arduino et il essaiera de forcer toutes les broches pour trouver si l'une d'entre elles appartient au JTAG et laquelle est chaque.\
Dans le **Raspberry PI**, vous ne pouvez utiliser que les **broches de 1 à 6** (6 broches, vous irez donc plus lentement en testant chaque broche JTAG potentielle).

### Arduino

Dans Arduino, après avoir connecté les câbles (broche 2 à 11 aux broches JTAG et GND de l'Arduino à la GND de la carte mère), **chargez le programme JTAGenum dans l'Arduino** et dans le Moniteur série envoyez un **`h`** (commande pour obtenir de l'aide) et vous devriez voir l'aide :

![](<../../.gitbook/assets/image (936).png>)

![](<../../.gitbook/assets/image (575).png>)

Configurez **"Aucune fin de ligne" et 115200 bauds**.\
Envoyez la commande s pour commencer le balayage :

![](<../../.gitbook/assets/image (771).png>)

Si vous contactez un JTAG, vous trouverez une ou plusieurs **lignes commençant par TROUVÉ !** indiquant les broches du JTAG.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
