<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) est un outil qui peut être utilisé avec un Raspberry PI ou un Arduino pour essayer de trouver les broches JTAG d'une puce inconnue.\
Sur l'**Arduino**, connectez les **broches de 2 à 11 à 10 broches potentiellement appartenant à un JTAG**. Chargez le programme dans l'Arduino et il essaiera de forcer brutalement toutes les broches pour trouver si des broches appartiennent au JTAG et lesquelles.\
Sur le **Raspberry PI**, vous ne pouvez utiliser que les **broches de 1 à 6** (6 broches, donc vous irez plus lentement pour tester chaque broche JTAG potentielle).

## Arduino

Sur Arduino, après avoir connecté les câbles (broche 2 à 11 aux broches JTAG et GND de l'Arduino au GND de la carte de base), **chargez le programme JTAGenum dans l'Arduino** et dans le moniteur série, envoyez un **`h`** (commande d'aide) et vous devriez voir l'aide :

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

Configurez **"Pas de fin de ligne" et 115200baud**.\
Envoyez la commande s pour commencer l'analyse :

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

Si vous êtes en contact avec un JTAG, vous trouverez une ou plusieurs **lignes commençant par TROUVÉ !** indiquant les broches du JTAG.


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
