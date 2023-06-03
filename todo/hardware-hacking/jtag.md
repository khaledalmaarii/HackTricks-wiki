# JTAGenum

[JTAGenum](https://github.com/cyphunk/JTAGenum) est un outil qui peut être utilisé avec un Raspberry PI ou un Arduino pour essayer les broches JTAG d'une puce inconnue.\
Dans l'**Arduino**, connectez les **broches de 2 à 11 à 10 broches potentiellement appartenant à un JTAG**. Chargez le programme dans l'Arduino et il essaiera de forcer toutes les broches pour trouver si l'une d'entre elles appartient à JTAG et laquelle est chaque broche.\
Dans le **Raspberry PI**, vous ne pouvez utiliser que les **broches de 1 à 6** (6 broches, vous testerez donc plus lentement chaque broche JTAG potentielle).

## Arduino

Dans Arduino, après avoir connecté les câbles (broche 2 à 11 aux broches JTAG et Arduino GND à la base), **chargez le programme JTAGenum dans Arduino** et dans le Moniteur série envoyez un **`h`** (commande pour obtenir de l'aide) et vous devriez voir l'aide :

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

Configurez **"No line ending" et 115200baud**.\
Envoyez la commande s pour commencer le balayage :

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

Si vous êtes en contact avec un JTAG, vous trouverez une ou plusieurs **lignes commençant par FOUND!** indiquant les broches de JTAG.
