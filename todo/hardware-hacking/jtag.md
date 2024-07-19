# JTAG

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum) est un outil qui peut être utilisé avec un Raspberry PI ou un Arduino pour essayer de trouver les broches JTAG d'une puce inconnue.\
Dans l'**Arduino**, connectez les **broches de 2 à 11 à 10 broches potentiellement appartenant à un JTAG**. Chargez le programme dans l'Arduino et il essaiera de brute-forcer toutes les broches pour déterminer si l'une d'elles appartient à JTAG et laquelle est laquelle.\
Dans le **Raspberry PI**, vous ne pouvez utiliser que **les broches de 1 à 6** (6 broches, donc vous avancerez plus lentement en testant chaque broche JTAG potentielle).

### Arduino

Dans Arduino, après avoir connecté les câbles (broche 2 à 11 aux broches JTAG et GND Arduino à GND de la carte de base), **chargez le programme JTAGenum dans Arduino** et dans le Moniteur Série, envoyez un **`h`** (commande d'aide) et vous devriez voir l'aide :

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

Configurez **"Pas de fin de ligne" et 115200baud**.\
Envoyez la commande s pour commencer le scan :

![](<../../.gitbook/assets/image (774).png>)

Si vous êtes en contact avec un JTAG, vous trouverez une ou plusieurs **lignes commençant par FOUND!** indiquant les broches de JTAG.

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
