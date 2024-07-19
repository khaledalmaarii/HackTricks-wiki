# FZ - Infrared

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

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Pour plus d'informations sur le fonctionnement de l'infrarouge, consultez :

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Récepteur de signal IR dans Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utilise un récepteur de signal IR numérique TSOP, qui **permet d'intercepter les signaux des télécommandes IR**. Il existe des **smartphones** comme Xiaomi, qui ont également un port IR, mais gardez à l'esprit que **la plupart d'entre eux ne peuvent que transmettre** des signaux et sont **incapables de les recevoir**.

Le récepteur infrarouge de Flipper est **assez sensible**. Vous pouvez même **attraper le signal** tout en restant **quelque part entre** la télécommande et la télévision. Il n'est pas nécessaire de pointer la télécommande directement vers le port IR de Flipper. Cela est pratique lorsque quelqu'un change de chaîne tout en se tenant près de la télévision, et que vous et Flipper êtes à une certaine distance.

Comme le **décodage du signal infrarouge** se fait du côté **logiciel**, Flipper Zero prend potentiellement en charge la **réception et la transmission de tous les codes de télécommande IR**. Dans le cas de protocoles **inconnus** qui ne peuvent pas être reconnus - il **enregistre et rejoue** le signal brut exactement tel qu'il a été reçu.

## Actions

### Télécommandes Universelles

Flipper Zero peut être utilisé comme une **télécommande universelle pour contrôler n'importe quelle télévision, climatiseur ou centre multimédia**. Dans ce mode, Flipper **force par essais** tous les **codes connus** de tous les fabricants pris en charge **selon le dictionnaire de la carte SD**. Vous n'avez pas besoin de choisir une télécommande particulière pour éteindre une télévision de restaurant.

Il suffit d'appuyer sur le bouton d'alimentation en mode Télécommande Universelle, et Flipper **enverra séquentiellement les commandes "Power Off"** de toutes les télévisions qu'il connaît : Sony, Samsung, Panasonic... et ainsi de suite. Lorsque la télévision reçoit son signal, elle réagira et s'éteindra.

Ce type de force brute prend du temps. Plus le dictionnaire est grand, plus cela prendra de temps pour finir. Il est impossible de savoir quel signal exactement la télévision a reconnu puisque il n'y a pas de retour d'information de la télévision.

### Apprendre une Nouvelle Télécommande

Il est possible de **capturer un signal infrarouge** avec Flipper Zero. Si il **trouve le signal dans la base de données**, Flipper saura automatiquement **de quel appareil il s'agit** et vous permettra d'interagir avec lui.\
Si ce n'est pas le cas, Flipper peut **stocker** le **signal** et vous permettra de **le rejouer**.

## Références

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

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
