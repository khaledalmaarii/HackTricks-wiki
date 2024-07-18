{% hint style="success" %}
Impara e pratica l'hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}


# Riassunto dell'attacco

Immagina un server che sta **firmando** dei **dati** **aggiungendo** un **segreto** a dei dati in chiaro noti e poi facendo l'hash di quei dati. Se conosci:

* **La lunghezza del segreto** (questo può essere anche forzato da un intervallo di lunghezza dato)
* **I dati in chiaro**
* **L'algoritmo (e che è vulnerabile a questo attacco)**
* **Il padding è noto**
* Di solito ne viene utilizzato uno predefinito, quindi se sono soddisfatte le altre 3 condizioni, anche questo lo è
* Il padding varia a seconda della lunghezza del segreto+dati, ecco perché è necessaria la lunghezza del segreto

Allora, è possibile per un **attaccante** **aggiungere** dei **dati** e **generare** una firma valida per i **dati precedenti + dati aggiunti**.

## Come?

Fondamentalmente gli algoritmi vulnerabili generano gli hash prima **hashando un blocco di dati**, e poi, **dal** **hash creato precedentemente** (stato), **aggiungono il blocco successivo di dati** e lo **hashano**.

Immagina che il segreto sia "segreto" e i dati siano "dati", l'MD5 di "segretodati" è 6036708eba0d11f6ef52ad44e8b74d5b.\
Se un attaccante vuole aggiungere la stringa "aggiungi" può:

* Generare un MD5 di 64 "A"
* Cambiare lo stato dell'hash inizializzato precedentemente a 6036708eba0d11f6ef52ad44e8b74d5b
* Aggiungere la stringa "aggiungi"
* Concludere l'hash e l'hash risultante sarà un **valido per "segreto" + "dati" + "padding" + "aggiungi"**

## **Strumento**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Riferimenti

Puoi trovare questo attacco ben spiegato in [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


{% hint style="success" %}
Impara e pratica l'hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}
