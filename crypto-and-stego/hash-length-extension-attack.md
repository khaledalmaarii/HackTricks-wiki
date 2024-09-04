# Hash Length Extension Attack

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


## Riepilogo dell'attacco

Immagina un server che **firma** alcuni **dati** **aggiungendo** un **segreto** a dei dati di testo chiaro noti e poi hashando quei dati. Se conosci:

* **La lunghezza del segreto** (questo può essere anche forzato a bruteforce da un dato intervallo di lunghezza)
* **I dati di testo chiaro**
* **L'algoritmo (e è vulnerabile a questo attacco)**
* **Il padding è noto**
* Di solito viene utilizzato un padding predefinito, quindi se gli altri 3 requisiti sono soddisfatti, anche questo lo è
* Il padding varia a seconda della lunghezza del segreto + dati, ecco perché è necessaria la lunghezza del segreto

Allora, è possibile per un **attaccante** **aggiungere** **dati** e **generare** una **firma** valida per i **dati precedenti + dati aggiunti**.

### Come?

Fondamentalmente, gli algoritmi vulnerabili generano gli hash prima **hashando un blocco di dati**, e poi, **dallo** **hash** (stato) **precedentemente** creato, **aggiungono il prossimo blocco di dati** e **lo hashano**.

Poi, immagina che il segreto sia "segreto" e i dati siano "dati", l'MD5 di "segreto dati" è 6036708eba0d11f6ef52ad44e8b74d5b.\
Se un attaccante vuole aggiungere la stringa "append" può:

* Generare un MD5 di 64 "A"
* Cambiare lo stato dell'hash precedentemente inizializzato a 6036708eba0d11f6ef52ad44e8b74d5b
* Aggiungere la stringa "append"
* Completare l'hash e l'hash risultante sarà un **valido per "segreto" + "dati" + "padding" + "append"**

### **Strumento**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Riferimenti

Puoi trovare questo attacco ben spiegato in [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)



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
