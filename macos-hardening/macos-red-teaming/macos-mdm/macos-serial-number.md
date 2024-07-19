# macOS Serial Number

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## Informazioni di base

I dispositivi Apple post-2010 hanno numeri di serie composti da **12 caratteri alfanumerici**, ciascun segmento trasmette informazioni specifiche:

- **Primi 3 caratteri**: Indicano il **luogo di produzione**.
- **Caratteri 4 e 5**: Denotano l'**anno e la settimana di produzione**.
- **Caratteri 6 a 8**: Servono come **identificatore unico** per ciascun dispositivo.
- **Ultimi 4 caratteri**: Specificano il **numero di modello**.

Ad esempio, il numero di serie **C02L13ECF8J2** segue questa struttura.

### **Luoghi di produzione (Primi 3 caratteri)**
Alcuni codici rappresentano fabbriche specifiche:
- **FC, F, XA/XB/QP/G8**: Varie località negli USA.
- **RN**: Messico.
- **CK**: Cork, Irlanda.
- **VM**: Foxconn, Repubblica Ceca.
- **SG/E**: Singapore.
- **MB**: Malesia.
- **PT/CY**: Corea.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Diverse località in Cina.
- **C0, C3, C7**: Città specifiche in Cina.
- **RM**: Dispositivi ricondizionati.

### **Anno di produzione (4° carattere)**
Questo carattere varia da 'C' (che rappresenta la prima metà del 2010) a 'Z' (seconda metà del 2019), con lettere diverse che indicano diversi periodi di sei mesi.

### **Settimana di produzione (5° carattere)**
Le cifre 1-9 corrispondono alle settimane 1-9. Le lettere C-Y (escludendo le vocali e 'S') rappresentano le settimane 10-27. Per la seconda metà dell'anno, a questo numero si aggiungono 26.

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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
{% endhint %}
</details>
{% endhint %}
