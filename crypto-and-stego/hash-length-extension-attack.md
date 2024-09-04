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


## Summary of the attack

Zamislite server koji **potpisuje** neke **podatke** dodajući **tajnu** nekim poznatim čistim tekstualnim podacima i zatim heširajući te podatke. Ako znate:

* **Dužinu tajne** (to se može takođe bruteforce-ovati iz datog opsega dužine)
* **Čiste tekstualne podatke**
* **Algoritam (i da je ranjiv na ovaj napad)**
* **Padding je poznat**
* Obično se koristi podrazumevani, tako da ako su ispunjena druga 3 zahteva, ovo takođe jeste
* Padding varira u zavisnosti od dužine tajne + podataka, zato je potrebna dužina tajne

Tada je moguće da **napadač** **doda** **podatke** i **generiše** važeći **potpis** za **prethodne podatke + dodate podatke**.

### How?

U suštini, ranjivi algoritmi generišu heševe prvo **heširajući blok podataka**, a zatim, **iz** **prethodno** kreiranog **heša** (stanja), **dodaju sledeći blok podataka** i **heširaju ga**.

Zamislite da je tajna "secret" a podaci su "data", MD5 od "secretdata" je 6036708eba0d11f6ef52ad44e8b74d5b.\
Ako napadač želi da doda string "append" može:

* Generisati MD5 od 64 "A"
* Promeniti stanje prethodno inicijalizovanog heša na 6036708eba0d11f6ef52ad44e8b74d5b
* Dodati string "append"
* Završiti heš i rezultantni heš će biti **važeći za "secret" + "data" + "padding" + "append"**

### **Tool**

{% embed url="https://github.com/iagox86/hash_extender" %}

### References

Možete pronaći ovaj napad dobro objašnjen na [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)



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
