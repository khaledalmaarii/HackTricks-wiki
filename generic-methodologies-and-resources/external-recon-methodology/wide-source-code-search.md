# Wide Source Code Search

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

Cilj ove stranice je da nabroji **platforme koje omogućavaju pretragu koda** (literalno ili regex) u hiljadama/milionima repozitorijuma na jednoj ili više platformi.

Ovo pomaže u nekoliko slučajeva da **pretražujete provale informacija** ili za **uzorke ranjivosti**.

* [**SourceGraph**](https://sourcegraph.com/search): Pretražujte u milionima repozitorijuma. Postoji besplatna verzija i verzija za preduzeća (sa 15 dana besplatno). Podržava regex.
* [**Github Search**](https://github.com/search): Pretražujte po Github-u. Podržava regex.
* Možda je takođe korisno proveriti i [**Github Code Search**](https://cs.github.com/).
* [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced\_search.html): Pretražujte po Gitlab projektima. Podržava regex.
* [**SearchCode**](https://searchcode.com/): Pretražujte kod u milionima projekata.

{% hint style="warning" %}
Kada tražite provale u repozitorijumu i pokrenete nešto poput `git log -p`, ne zaboravite da mogu postojati **druge grane sa drugim commit-ima** koje sadrže tajne!
{% endhint %}

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
