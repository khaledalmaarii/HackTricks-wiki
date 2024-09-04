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

Celem tej strony jest enumeracja **platform, które pozwalają na wyszukiwanie kodu** (literalnego lub regex) w tysiącach/milionach repozytoriów na jednej lub więcej platformach.

Pomaga to w kilku sytuacjach w **wyszukiwaniu wycieków informacji** lub wzorców **vulnerabilities**.

* [**SourceGraph**](https://sourcegraph.com/search): Wyszukiwanie w milionach repozytoriów. Istnieje wersja darmowa i wersja enterprise (z 15 dniami za darmo). Obsługuje regexy.
* [**Github Search**](https://github.com/search): Wyszukiwanie w Githubie. Obsługuje regexy.
* Może również warto sprawdzić [**Github Code Search**](https://cs.github.com/).
* [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced\_search.html): Wyszukiwanie w projektach Gitlab. Obsługuje regexy.
* [**SearchCode**](https://searchcode.com/): Wyszukiwanie kodu w milionach projektów.

{% hint style="warning" %}
Kiedy szukasz wycieków w repozytorium i uruchamiasz coś takiego jak `git log -p`, nie zapomnij, że mogą być **inne gałęzie z innymi commitami** zawierającymi sekrety!
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
