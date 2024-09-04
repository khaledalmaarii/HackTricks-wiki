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

O objetivo desta página é enumerar **plataformas que permitem buscar código** (literal ou regex) em milhares/milhões de repositórios em uma ou mais plataformas.

Isso ajuda em várias ocasiões a **procurar informações vazadas** ou por padrões de **vulnerabilidades**.

* [**SourceGraph**](https://sourcegraph.com/search): Pesquisar em milhões de repositórios. Há uma versão gratuita e uma versão empresarial (com 15 dias grátis). Suporta regex.
* [**Github Search**](https://github.com/search): Pesquisar no Github. Suporta regex.
* Talvez também seja útil verificar [**Github Code Search**](https://cs.github.com/).
* [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced\_search.html): Pesquisar em projetos do Gitlab. Suporta regex.
* [**SearchCode**](https://searchcode.com/): Pesquisar código em milhões de projetos.

{% hint style="warning" %}
Quando você procura por vazamentos em um repositório e executa algo como `git log -p`, não se esqueça de que pode haver **outras branches com outros commits** contendo segredos!
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
