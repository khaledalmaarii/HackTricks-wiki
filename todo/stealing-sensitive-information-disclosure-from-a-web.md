# Roubo de Divulgação de Informações Sensíveis de uma Web

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

Se em algum momento você encontrar uma **página da web que apresenta informações sensíveis com base na sua sessão**: Talvez esteja refletindo cookies, ou imprimindo detalhes de cartão de crédito ou qualquer outra informação sensível, você pode tentar roubá-la.\
Aqui apresento as principais maneiras que você pode tentar alcançar isso:

* [**CORS bypass**](../pentesting-web/cors-bypass.md): Se você conseguir contornar os cabeçalhos CORS, poderá roubar as informações realizando uma solicitação Ajax para uma página maliciosa.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): Se você encontrar uma vulnerabilidade XSS na página, pode ser capaz de abusar dela para roubar as informações.
* [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Se você não conseguir injetar tags XSS, ainda pode ser capaz de roubar as informações usando outras tags HTML regulares.
* [**Clickjaking**](../pentesting-web/clickjacking.md): Se não houver proteção contra esse ataque, você pode ser capaz de enganar o usuário para enviar os dados sensíveis (um exemplo [aqui](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
