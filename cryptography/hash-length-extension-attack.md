{% hint style="success" %}
Aprenda e pratique AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

# Resumo do ataque

Imagine um servidor que está **assinando** alguns **dados** ao **anexar** um **segredo** a alguns dados de texto claro conhecidos e, em seguida, fazendo o hash desses dados. Se você souber:

* **O comprimento do segredo** (isso também pode ser forçado por força bruta a partir de uma faixa de comprimento fornecida)
* **Os dados de texto claro**
* **O algoritmo (e que é vulnerável a esse ataque)**
* **O preenchimento é conhecido**
* Geralmente, um padrão é usado, então se os outros 3 requisitos forem atendidos, este também é
* O preenchimento varia dependendo do comprimento do segredo+dados, por isso o comprimento do segredo é necessário

Então, é possível para um **atacante** **anexar** **dados** e **gerar** uma **assinatura** válida para os **dados anteriores + dados anexados**.

## Como?

Basicamente, os algoritmos vulneráveis geram os hashes primeiro **fazendo o hash de um bloco de dados**, e então, **a partir** do **hash previamente** criado (estado), eles **adicionam o próximo bloco de dados** e **fazem o hash dele**.

Então, imagine que o segredo é "secreto" e os dados são "dados", o MD5 de "secretdata" é 6036708eba0d11f6ef52ad44e8b74d5b.\
Se um atacante quiser anexar a string "anexar" ele pode:

* Gerar um MD5 de 64 "A"s
* Alterar o estado do hash previamente inicializado para 6036708eba0d11f6ef52ad44e8b74d5b
* Anexar a string "anexar"
* Finalizar o hash e o hash resultante será um **válido para "secreto" + "dados" + "preenchimento" + "anexar"**

## **Ferramenta**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referências

Você pode encontrar este ataque bem explicado em [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


{% hint style="success" %}
Aprenda e pratique AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
