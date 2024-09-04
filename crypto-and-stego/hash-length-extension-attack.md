# Hash Length Extension Attack

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}


## Resumo do ataque

Imagine um servidor que está **assinando** alguns **dados** ao **anexar** um **segredo** a alguns dados de texto claro conhecidos e, em seguida, hashando esses dados. Se você souber:

* **O comprimento do segredo** (isso também pode ser forçado a partir de um intervalo de comprimento dado)
* **Os dados de texto claro**
* **O algoritmo (e ele é vulnerável a este ataque)**
* **O padding é conhecido**
* Normalmente, um padrão padrão é usado, então se os outros 3 requisitos forem atendidos, isso também é
* O padding varia dependendo do comprimento do segredo + dados, é por isso que o comprimento do segredo é necessário

Então, é possível para um **atacante** **anexar** **dados** e **gerar** uma **assinatura** válida para os **dados anteriores + dados anexados**.

### Como?

Basicamente, os algoritmos vulneráveis geram os hashes primeiro **hashando um bloco de dados**, e então, **a partir** do **hash** (estado) **anteriormente** criado, eles **adicionam o próximo bloco de dados** e **hasham**.

Então, imagine que o segredo é "segredo" e os dados são "dados", o MD5 de "segredodados" é 6036708eba0d11f6ef52ad44e8b74d5b.\
Se um atacante quiser anexar a string "anexar", ele pode:

* Gerar um MD5 de 64 "A"s
* Mudar o estado do hash previamente inicializado para 6036708eba0d11f6ef52ad44e8b74d5b
* Anexar a string "anexar"
* Finalizar o hash e o hash resultante será um **válido para "segredo" + "dados" + "padding" + "anexar"**

### **Ferramenta**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Referências

Você pode encontrar este ataque bem explicado em [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)



{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
