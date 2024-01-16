<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Resumo do ataque

Imagine um servidor que está **assinando** alguns **dados** **anexando** um **segredo** a alguns dados de texto claro conhecidos e, em seguida, fazendo o hash desses dados. Se você souber:

* **O comprimento do segredo** (isso também pode ser forçado bruto dentro de um intervalo de comprimento dado)
* **Os dados de texto claro**
* **O algoritmo (e ele é vulnerável a este ataque)**
* **O preenchimento é conhecido**
* Geralmente um padrão é usado, então, se os outros 3 requisitos forem atendidos, este também será
* O preenchimento varia dependendo do comprimento do segredo+dados, por isso é necessário saber o comprimento do segredo

Então, é possível para um **atacante** **anexar** **dados** e **gerar** uma **assinatura** válida para os **dados anteriores + dados anexados**.

## Como?

Basicamente, os algoritmos vulneráveis geram os hashes primeiramente **fazendo o hash de um bloco de dados**, e então, **a partir** do **hash** previamente criado (estado), eles **adicionam o próximo bloco de dados** e **fazem o hash**.

Então, imagine que o segredo seja "secret" e os dados sejam "data", o MD5 de "secretdata" é 6036708eba0d11f6ef52ad44e8b74d5b.\
Se um atacante quiser anexar a string "append", ele pode:

* Gerar um MD5 de 64 "A"s
* Mudar o estado do hash previamente inicializado para 6036708eba0d11f6ef52ad44e8b74d5b
* Anexar a string "append"
* Finalizar o hash e o hash resultante será um **válido para "secret" + "data" + "preenchimento" + "append"**

## **Ferramenta**

{% embed url="https://github.com/iagox86/hash_extender" %}

# Referências

Você pode encontrar este ataque bem explicado em [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
