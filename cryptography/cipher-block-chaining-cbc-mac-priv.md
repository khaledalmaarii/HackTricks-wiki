<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# CBC

Se o **cookie** é **apenas** o **username** (ou a primeira parte do cookie é o username) e você quer se passar pelo usuário "**admin**". Então, você pode criar o nome de usuário **"bdmin"** e **forçar bruta** o **primeiro byte** do cookie.

# CBC-MAC

Em criptografia, um **cipher block chaining message authentication code** (**CBC-MAC**) é uma técnica para construir um código de autenticação de mensagem a partir de uma cifra de bloco. A mensagem é criptografada com algum algoritmo de cifra de bloco no modo CBC para criar uma **cadeia de blocos de tal forma que cada bloco dependa da criptografia adequada do bloco anterior**. Essa interdependência garante que uma **mudança** em **qualquer** dos **bits** do texto original causará uma **mudança** no **bloco criptografado final** de uma maneira que não pode ser prevista ou contrariada sem conhecer a chave da cifra de bloco.

Para calcular o CBC-MAC de uma mensagem m, criptografa-se m no modo CBC com um vetor de inicialização zero e mantém-se o último bloco. A figura a seguir esboça o cálculo do CBC-MAC de uma mensagem composta por blocos ![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) usando uma chave secreta k e uma cifra de bloco E:

![Estrutura do CBC-MAC (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Vulnerabilidade

Com o CBC-MAC geralmente o **IV usado é 0**.\
Isso é um problema porque 2 mensagens conhecidas (`m1` e `m2`) independentemente gerarão 2 assinaturas (`s1` e `s2`). Então:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Então, uma mensagem composta por m1 e m2 concatenados (m3) gerará 2 assinaturas (s31 e s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**O que é possível calcular sem conhecer a chave da criptografia.**

Imagine que você está criptografando o nome **Administrator** em blocos de **8bytes**:

* `Administ`
* `rator\00\00\00`

Você pode criar um nome de usuário chamado **Administ** (m1) e recuperar a assinatura (s1).\
Então, você pode criar um nome de usuário chamado o resultado de `rator\00\00\00 XOR s1`. Isso gerará `E(m2 XOR s1 XOR 0)` que é s32.\
Agora, você pode usar s32 como a assinatura do nome completo **Administrator**.

### Resumo

1. Obtenha a assinatura do nome de usuário **Administ** (m1) que é s1
2. Obtenha a assinatura do nome de usuário **rator\x00\x00\x00 XOR s1 XOR 0** que é s32**.**
3. Defina o cookie para s32 e ele será um cookie válido para o usuário **Administrator**.

# Ataque Controlando IV

Se você pode controlar o IV usado, o ataque pode ser muito fácil.\
Se o cookie é apenas o nome de usuário criptografado, para se passar pelo usuário "**administrator**" você pode criar o usuário "**Administrator**" e obterá seu cookie.\
Agora, se você pode controlar o IV, você pode mudar o primeiro Byte do IV para que **IV\[0] XOR "A" == IV'\[0] XOR "a"** e regenerar o cookie para o usuário **Administrator**. Esse cookie será válido para **se passar** pelo usuário **administrator** com o IV inicial.

# Referências

Mais informações em [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
