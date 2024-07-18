{% hint style="success" %}
Aprenda e pratique Hacking AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> [**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte) <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> \
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line"> [**Treinamento HackTricks GCP Red Team Expert (GRTE)** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

- Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
- **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
- **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

# CBC

Se o **cookie** for **apenas** o **nome de usuário** (ou a primeira parte do cookie for o nome de usuário) e você deseja se passar pelo nome de usuário "**admin**". Então, você pode criar o nome de usuário **"bdmin"** e **forçar a entrada** do **primeiro byte** do cookie.

# CBC-MAC

**Código de autenticação de mensagem de encadeamento de bloco de cifra** (**CBC-MAC**) é um método usado em criptografia. Funciona pegando uma mensagem e criptografando-a bloco por bloco, onde a criptografia de cada bloco está vinculada ao anterior. Esse processo cria uma **cadeia de blocos**, garantindo que a alteração de até mesmo um único bit da mensagem original levará a uma mudança imprevisível no último bloco de dados criptografados. Para fazer ou reverter tal mudança, a chave de criptografia é necessária, garantindo segurança.

Para calcular o CBC-MAC da mensagem m, criptografa-se m no modo CBC com vetor de inicialização zero e mantém o último bloco. A figura a seguir esboça o cálculo do CBC-MAC de uma mensagem composta por blocos ![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) usando uma chave secreta k e um cifrador de bloco E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Vulnerabilidade

Com o CBC-MAC, geralmente o **IV usado é 0**.\
Isso é um problema porque 2 mensagens conhecidas (`m1` e `m2`) independentemente gerarão 2 assinaturas (`s1` e `s2`). Então:

- `E(m1 XOR 0) = s1`
- `E(m2 XOR 0) = s2`

Então, uma mensagem composta por m1 e m2 concatenados (m3) gerará 2 assinaturas (s31 e s32):

- `E(m1 XOR 0) = s31 = s1`
- `E(m2 XOR s1) = s32`

**O que é possível calcular sem conhecer a chave da criptografia.**

Imagine que você está criptografando o nome **Administrador** em blocos de **8 bytes**:

- `Administ`
- `rator\00\00\00`

Você pode criar um nome de usuário chamado **Administ** (m1) e recuperar a assinatura (s1).\
Em seguida, você pode criar um nome de usuário chamado o resultado de `rator\00\00\00 XOR s1`. Isso gerará `E(m2 XOR s1 XOR 0)` que é s32.\
agora, você pode usar s32 como a assinatura do nome completo **Administrador**.

### Resumo

1. Obtenha a assinatura do nome de usuário **Administ** (m1) que é s1
2. Obtenha a assinatura do nome de usuário **rator\x00\x00\x00 XOR s1 XOR 0** é s32**.**
3. Defina o cookie como s32 e ele será um cookie válido para o usuário **Administrador**.

# Ataque Controlando IV

Se você puder controlar o IV usado, o ataque pode ser muito fácil.\
Se os cookies forem apenas o nome de usuário criptografado, para se passar pelo usuário "**administrador**" você pode criar o usuário "**Administrador**" e obterá seu cookie.\
Agora, se você puder controlar o IV, poderá alterar o primeiro byte do IV para que **IV\[0] XOR "A" == IV'\[0] XOR "a"** e regenerar o cookie para o usuário **Administrador**. Este cookie será válido para **se passar** pelo usuário **administrador** com o IV inicial.

## Referências

Mais informações em [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


{% hint style="success" %}
Aprenda e pratique Hacking AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> [**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte) <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> \
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line"> [**Treinamento HackTricks GCP Red Team Expert (GRTE)** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

- Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
- **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
- **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
