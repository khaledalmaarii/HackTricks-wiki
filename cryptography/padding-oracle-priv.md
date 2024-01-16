<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# CBC - Cipher Block Chaining

No modo CBC, o **bloco criptografado anterior é usado como IV** para fazer XOR com o próximo bloco:

![CBC encryption](https://defuse.ca/images/cbc\_encryption.png)

Para descriptografar CBC, as **operações opostas** são realizadas:

![CBC decryption](https://defuse.ca/images/cbc\_decryption.png)

Note como é necessário usar uma **chave de criptografia** e um **IV**.

# Message Padding

Como a criptografia é realizada em **blocos de tamanho fixo**, geralmente é necessário **preenchimento** no **último bloco** para completar seu comprimento.\
Normalmente, **PKCS7** é usado, que gera um preenchimento **repetindo** o **número** de **bytes necessários** para **completar** o bloco. Por exemplo, se faltam 3 bytes no último bloco, o preenchimento será `\x03\x03\x03`.

Vamos olhar mais exemplos com **2 blocos de comprimento de 8 bytes**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Note como no último exemplo o **último bloco estava cheio, então outro foi gerado apenas com preenchimento**.

# Padding Oracle

Quando uma aplicação descriptografa dados criptografados, ela primeiro descriptografa os dados; depois, ela remove o preenchimento. Durante a limpeza do preenchimento, se um **preenchimento inválido desencadear um comportamento detectável**, você tem uma **vulnerabilidade de padding oracle**. O comportamento detectável pode ser um **erro**, uma **falta de resultados**, ou uma **resposta mais lenta**.

Se você detectar esse comportamento, você pode **descriptografar os dados criptografados** e até mesmo **criptografar qualquer texto claro**.

## Como explorar

Você poderia usar [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) para explorar esse tipo de vulnerabilidade ou simplesmente fazer
```
sudo apt-get install padbuster
```
Para testar se o cookie de um site é vulnerável, você poderia tentar:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Codificação 0** significa que **base64** é utilizado (mas outras estão disponíveis, verifique o menu de ajuda).

Você também poderia **abusar dessa vulnerabilidade para criptografar novos dados. Por exemplo, imagine que o conteúdo do cookie seja "**_**user=MyUsername**_**", então você poderia alterá-lo para "\_user=administrator\_" e escalar privilégios dentro da aplicação. Você também poderia fazer isso usando `paduster` especificando o parâmetro -plaintext**:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Se o site for vulnerável, `padbuster` tentará automaticamente descobrir quando ocorre o erro de preenchimento, mas você também pode indicar a mensagem de erro usando o parâmetro **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## A teoria

**Resumindo**, você pode começar a descriptografar os dados criptografados adivinhando os valores corretos que podem ser usados para criar todos os **diferentes paddings**. Então, o ataque de padding oracle começará a descriptografar bytes de trás para frente adivinhando qual será o valor correto que **cria um padding de 1, 2, 3, etc**.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Imagine que você tem um texto criptografado que ocupa **2 blocos** formados pelos bytes de **E0 a E15**.\
Para **descriptografar** o **último bloco** (**E8 a E15**), o bloco inteiro passa pela "decifração de bloco de cifra" gerando os **bytes intermediários I0 a I15**.\
Finalmente, cada byte intermediário é **XORed** com os bytes criptografados anteriores (E0 a E7). Então:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Agora, é possível **modificar `E7` até que `C15` seja `0x01`**, o que também será um padding correto. Então, neste caso: `\x01 = I15 ^ E'7`

Assim, encontrando E'7, é **possível calcular I15**: `I15 = 0x01 ^ E'7`

O que nos permite **calcular C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Sabendo **C15**, agora é possível **calcular C14**, mas desta vez forçando bruscamente o padding `\x02\x02`.

Este BF é tão complexo quanto o anterior, pois é possível calcular o `E''15` cujo valor é 0x02: `E''7 = \x02 ^ I15` então é só necessário encontrar o **`E'14`** que gera um **`C14` igual a `0x02`**.\
Então, faça os mesmos passos para descriptografar C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Siga esta cadeia até descriptografar todo o texto criptografado.**

## Detecção da vulnerabilidade

Registre e acesse com essa conta.\
Se você **acessar várias vezes** e sempre receber o **mesmo cookie**, provavelmente há **algo errado** na aplicação. O **cookie enviado de volta deve ser único** a cada acesso. Se o cookie for **sempre o mesmo**, provavelmente sempre será válido e **não haverá como invalidá-lo**.

Agora, se você tentar **modificar** o **cookie**, você pode ver que recebe um **erro** da aplicação.\
Mas se você forçar bruscamente o padding (usando padbuster, por exemplo) você consegue obter outro cookie válido para um usuário diferente. Este cenário é altamente provável de ser vulnerável ao padbuster.

# Referências

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><strong>Aprenda hacking em AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
