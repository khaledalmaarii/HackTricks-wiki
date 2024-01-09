<details>

<summary><strong>Aprenda a hackear AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


Em uma resposta de ping TTL:\
127 = Windows\
254 = Cisco\
Lo demás, algunlinux

$1$- md5\
$2$ ou $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Se você não sabe o que está por trás de um serviço, tente fazer uma requisição HTTP GET.

**Varreduras UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Um pacote UDP vazio é enviado a uma porta específica. Se a porta UDP estiver aberta, nenhuma resposta é enviada de volta pela máquina alvo. Se a porta UDP estiver fechada, um pacote ICMP de porta inalcançável deve ser enviado de volta pela máquina alvo.\

A varredura de portas UDP é frequentemente não confiável, pois firewalls e roteadores podem descartar pacotes ICMP\
Isso pode levar a falsos positivos na sua varredura, e você verá regularmente\
varreduras de portas UDP mostrando todas as portas UDP abertas em uma máquina escaneada.\
o A maioria dos scanners de portas não varre todas as portas disponíveis, e geralmente têm uma lista predefinida\
de "portas interessantes" que são varridas.

# CTF - Truques

No **Windows** use **Winzip** para procurar por arquivos.\
**Alternate data Streams**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Criptografia

**featherduster**


**Base64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Começa com "_begin \<mode> \<filename>_" e caracteres estranhos\
**Xxencoding** --> Começa com "_begin \<mode> \<filename>_" e B64\
\
**Vigenere** (análise de frequência) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (deslocamento de caracteres) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Oculta mensagens usando espaços e tabs

# Caracteres

%E2%80%AE => Caractere RTL (escreve cargas úteis de trás para frente)


<details>

<summary><strong>Aprenda a hackear AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
