<details>

<summary><strong>Aprenda hacking AWS de zero a herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


Em uma resposta de ping TTL:\
127 = Windows\
254 = Cisco\
Lo demás,algunlinux

$1$- md5\
$2$ou $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Se você não sabe o que está por trás de um serviço, tente fazer uma solicitação HTTP GET.

**Scans UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Um pacote UDP vazio é enviado para uma porta específica. Se a porta UDP estiver aberta, nenhuma resposta é enviada de volta da máquina de destino. Se a porta UDP estiver fechada, um pacote ICMP de porta inacessível deve ser enviado de volta da máquina de destino.\

A varredura de portas UDP geralmente é pouco confiável, pois firewalls e roteadores podem descartar pacotes ICMP. Isso pode levar a falsos positivos em sua varredura, e você verá regularmente varreduras de portas UDP mostrando todas as portas UDP abertas em uma máquina escaneada.\
o A maioria dos scanners de portas não escaneia todas as portas disponíveis e geralmente tem uma lista predefinida de "portas interessantes" que são escaneadas.

# CTF - Truques

No **Windows** use o **Winzip** para pesquisar arquivos.\
**Streams de Dados Alternativos**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Criptografia

**featherduster**\

**Base64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Começa com "_begin \<modo> \<nome do arquivo>_" e caracteres estranhos\
**Xxencoding** --> Começa com "_begin \<modo> \<nome do arquivo>_" e B64\
\
**Vigenere** (análise de frequência) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (deslocamento de caracteres) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Esconder mensagens usando espaços e tabulações

# Caracteres

%E2%80%AE => Caractere RTL (escreve payloads ao contrário)


<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou nos siga no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
