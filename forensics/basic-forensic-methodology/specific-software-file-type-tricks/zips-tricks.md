# Truques com ZIPs

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Existem várias ferramentas de linha de comando para arquivos zip que serão úteis de conhecer.

* `unzip` frequentemente fornece informações úteis sobre por que um zip não está descomprimindo.
* `zipdetails -v` fornece informações detalhadas sobre os valores presentes nos diversos campos do formato.
* `zipinfo` lista informações sobre o conteúdo do arquivo zip, sem extraí-lo.
* `zip -F input.zip --out output.zip` e `zip -FF input.zip --out output.zip` tentam reparar um arquivo zip corrompido.
* [fcrackzip](https://github.com/hyc/fcrackzip) realiza tentativas de força bruta para adivinhar a senha de um zip (para senhas de <7 caracteres ou assim).

[Especificação do formato de arquivo zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

Uma nota importante relacionada à segurança sobre arquivos zip protegidos por senha é que eles não criptografam os nomes dos arquivos e os tamanhos originais dos arquivos comprimidos que contêm, ao contrário de arquivos RAR ou 7z protegidos por senha.

Outra observação sobre a quebra de senhas de zip é que, se você tiver uma cópia não criptografada/descomprimida de qualquer um dos arquivos que estão comprimidos no zip criptografado, você pode realizar um "ataque de texto simples" e quebrar o zip, como [detalhado aqui](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files), e explicado neste [artigo](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). O esquema mais recente para proteção de arquivos zip com senha (com AES-256, em vez de "ZipCrypto") não possui essa fraqueza.

De: [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
