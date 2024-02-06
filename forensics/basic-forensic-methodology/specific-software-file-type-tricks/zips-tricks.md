# Truques com arquivos ZIP

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** repositórios [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Existem algumas ferramentas de linha de comando para arquivos zip que serão úteis de conhecer.

* `unzip` frequentemente fornece informações úteis sobre por que um arquivo zip não será descompactado.
* `zipdetails -v` fornecerá informações detalhadas sobre os valores presentes nos vários campos do formato.
* `zipinfo` lista informações sobre o conteúdo do arquivo zip, sem extraí-lo.
* `zip -F input.zip --out output.zip` e `zip -FF input.zip --out output.zip` tentam reparar um arquivo zip corrompido.
* [fcrackzip](https://github.com/hyc/fcrackzip) faz suposições de força bruta sobre uma senha zip (para senhas <7 caracteres mais ou menos).

[Especificação do formato de arquivo ZIP](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

Uma nota importante relacionada à segurança sobre arquivos zip protegidos por senha é que eles não criptografam os nomes de arquivo e os tamanhos de arquivo originais dos arquivos compactados que contêm, ao contrário dos arquivos RAR ou 7z protegidos por senha.

Outra observação sobre quebra de senhas zip é que se você tiver uma cópia não criptografada/não compactada de qualquer um dos arquivos que estão compactados no zip criptografado, você pode realizar um "ataque de texto simples" e quebrar o zip, como [detalhado aqui](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files), e explicado neste [artigo](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). O novo esquema para proteger arquivos zip com senha (com AES-256, em vez de "ZipCrypto") não possui essa vulnerabilidade.

De: [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)
