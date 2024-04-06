# Truques com arquivos ZIP

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Ferramentas de linha de comando** para gerenciar **arquivos zip** são essenciais para diagnosticar, reparar e quebrar arquivos zip. Aqui estão algumas utilidades-chave:

- **`unzip`**: Revela por que um arquivo zip pode não descompactar.
- **`zipdetails -v`**: Oferece análise detalhada dos campos do formato do arquivo zip.
- **`zipinfo`**: Lista o conteúdo de um arquivo zip sem extraí-los.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tente reparar arquivos zip corrompidos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uma ferramenta para quebrar senhas zip por força bruta, eficaz para senhas de até cerca de 7 caracteres.

A [especificação do formato de arquivo Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornece detalhes abrangentes sobre a estrutura e os padrões de arquivos zip.

É crucial observar que arquivos zip protegidos por senha **não criptografam os nomes de arquivos ou tamanhos de arquivos** dentro deles, uma falha de segurança não compartilhada com arquivos RAR ou 7z que criptografam essas informações. Além disso, arquivos zip criptografados com o método ZipCrypto mais antigo são vulneráveis a um **ataque de texto simples** se uma cópia não criptografada de um arquivo compactado estiver disponível. Esse ataque aproveita o conteúdo conhecido para quebrar a senha do zip, uma vulnerabilidade detalhada no [artigo do HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e explicada mais detalhadamente neste [artigo acadêmico](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). No entanto, arquivos zip protegidos com criptografia **AES-256** são imunes a esse ataque de texto simples, destacando a importância de escolher métodos de criptografia seguros para dados sensíveis.

# Referências
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
