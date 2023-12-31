# macOS AppleFS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Sistema de Arquivos Proprietário da Apple (APFS)

APFS, ou Apple File System, é um sistema de arquivos moderno desenvolvido pela Apple Inc. que foi projetado para substituir o antigo Hierarchical File System Plus (HFS+) com ênfase em **desempenho, segurança e eficiência aprimorados**.

Algumas características notáveis do APFS incluem:

1. **Compartilhamento de Espaço**: APFS permite que múltiplos volumes **compartilhem o mesmo armazenamento livre subjacente** em um único dispositivo físico. Isso possibilita uma utilização mais eficiente do espaço, pois os volumes podem crescer e diminuir dinamicamente sem a necessidade de redimensionamento manual ou reparticionamento.
2. Isso significa, comparado com partições tradicionais em discos de arquivos, **que no APFS diferentes partições (volumes) compartilham todo o espaço do disco**, enquanto uma partição regular geralmente tinha um tamanho fixo.
3. **Snapshots**: APFS suporta a **criação de snapshots**, que são instâncias do sistema de arquivos **somente leitura**, em um determinado ponto no tempo. Snapshots possibilitam backups eficientes e fácil reversão do sistema, pois consomem armazenamento adicional mínimo e podem ser criados ou revertidos rapidamente.
4. **Clones**: APFS pode **criar clones de arquivos ou diretórios que compartilham o mesmo armazenamento** que o original até que o clone ou o arquivo original seja modificado. Este recurso fornece uma maneira eficiente de criar cópias de arquivos ou diretórios sem duplicar o espaço de armazenamento.
5. **Criptografia**: APFS **suporta nativamente criptografia de disco inteiro** assim como criptografia por arquivo e por diretório, aumentando a segurança dos dados em diferentes casos de uso.
6. **Proteção contra Falhas**: APFS usa um esquema de metadados **copy-on-write que garante a consistência do sistema de arquivos** mesmo em casos de perda de energia súbita ou falhas do sistema, reduzindo o risco de corrupção de dados.

No geral, APFS oferece um sistema de arquivos mais moderno, flexível e eficiente para dispositivos Apple, com foco em desempenho aprimorado, confiabilidade e segurança.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

O volume `Data` é montado em **`/System/Volumes/Data`** (você pode verificar isso com `diskutil apfs list`).

A lista de firmlinks pode ser encontrada no arquivo **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
À **esquerda**, está o caminho do diretório no **volume do Sistema**, e à **direita**, o caminho do diretório onde ele mapeia no **volume de Dados**. Então, `/library` --> `/system/Volumes/data/library`

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
