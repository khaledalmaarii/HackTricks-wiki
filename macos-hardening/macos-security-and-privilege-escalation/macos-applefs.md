# macOS AppleFS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Sistema de Arquivos Proprietário da Apple (APFS)

O **Sistema de Arquivos da Apple (APFS)** é um sistema de arquivos moderno projetado para substituir o Hierarchical File System Plus (HFS+). Seu desenvolvimento foi impulsionado pela necessidade de **melhor desempenho, segurança e eficiência**.

Algumas características notáveis do APFS incluem:

1. **Compartilhamento de Espaço**: O APFS permite que vários volumes **compartilhem o mesmo armazenamento livre subjacente** em um único dispositivo físico. Isso permite uma utilização de espaço mais eficiente, pois os volumes podem crescer e encolher dinamicamente sem a necessidade de redimensionamento ou reparticionamento manual.
1. Isso significa, em comparação com partições tradicionais em discos de arquivos, **que no APFS diferentes partições (volumes) compartilham todo o espaço do disco**, enquanto uma partição regular geralmente tinha um tamanho fixo.
2. **Snapshots**: O APFS suporta **criar snapshots**, que são instâncias **somente leitura**, do sistema de arquivos em determinado momento. Os snapshots permitem backups eficientes e reversões fáceis do sistema, pois consomem um armazenamento adicional mínimo e podem ser criados ou revertidos rapidamente.
3. **Clones**: O APFS pode **criar clones de arquivos ou diretórios que compartilham o mesmo armazenamento** que o original até que o clone ou o arquivo original seja modificado. Essa funcionalidade oferece uma maneira eficiente de criar cópias de arquivos ou diretórios sem duplicar o espaço de armazenamento.
4. **Criptografia**: O APFS **suporta nativamente criptografia de disco completo** e criptografia por arquivo e por diretório, aprimorando a segurança dos dados em diferentes casos de uso.
5. **Proteção contra Falhas**: O APFS utiliza um **esquema de metadados de cópia em gravação que garante a consistência do sistema de arquivos** mesmo em casos de perda de energia repentina ou falhas do sistema, reduzindo o risco de corrupção de dados.

No geral, o APFS oferece um sistema de arquivos mais moderno, flexível e eficiente para dispositivos Apple, com foco em melhor desempenho, confiabilidade e segurança aprimorada.
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
Na **esquerda**, há o caminho do diretório no **volume do Sistema**, e na **direita**, o caminho do diretório onde ele mapeia no **volume de Dados**. Portanto, `/library` --> `/system/Volumes/data/library`
