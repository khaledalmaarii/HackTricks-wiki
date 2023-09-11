# macOS AppleFS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Sistema de Arquivos Proprietário da Apple (APFS)

APFS, ou Apple File System, é um sistema de arquivos moderno desenvolvido pela Apple Inc. que foi projetado para substituir o antigo Hierarchical File System Plus (HFS+) com ênfase em **melhor desempenho, segurança e eficiência**.

Algumas características notáveis do APFS incluem:

1. **Compartilhamento de Espaço**: O APFS permite que múltiplos volumes **compartilhem o mesmo espaço de armazenamento livre** em um único dispositivo físico. Isso permite uma utilização mais eficiente do espaço, pois os volumes podem crescer e encolher dinamicamente sem a necessidade de redimensionamento ou reparticionamento manual.
1. Isso significa, em comparação com partições tradicionais em discos de arquivos, **que no APFS diferentes partições (volumes) compartilham todo o espaço do disco**, enquanto uma partição regular geralmente tinha um tamanho fixo.
2. **Snapshots**: O APFS suporta a **criação de snapshots**, que são instâncias **somente leitura** do sistema de arquivos em um determinado momento. Os snapshots permitem backups eficientes e reversões do sistema, pois consomem um armazenamento adicional mínimo e podem ser criados ou revertidos rapidamente.
3. **Clones**: O APFS pode **criar clones de arquivos ou diretórios que compartilham o mesmo armazenamento** que o original até que o clone ou o arquivo original seja modificado. Essa funcionalidade oferece uma maneira eficiente de criar cópias de arquivos ou diretórios sem duplicar o espaço de armazenamento.
4. **Criptografia**: O APFS **suporta nativamente criptografia de disco completo**, bem como criptografia por arquivo e por diretório, aumentando a segurança dos dados em diferentes casos de uso.
5. **Proteção contra falhas**: O APFS utiliza um **esquema de metadados de cópia em gravação que garante a consistência do sistema de arquivos** mesmo em casos de perda repentina de energia ou falhas do sistema, reduzindo o risco de corrupção de dados.

No geral, o APFS oferece um sistema de arquivos mais moderno, flexível e eficiente para dispositivos Apple, com foco em melhor desempenho, confiabilidade e segurança.
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
À **esquerda**, está o caminho do diretório no **volume do sistema**, e à **direita**, o caminho do diretório onde ele é mapeado no **volume de dados**. Portanto, `/library` --> `/system/Volumes/data/library`

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
