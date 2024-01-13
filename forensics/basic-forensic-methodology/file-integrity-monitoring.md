<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Linha de Base

Uma linha de base consiste em tirar um instantâneo de certas partes de um sistema para **compará-lo com um status futuro para destacar mudanças**.

Por exemplo, você pode calcular e armazenar o hash de cada arquivo do sistema de arquivos para poder descobrir quais arquivos foram modificados.\
Isso também pode ser feito com as contas de usuários criadas, processos em execução, serviços em execução e qualquer outra coisa que não deveria mudar muito, ou de todo.

## Monitoramento de Integridade de Arquivos

O monitoramento de integridade de arquivos é uma das técnicas mais poderosas usadas para proteger infraestruturas de TI e dados empresariais contra uma ampla variedade de ameaças conhecidas e desconhecidas.\
O objetivo é gerar uma **linha de base de todos os arquivos** que você deseja monitorar e, em seguida, **periodicamente** **verificar** esses arquivos para possíveis **mudanças** (no conteúdo, atributo, metadados, etc.).

1\. **Comparação de linha de base,** onde um ou mais atributos de arquivo serão capturados ou calculados e armazenados como uma linha de base que pode ser comparada no futuro. Isso pode ser tão simples quanto a data e hora do arquivo, no entanto, como esses dados podem ser facilmente falsificados, uma abordagem mais confiável é normalmente usada. Isso pode incluir avaliar periodicamente o checksum criptográfico de um arquivo monitorado, (por exemplo, usando o algoritmo de hash MD5 ou SHA-2) e depois comparar o resultado com o checksum previamente calculado.

2\. **Notificação de mudança em tempo real**, que é tipicamente implementada dentro ou como uma extensão do kernel do sistema operacional que sinalizará quando um arquivo é acessado ou modificado.

## Ferramentas

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

# Referências

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
