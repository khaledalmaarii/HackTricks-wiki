# SmbExec/ScExec

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Como Funciona

**Smbexec** opera de maneira semelhante ao **Psexec**, visando **cmd.exe** ou **powershell.exe** no sistema da vítima para execução de backdoor, evitando o uso de executáveis maliciosos.

## **SMBExec**
```bash
smbexec.py WORKGROUP/username:password@10.10.10.10
```
A funcionalidade do smbexec envolve a criação de um serviço temporário (por exemplo, "BTOBTO") na máquina alvo para executar comandos sem deixar um binário. Esse serviço, construído para executar um comando através do caminho do cmd.exe (%COMSPEC%), redireciona a saída para um arquivo temporário e se deleta após a execução. O método é furtivo, mas gera logs de eventos para cada comando, oferecendo um "shell" não interativo repetindo esse processo para cada comando emitido pelo lado do atacante.

## Executando Comandos Sem Binários

Essa abordagem permite a execução direta de comandos via binPaths de serviço, eliminando a necessidade de binários. É particularmente útil para a execução de comandos pontuais em um alvo Windows. Por exemplo, usando o módulo `web_delivery` do Metasploit com um payload Meterpreter reverso direcionado para PowerShell, é possível estabelecer um ouvinte que fornece o comando de execução necessário. Criar e iniciar um serviço remoto na máquina Windows do atacante com o binPath configurado para executar esse comando via cmd.exe permite a execução do payload, apesar de possíveis erros de resposta do serviço, alcançando o retorno de chamada e a execução do payload no lado do ouvinte do Metasploit.

### Exemplo de Comandos

A criação e inicialização do serviço podem ser realizadas com os seguintes comandos:
```cmd
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Para mais detalhes, consulte [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


# Referências
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
