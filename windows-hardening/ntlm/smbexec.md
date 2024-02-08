# SmbExec/ScExec

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Como Funciona

**Smbexec** é uma ferramenta usada para execução de comandos remotos em sistemas Windows, semelhante ao **Psexec**, mas evita colocar arquivos maliciosos no sistema alvo.

### Pontos Chave sobre **SMBExec**

- Opera criando um serviço temporário (por exemplo, "BTOBTO") na máquina alvo para executar comandos via cmd.exe (%COMSPEC%), sem deixar cair binários.
- Apesar de sua abordagem furtiva, gera logs de eventos para cada comando executado, oferecendo uma forma de "shell" não interativa.
- O comando para se conectar usando **Smbexec** se parece com isso:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Executando Comandos Sem Binários

- **Smbexec** permite a execução direta de comandos através de binPaths de serviço, eliminando a necessidade de binários físicos no alvo.
- Este método é útil para executar comandos pontuais em um alvo Windows. Por exemplo, combiná-lo com o módulo `web_delivery` do Metasploit permite a execução de um payload Meterpreter reverso direcionado ao PowerShell.
- Ao criar um serviço remoto na máquina do atacante com binPath configurado para executar o comando fornecido através do cmd.exe, é possível executar o payload com sucesso, alcançando o callback e a execução do payload com o ouvinte do Metasploit, mesmo se ocorrerem erros de resposta do serviço.

### Exemplo de Comandos

A criação e inicialização do serviço podem ser realizadas com os seguintes comandos:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Para mais detalhes, consulte [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## Referências
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
