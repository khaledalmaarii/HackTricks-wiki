# PsExec/Winexec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Trabalha numa **empresa de cibersegurança**? Quer ver a sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Como funcionam

1. Copiar um binário de serviço para o compartilhamento ADMIN$ via SMB
2. Criar um serviço na máquina remota apontando para o binário
3. Iniciar o serviço remotamente
4. Quando sair, parar o serviço e deletar o binário

## **Manualmente PsExec'ing**

Primeiro, vamos assumir que temos um executável de payload que geramos com msfvenom e ofuscamos com Veil (para que o AV não o identifique). Neste caso, criei um payload meterpreter reverse_http e o chamei de 'met8888.exe'

**Copiar o binário**. Do nosso prompt de comando "jarrieta", simplesmente copie o binário para o ADMIN$. Na verdade, ele poderia ser copiado e escondido em qualquer lugar no sistema de arquivos.

![](../../.gitbook/assets/copy\_binary\_admin.png)

**Criar um serviço**. O comando `sc` do Windows é usado para consultar, criar, deletar, etc serviços do Windows e pode ser usado remotamente. Leia mais sobre isso [aqui](https://technet.microsoft.com/en-us/library/bb490995.aspx). Do nosso prompt de comando, vamos criar remotamente um serviço chamado "meterpreter" que aponta para o nosso binário carregado:

![](../../.gitbook/assets/sc\_create.png)

**Iniciar o serviço**. O último passo é iniciar o serviço e executar o binário. _Nota:_ quando o serviço iniciar, ele vai "expirar" e gerar um erro. Isso acontece porque o nosso binário meterpreter não é um binário de serviço real e não retornará o código de resposta esperado. Isso é bom porque só precisamos que ele execute uma vez para disparar:

![](../../.gitbook/assets/sc\_start\_error.png)

Se olharmos para o nosso ouvinte do Metasploit, veremos que a sessão foi aberta.

**Limpar o serviço.**

![](../../.gitbook/assets/sc\_delete.png)

Extraído daqui: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Você também poderia usar o binário PsExec.exe do Windows Sysinternals:**

![](<../../.gitbook/assets/image (165).png>)

Você também poderia usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
```markdown
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
