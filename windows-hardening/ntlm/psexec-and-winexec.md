# PsExec/Winexec/ScExec

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Como eles funcionam

1. Copie um binário de serviço para o compartilhamento ADMIN$ via SMB
2. Crie um serviço na máquina remota apontando para o binário
3. Inicie o serviço remotamente
4. Quando sair, pare o serviço e delete o binário

## **Manualmente PsExec'ing**

Primeiro, vamos supor que temos um executável de payload que geramos com msfvenom e ofuscamos com Veil (para que o AV não o identifique). Neste caso, criei um payload meterpreter reverse_http e o chamei de 'met8888.exe'

**Copie o binário**. Do nosso prompt de comando "jarrieta", simplesmente copie o binário para o ADMIN$. Na verdade, ele poderia ser copiado e escondido em qualquer lugar no sistema de arquivos.

![](../../.gitbook/assets/copy\_binary\_admin.png)

**Crie um serviço**. O comando `sc` do Windows é usado para consultar, criar, excluir, etc serviços do Windows e pode ser usado remotamente. Leia mais sobre isso [aqui](https://technet.microsoft.com/en-us/library/bb490995.aspx). Do nosso prompt de comando, vamos criar remotamente um serviço chamado "meterpreter" que aponta para nosso binário carregado:

![](../../.gitbook/assets/sc\_create.png)

**Inicie o serviço**. O último passo é iniciar o serviço e executar o binário. _Nota:_ quando o serviço iniciar, ele vai "expirar" e gerar um erro. Isso acontece porque nosso binário meterpreter não é um binário de serviço real e não retornará o código de resposta esperado. Isso é bom porque só precisamos que ele execute uma vez para disparar:

![](../../.gitbook/assets/sc\_start\_error.png)

Se olharmos para o nosso ouvinte do Metasploit, veremos que a sessão foi aberta.

**Limpe o serviço.**

![](../../.gitbook/assets/sc\_delete.png)

Extraído daqui: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Você também poderia usar o binário PsExec.exe do Windows Sysinternals:**

![](<../../.gitbook/assets/image (165).png>)

Você também poderia usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
