# PsExec/Winexec/ScExec

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira [**produtos oficiais PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Como eles funcionam

O processo é descrito nos passos abaixo, ilustrando como binários de serviço são manipulados para obter execução remota em uma máquina-alvo via SMB:

1. **Cópia de um binário de serviço para o compartilhamento ADMIN$ via SMB** é realizada.
2. **Criação de um serviço na máquina remota** é feita apontando para o binário.
3. O serviço é **iniciado remotamente**.
4. Após a saída, o serviço é **parado e o binário é excluído**.

### **Processo de Execução Manual do PsExec**

Supondo que haja um payload executável (criado com msfvenom e obfuscado usando Veil para evitar a detecção de antivírus), chamado 'met8888.exe', representando um payload meterpreter reverse_http, os seguintes passos são tomados:

- **Copiando o binário**: O executável é copiado para o compartilhamento ADMIN$ a partir de um prompt de comando, embora possa ser colocado em qualquer lugar no sistema de arquivos para permanecer oculto.

- **Criando um serviço**: Utilizando o comando `sc` do Windows, que permite consultar, criar e excluir serviços do Windows remotamente, um serviço chamado "meterpreter" é criado para apontar para o binário enviado.

- **Iniciando o serviço**: O último passo envolve iniciar o serviço, o que provavelmente resultará em um erro de "tempo esgotado" devido ao binário não ser um binário de serviço genuíno e falhar em retornar o código de resposta esperado. Esse erro é inconsequente, pois o objetivo principal é a execução do binário.

A observação do ouvinte Metasploit revelará que a sessão foi iniciada com sucesso.

[Saiba mais sobre o comando `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).


Encontre passos mais detalhados em: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Você também pode usar o binário do Windows Sysinternals PsExec.exe:**

![](<../../.gitbook/assets/image (165).png>)

Você também pode usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
