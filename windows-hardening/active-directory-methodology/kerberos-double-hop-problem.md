# Problema de Duplo Salto do Kerberos

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Introdução

O problema de "Duplo Salto" do Kerberos ocorre quando um atacante tenta usar a **autenticação Kerberos em dois** **saltos**, por exemplo, usando **PowerShell**/**WinRM**.

Quando uma **autenticação** ocorre através do **Kerberos**, as **credenciais** **não** são armazenadas em **memória**. Portanto, se você executar o mimikatz, **não encontrará as credenciais** do usuário na máquina, mesmo que ele esteja executando processos.

Isso ocorre porque, ao se conectar com o Kerberos, essas são as etapas:

1. O Usuário1 fornece credenciais e o **controlador de domínio** retorna um **TGT** do Kerberos para o Usuário1.
2. O Usuário1 usa o **TGT** para solicitar um **ticket de serviço** para **conectar-se** ao Servidor1.
3. O Usuário1 **conecta-se** ao **Servidor1** e fornece o **ticket de serviço**.
4. O **Servidor1** **não** tem as **credenciais** do Usuário1 em cache ou o **TGT** do Usuário1. Portanto, quando o Usuário1 do Servidor1 tenta fazer login em um segundo servidor, ele **não consegue se autenticar**.

### Delegação Não Restrita

Se a **delegação não restrita** estiver habilitada no PC, isso não acontecerá, pois o **Servidor** receberá um **TGT** de cada usuário que o acessar. Além disso, se a delegação não restrita for usada, você provavelmente pode **comprometer o Controlador de Domínio** a partir dela.\
[Mais informações na página de delegação não restrita](unconstrained-delegation.md).

### CredSSP

Outra maneira de evitar esse problema, que é [**notavelmente insegura**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), é o **Provedor de Suporte de Segurança de Credenciais**. Da Microsoft:

> A autenticação CredSSP delega as credenciais do usuário do computador local para um computador remoto. Essa prática aumenta o risco de segurança da operação remota. Se o computador remoto for comprometido, quando as credenciais forem passadas para ele, as credenciais podem ser usadas para controlar a sessão de rede.

É altamente recomendável que o **CredSSP** seja desativado em sistemas de produção, redes sensíveis e ambientes semelhantes devido a preocupações de segurança. Para determinar se o **CredSSP** está habilitado, o comando `Get-WSManCredSSP` pode ser executado. Esse comando permite a **verificação do status do CredSSP** e pode até ser executado remotamente, desde que o **WinRM** esteja habilitado.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Soluções alternativas

### Invocar Comando

Para lidar com o problema de duplo salto, é apresentado um método envolvendo um `Invoke-Command` aninhado. Isso não resolve o problema diretamente, mas oferece uma solução alternativa sem a necessidade de configurações especiais. A abordagem permite executar um comando (`hostname`) em um servidor secundário por meio de um comando PowerShell executado a partir de uma máquina de ataque inicial ou por meio de uma sessão PS previamente estabelecida com o primeiro servidor. Veja como é feito:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
### Registrar Configuração de Sessão PS

Uma solução para contornar o problema de duplo salto envolve o uso de `Register-PSSessionConfiguration` com `Enter-PSSession`. Este método requer uma abordagem diferente do `evil-winrm` e permite uma sessão que não sofre com a limitação do duplo salto.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### Encaminhamento de Porta

Para administradores locais em um alvo intermediário, o encaminhamento de porta permite que solicitações sejam enviadas para um servidor final. Usando `netsh`, uma regra pode ser adicionada para o encaminhamento de porta, juntamente com uma regra de firewall do Windows para permitir a porta encaminhada.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` pode ser usado para encaminhar solicitações do WinRM, potencialmente como uma opção menos detectável se a monitorização do PowerShell for uma preocupação. O comando abaixo demonstra o seu uso:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

A instalação do OpenSSH no primeiro servidor permite uma solução alternativa para o problema de double-hop, particularmente útil para cenários de jump box. Este método requer a instalação e configuração da CLI do OpenSSH para Windows. Quando configurado para Autenticação por Senha, isso permite que o servidor intermediário obtenha um TGT em nome do usuário.

#### Etapas de Instalação do OpenSSH

1. Baixe e mova o arquivo zip da última versão do OpenSSH para o servidor de destino.
2. Descompacte e execute o script `Install-sshd.ps1`.
3. Adicione uma regra de firewall para abrir a porta 22 e verifique se os serviços SSH estão em execução.

Para resolver erros de `Conexão redefinida`, as permissões podem precisar ser atualizadas para permitir que todos tenham acesso de leitura e execução no diretório do OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Referências

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
