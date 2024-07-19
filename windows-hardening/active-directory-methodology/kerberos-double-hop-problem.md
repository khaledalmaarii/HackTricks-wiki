# Problema do Duplo Salto do Kerberos

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Introdução

O problema do "Duplo Salto" do Kerberos aparece quando um atacante tenta usar **autenticação Kerberos através de dois** **saltos**, por exemplo usando **PowerShell**/**WinRM**.

Quando uma **autenticação** ocorre através do **Kerberos**, as **credenciais** **não são** armazenadas em **memória.** Portanto, se você executar o mimikatz, você **não encontrará credenciais** do usuário na máquina, mesmo que ele esteja executando processos.

Isso acontece porque, ao conectar-se com o Kerberos, estes são os passos:

1. User1 fornece credenciais e o **controlador de domínio** retorna um **TGT** Kerberos para o User1.
2. User1 usa o **TGT** para solicitar um **ticket de serviço** para **conectar-se** ao Server1.
3. User1 **conecta-se** ao **Server1** e fornece o **ticket de serviço**.
4. O **Server1** **não tem** as **credenciais** do User1 armazenadas ou o **TGT** do User1. Portanto, quando o User1 do Server1 tenta fazer login em um segundo servidor, ele **não consegue se autenticar**.

### Delegação Não Restrita

Se a **delegação não restrita** estiver habilitada no PC, isso não acontecerá, pois o **Servidor** irá **obter** um **TGT** de cada usuário que o acessar. Além disso, se a delegação não restrita for usada, você provavelmente pode **comprometer o Controlador de Domínio** a partir dele.\
[**Mais informações na página de delegação não restrita**](unconstrained-delegation.md).

### CredSSP

Outra maneira de evitar esse problema, que é [**notavelmente insegura**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), é o **Provedor de Suporte de Segurança de Credenciais**. Da Microsoft:

> A autenticação CredSSP delega as credenciais do usuário do computador local para um computador remoto. Essa prática aumenta o risco de segurança da operação remota. Se o computador remoto for comprometido, quando as credenciais forem passadas para ele, as credenciais podem ser usadas para controlar a sessão de rede.

É altamente recomendável que o **CredSSP** seja desativado em sistemas de produção, redes sensíveis e ambientes semelhantes devido a preocupações de segurança. Para determinar se o **CredSSP** está habilitado, o comando `Get-WSManCredSSP` pode ser executado. Este comando permite a **verificação do status do CredSSP** e pode até ser executado remotamente, desde que o **WinRM** esteja habilitado.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Soluções Alternativas

### Invoke Command

Para resolver o problema do double hop, é apresentado um método que envolve um `Invoke-Command` aninhado. Isso não resolve o problema diretamente, mas oferece uma solução alternativa sem a necessidade de configurações especiais. A abordagem permite executar um comando (`hostname`) em um servidor secundário através de um comando PowerShell executado de uma máquina de ataque inicial ou através de uma PS-Session previamente estabelecida com o primeiro servidor. Veja como é feito:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativamente, estabelecer uma PS-Session com o primeiro servidor e executar o `Invoke-Command` usando `$cred` é sugerido para centralizar tarefas.

### Registrar Configuração de PSSession

Uma solução para contornar o problema do double hop envolve o uso de `Register-PSSessionConfiguration` com `Enter-PSSession`. Este método requer uma abordagem diferente do `evil-winrm` e permite uma sessão que não sofre da limitação do double hop.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Para administradores locais em um alvo intermediário, o redirecionamento de porta permite que solicitações sejam enviadas para um servidor final. Usando `netsh`, uma regra pode ser adicionada para o redirecionamento de porta, juntamente com uma regra de firewall do Windows para permitir a porta redirecionada.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` pode ser usado para encaminhar solicitações WinRM, potencialmente como uma opção menos detectável se o monitoramento do PowerShell for uma preocupação. O comando abaixo demonstra seu uso:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instalar o OpenSSH no primeiro servidor permite uma solução para o problema do double-hop, particularmente útil para cenários de jump box. Este método requer a instalação e configuração do OpenSSH para Windows via CLI. Quando configurado para Autenticação por Senha, isso permite que o servidor intermediário obtenha um TGT em nome do usuário.

#### Passos para Instalação do OpenSSH

1. Baixe e mova o arquivo zip da versão mais recente do OpenSSH para o servidor de destino.
2. Descompacte e execute o script `Install-sshd.ps1`.
3. Adicione uma regra de firewall para abrir a porta 22 e verifique se os serviços SSH estão em execução.

Para resolver erros de `Connection reset`, as permissões podem precisar ser atualizadas para permitir que todos tenham acesso de leitura e execução no diretório do OpenSSH.
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

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
