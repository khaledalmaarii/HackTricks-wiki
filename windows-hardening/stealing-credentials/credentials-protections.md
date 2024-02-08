# Proteções de Credenciais do Windows

## Proteções de Credenciais

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## WDigest

O protocolo [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396), introduzido com o Windows XP, é projetado para autenticação via Protocolo HTTP e é **ativado por padrão no Windows XP até o Windows 8.0 e no Windows Server 2003 até o Windows Server 2012**. Essa configuração padrão resulta no **armazenamento de senhas em texto simples no LSASS** (Local Security Authority Subsystem Service). Um atacante pode usar o Mimikatz para **extrair essas credenciais** executando:
```bash
sekurlsa::wdigest
```
Para **ativar ou desativar esse recurso**, as chaves do registro _**UseLogonCredential**_ e _**Negotiate**_ dentro de _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ devem ser definidas como "1". Se essas chaves estiverem **ausentes ou definidas como "0"**, o WDigest está **desativado**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Proteção LSA

A partir do **Windows 8.1**, a Microsoft aprimorou a segurança do LSA para **bloquear leituras de memória não autorizadas ou injeções de código por processos não confiáveis**. Esse aprimoramento dificulta o funcionamento típico de comandos como `mimikatz.exe sekurlsa:logonpasswords`. Para **habilitar essa proteção aprimorada**, o valor _**RunAsPPL**_ em _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ deve ser ajustado para 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

É possível contornar essa proteção usando o driver Mimikatz mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Guarda de Credenciais

A **Guarda de Credenciais**, um recurso exclusivo do **Windows 10 (Enterprise e Education editions)**, aprimora a segurança das credenciais da máquina usando o **Modo Virtual Seguro (VSM)** e a **Segurança Baseada em Virtualização (VBS)**. Ela aproveita as extensões de virtualização da CPU para isolar processos-chave dentro de um espaço de memória protegido, longe do alcance do sistema operacional principal. Essa isolamento garante que nem mesmo o kernel possa acessar a memória no VSM, protegendo efetivamente as credenciais de ataques como **pass-the-hash**. A **Autoridade de Segurança Local (LSA)** opera dentro desse ambiente seguro como um trustlet, enquanto o processo **LSASS** no sistema operacional principal age apenas como um comunicador com a LSA do VSM.

Por padrão, a **Guarda de Credenciais** não está ativa e requer ativação manual dentro de uma organização. É crucial para aprimorar a segurança contra ferramentas como o **Mimikatz**, que são impedidas em sua capacidade de extrair credenciais. No entanto, vulnerabilidades ainda podem ser exploradas por meio da adição de **Provedores de Suporte de Segurança (SSP)** personalizados para capturar credenciais em texto claro durante tentativas de login.

Para verificar o status de ativação da **Guarda de Credenciais**, a chave do registro **_LsaCfgFlags_** em **_HKLM\System\CurrentControlSet\Control\LSA_** pode ser inspecionada. Um valor de "**1**" indica ativação com **bloqueio UEFI**, "**2**" sem bloqueio, e "**0**" indica que não está habilitado. Esta verificação de registro, embora um forte indicador, não é o único passo para habilitar a Guarda de Credenciais. Orientações detalhadas e um script do PowerShell para habilitar esse recurso estão disponíveis online.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Para obter uma compreensão abrangente e instruções sobre como habilitar o **Credential Guard** no Windows 10 e sua ativação automática em sistemas compatíveis com o **Windows 11 Enterprise e Education (versão 22H2)**, visite a [documentação da Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Mais detalhes sobre a implementação de SSPs personalizados para captura de credenciais são fornecidos neste [guia](../active-directory-methodology/custom-ssp.md).


## Modo RestrictedAdmin do RDP

O **Windows 8.1 e o Windows Server 2012 R2** introduziram vários novos recursos de segurança, incluindo o **_Modo Restricted Admin para RDP_**. Esse modo foi projetado para aprimorar a segurança, mitigando os riscos associados aos ataques de **[pass the hash](https://blog.ahasayen.com/pass-the-hash/)**.

Tradicionalmente, ao se conectar a um computador remoto via RDP, suas credenciais são armazenadas na máquina de destino. Isso representa um risco significativo de segurança, especialmente ao usar contas com privilégios elevados. No entanto, com a introdução do **_Modo Restricted Admin_**, esse risco é substancialmente reduzido.

Ao iniciar uma conexão RDP usando o comando **mstsc.exe /RestrictedAdmin**, a autenticação no computador remoto é realizada sem armazenar suas credenciais nele. Esse método garante que, no caso de uma infecção por malware ou se um usuário malicioso ganhar acesso ao servidor remoto, suas credenciais não sejam comprometidas, pois não são armazenadas no servidor.

É importante observar que, no **Modo Restricted Admin**, as tentativas de acessar recursos de rede a partir da sessão RDP não usarão suas credenciais pessoais; em vez disso, a **identidade da máquina** é usada.

Essa funcionalidade representa um avanço significativo na segurança das conexões de desktop remoto e na proteção de informações confidenciais contra exposição em caso de violação de segurança.

![](../../.gitbook/assets/ram.png)

Para obter informações mais detalhadas, visite [este recurso](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).


## Credenciais em Cache

O Windows protege **credenciais de domínio** por meio da **Autoridade de Segurança Local (LSA)**, suportando processos de logon com protocolos de segurança como **Kerberos** e **NTLM**. Um recurso chave do Windows é sua capacidade de armazenar em cache os **últimos dez logins de domínio** para garantir que os usuários ainda possam acessar seus computadores mesmo se o **controlador de domínio estiver offline**—um benefício para usuários de laptop frequentemente longe da rede da empresa.

O número de logins em cache é ajustável por meio de uma **chave de registro específica ou política de grupo**. Para visualizar ou alterar essa configuração, o seguinte comando é utilizado:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
O acesso a essas credenciais em cache é estritamente controlado, com apenas a conta **SYSTEM** tendo as permissões necessárias para visualizá-las. Administradores que precisam acessar essas informações devem fazê-lo com privilégios de usuário SYSTEM. As credenciais são armazenadas em: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** pode ser utilizado para extrair essas credenciais em cache usando o comando `lsadump::cache`.

Para mais detalhes, a [fonte](http://juggernaut.wikidot.com/cached-credentials) original fornece informações abrangentes.


## Usuários Protegidos

A adesão ao grupo **Protected Users** introduz várias melhorias de segurança para os usuários, garantindo níveis mais altos de proteção contra roubo e uso indevido de credenciais:

- **Delegação de Credenciais (CredSSP)**: Mesmo que a configuração de Política de Grupo para **Permitir a delegação de credenciais padrão** esteja ativada, as credenciais em texto simples dos Protected Users não serão armazenadas em cache.
- **Windows Digest**: A partir do **Windows 8.1 e Windows Server 2012 R2**, o sistema não armazenará em cache as credenciais em texto simples dos Protected Users, independentemente do status do Windows Digest.
- **NTLM**: O sistema não armazenará em cache as credenciais em texto simples dos Protected Users ou as funções unidirecionais NT (NTOWF).
- **Kerberos**: Para os Protected Users, a autenticação Kerberos não gerará chaves **DES** ou **RC4**, nem armazenará em cache as credenciais em texto simples ou chaves de longo prazo além da aquisição inicial do Ticket-Granting Ticket (TGT).
- **Logon Offline**: Os Protected Users não terão um verificador em cache criado no logon ou desbloqueio, o que significa que o logon offline não é suportado para essas contas.

Essas proteções são ativadas no momento em que um usuário, que é membro do grupo **Protected Users**, faz login no dispositivo. Isso garante que medidas de segurança críticas estejam em vigor para proteger contra vários métodos de comprometimento de credenciais.

Para obter informações mais detalhadas, consulte a [documentação](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) oficial.

**Tabela do** [**documento**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |
