# Proteções de Credenciais do Windows

## Proteções de Credenciais

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WDigest

O protocolo [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) foi introduzido no Windows XP e foi projetado para ser usado com o Protocolo HTTP para autenticação. A Microsoft tem esse protocolo **ativado por padrão em várias versões do Windows** (Windows XP — Windows 8.0 e Windows Server 2003 — Windows Server 2012), o que significa que **senhas em texto puro são armazenadas no LSASS** (Local Security Authority Subsystem Service). O **Mimikatz** pode interagir com o LSASS permitindo que um atacante **recupere essas credenciais** através do seguinte comando:
```
sekurlsa::wdigest
```
Este comportamento pode ser **desativado/ativado definindo como 1** o valor de _**UseLogonCredential**_ e _**Negotiate**_ em _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_.\
Se essas chaves de registro **não existirem** ou o valor for **"0"**, então o WDigest será **desativado**.
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Proteção LSA

A Microsoft, no **Windows 8.1 e versões posteriores**, forneceu proteção adicional para o LSA para **impedir** que processos não confiáveis possam **ler sua memória** ou injetar código. Isso impedirá que o comando regular `mimikatz.exe sekurlsa:logonpasswords` funcione corretamente.\
Para **ativar essa proteção**, você precisa definir o valor _**RunAsPPL**_ em _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ para 1.
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

É possível contornar essa proteção usando o driver Mimikatz mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard** é um recurso novo no Windows 10 (edições Enterprise e Education) que ajuda a proteger suas credenciais em uma máquina contra ameaças como pass the hash. Isso funciona por meio de uma tecnologia chamada Modo Seguro Virtual (VSM), que utiliza extensões de virtualização da CPU (mas não é uma máquina virtual real) para fornecer **proteção a áreas da memória** (você pode ouvir isso sendo referido como Segurança Baseada em Virtualização ou VBS). O VSM cria uma "bolha" separada para **processos** chave que são **isolados** dos processos regulares do **sistema operacional**, até mesmo do kernel e **apenas processos confiáveis específicos podem se comunicar com os processos** (conhecidos como **trustlets**) no VSM. Isso significa que um processo no SO principal não pode ler a memória do VSM, nem mesmo processos do kernel. A **Autoridade de Segurança Local (LSA) é um dos trustlets** no VSM, além do processo **LSASS** padrão que ainda é executado no SO principal para garantir suporte com processos existentes, mas que realmente atua apenas como um proxy ou stub para se comunicar com a versão no VSM, garantindo que as credenciais reais sejam executadas na versão do VSM e, portanto, protegidas contra ataques. Para o Windows 10, o Credential Guard deve ser ativado e implantado em sua organização, pois **não está habilitado por padrão.**
De [https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard). Mais informações e um script PS1 para habilitar o Credential Guard [podem ser encontrados aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage). No entanto, a partir do Windows 11 Enterprise, versão 22H2, e Windows 11 Education, versão 22H2, sistemas compatíveis têm o Windows Defender Credential Guard [ativado por padrão](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#Default%20Enablement).

Neste caso, **Mimikatz não pode fazer muito para contornar** isso e extrair os hashes do LSASS. Mas você sempre pode adicionar seu **SSP personalizado** e **capturar as credenciais** quando um usuário tenta fazer login em **texto claro**.\
Mais informações sobre [**SSP e como fazer isso aqui**](../active-directory-methodology/custom-ssp.md).

O Credential Guard pode ser **habilitado de diferentes maneiras**. Para verificar se foi habilitado usando o registro, você pode verificar o valor da chave _**LsaCfgFlags**_ em _**HKLM\System\CurrentControlSet\Control\LSA**_. Se o valor for **"1"**, então está ativo com bloqueio UEFI, se **"2"**, está ativo sem bloqueio e se **"0"**, não está habilitado.\
Isso **não é suficiente para habilitar o Credential Guard** (mas é um forte indicador).\
Mais informações e um script PS1 para habilitar o Credential Guard [podem ser encontrados aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
## Modo RestrictedAdmin do RDP

Com o Windows 8.1 e o Windows Server 2012 R2, novos recursos de segurança foram introduzidos. Um desses recursos de segurança é o _modo Restricted Admin para RDP_. Esse novo recurso de segurança foi introduzido para mitigar o risco de ataques de [pass the hash](https://blog.ahasayen.com/pass-the-hash/).

Quando você se conecta a um computador remoto usando RDP, suas credenciais são armazenadas no computador remoto ao qual você se conecta via RDP. Geralmente, você usa uma conta poderosa para se conectar a servidores remotos, e ter suas credenciais armazenadas em todos esses computadores é de fato uma ameaça à segurança.

Usando o _modo Restricted Admin para RDP_, quando você se conecta a um computador remoto usando o comando, **mstsc.exe /RestrictedAdmin**, você será autenticado no computador remoto, mas **suas credenciais não serão armazenadas nesse computador remoto**, como teriam sido no passado. Isso significa que, se um malware ou até mesmo um usuário malicioso estiver ativo nesse servidor remoto, suas credenciais não estarão disponíveis nesse servidor de desktop remoto para o malware atacar.

Observe que, como suas credenciais não estão sendo salvas na sessão RDP, se **tentar acessar recursos de rede**, suas credenciais não serão usadas. **A identidade da máquina será usada em vez disso**.

![](../../.gitbook/assets/ram.png)

A partir de [aqui](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credenciais em Cache

**Credenciais de domínio** são usadas por componentes do sistema operacional e são **autenticadas** pela **Autoridade de Segurança Local** (LSA). Tipicamente, as credenciais de domínio são estabelecidas para um usuário quando um pacote de segurança registrado autentica os dados de logon do usuário. Esse pacote de segurança registrado pode ser o protocolo **Kerberos** ou **NTLM**.

**O Windows armazena as últimas dez credenciais de login de domínio no caso de o controlador de domínio ficar offline**. Se o controlador de domínio ficar offline, um usuário **ainda poderá fazer login em seu computador**. Esse recurso é principalmente para usuários de laptop que não se conectam regularmente ao domínio de sua empresa. O número de credenciais que o computador armazena pode ser controlado pela seguinte **chave de registro, ou via política de grupo**:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
As credenciais estão ocultas de usuários normais, até mesmo contas de administrador. O usuário **SYSTEM** é o único usuário que tem **privilégios** para **visualizar** essas **credenciais**. Para que um administrador visualize essas credenciais no registro, ele deve acessar o registro como um usuário SYSTEM.
As credenciais armazenadas em cache estão localizadas no registro no seguinte endereço do registro:
```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```
**Extração do Mimikatz**: `lsadump::cache`\
De [aqui](http://juggernaut.wikidot.com/cached-credentials).

## Usuários Protegidos

Quando o usuário conectado é membro do grupo Usuários Protegidos, as seguintes proteções são aplicadas:

* A delegação de credenciais (CredSSP) não armazenará as credenciais em texto puro do usuário, mesmo quando a configuração de Política de Grupo **Permitir delegação de credenciais padrão** estiver habilitada.
* A partir do Windows 8.1 e Windows Server 2012 R2, o Windows Digest não armazenará as credenciais em texto puro do usuário, mesmo quando o Windows Digest estiver habilitado.
* **NTLM** não armazenará **as credenciais em texto puro** do usuário ou a função unidirecional do NT (NTOWF).
* **Kerberos** não criará mais chaves **DES** ou **RC4**. Também não armazenará as credenciais em texto puro do usuário ou chaves de longo prazo após a obtenção inicial do TGT.
* **Um verificador armazenado não é criado no momento do login ou desbloqueio**, portanto, o login offline não é mais suportado.

Após a conta do usuário ser adicionada ao grupo Usuários Protegidos, a proteção começará quando o usuário se conectar ao dispositivo. **De** [**aqui**](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Operadores de Conta     | Operadores de Conta      | Operadores de Conta                                                           | Operadores de Conta          |
| Administrador           | Administrador            | Administrador                                                                 | Administrador                |
| Administradores         | Administradores          | Administradores                                                               | Administradores              |
| Operadores de Backup    | Operadores de Backup     | Operadores de Backup                                                          | Operadores de Backup         |
| Publicadores de Cert    |                          |                                                                               |                              |
| Admins de Domínio       | Admins de Domínio        | Admins de Domínio                                                             | Admins de Domínio            |
| Controladores de Domínio| Controladores de Domínio | Controladores de Domínio                                                      | Controladores de Domínio     |
| Admins de Empresa       | Admins de Empresa        | Admins de Empresa                                                             | Admins de Empresa            |
|                         |                          |                                                                               | Admins de Chave de Empresa   |
|                         |                          |                                                                               | Admins de Chave              |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Operadores de Impressão | Operadores de Impressão  | Operadores de Impressão                                                       | Operadores de Impressão      |
|                         |                          | Controladores de Domínio Somente Leitura                                      | Controladores de Domínio Somente Leitura |
| Replicador              | Replicador               | Replicador                                                                    | Replicador                   |
| Admins de Esquema       | Admins de Esquema        | Admins de Esquema                                                             | Admins de Esquema            |
| Operadores de Servidor  | Operadores de Servidor   | Operadores de Servidor                                                        | Operadores de Servidor       |

**Tabela de** [**aqui**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
