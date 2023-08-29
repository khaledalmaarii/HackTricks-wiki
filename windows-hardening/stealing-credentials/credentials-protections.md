# Proteções de Credenciais do Windows

## Proteções de Credenciais

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WDigest

O protocolo [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) foi introduzido no Windows XP e foi projetado para ser usado com o Protocolo HTTP para autenticação. A Microsoft tem este protocolo **habilitado por padrão em várias versões do Windows** (Windows XP - Windows 8.0 e Windows Server 2003 - Windows Server 2012), o que significa que **senhas em texto simples são armazenadas no LSASS** (Local Security Authority Subsystem Service). O Mimikatz pode interagir com o LSASS permitindo que um atacante **recupere essas credenciais** por meio do seguinte comando:
```
sekurlsa::wdigest
```
Esse comportamento pode ser **desativado/ativado definindo o valor como 1** para _**UseLogonCredential**_ e _**Negotiate**_ em _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_.\
Se essas chaves de registro **não existirem** ou o valor for **"0"**, então o WDigest será **desativado**.
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Proteção LSA

A Microsoft no **Windows 8.1 e posterior** forneceu proteção adicional para o LSA para **prevenir** que processos não confiáveis possam **ler sua memória** ou injetar código. Isso impedirá que o `mimikatz.exe sekurlsa:logonpasswords` funcione corretamente.\
Para **ativar essa proteção**, você precisa definir o valor _**RunAsPPL**_ em _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ como 1.
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypassar

É possível contornar essa proteção usando o driver Mimikatz mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard** é um novo recurso no Windows 10 (Enterprise e Education edition) que ajuda a proteger suas credenciais em uma máquina contra ameaças como pass the hash. Isso funciona por meio de uma tecnologia chamada Virtual Secure Mode (VSM), que utiliza extensões de virtualização da CPU (mas não é uma máquina virtual real) para fornecer **proteção para áreas de memória** (você pode ouvir isso referido como Segurança Baseada em Virtualização ou VBS). O VSM cria uma "bolha" separada para **processos**-chave que estão **isolados** dos processos regulares do **sistema operacional**, inclusive o kernel, e apenas processos confiáveis específicos podem se comunicar com os processos (conhecidos como **trustlets**) no VSM. Isso significa que um processo no sistema operacional principal não pode ler a memória do VSM, nem mesmo processos do kernel. A **Autoridade de Segurança Local (LSA) é um dos trustlets** no VSM, além do processo padrão **LSASS** que ainda é executado no sistema operacional principal para garantir suporte aos processos existentes, mas na verdade está apenas atuando como um proxy ou stub para se comunicar com a versão no VSM, garantindo que as credenciais reais sejam executadas na versão do VSM e, portanto, estejam protegidas contra ataques. No Windows 10, o Credential Guard deve ser ativado e implantado em sua organização, pois **não está habilitado por padrão**.
De [https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard). Mais informações e um script PS1 para habilitar o Credential Guard [podem ser encontrados aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage). No entanto, a partir do Windows 11 Enterprise, versão 22H2, e do Windows 11 Education, versão 22H2, sistemas compatíveis têm o Windows Defender Credential Guard [ativado por padrão](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#Default%20Enablement).

Nesse caso, **Mimikatz não pode fazer muito para contornar** isso e extrair os hashes do LSASS. Mas você sempre pode adicionar seu **SSP personalizado** e **capturar as credenciais** quando um usuário tentar fazer login em **texto claro**.\
Mais informações sobre [**SSP e como fazer isso aqui**](../active-directory-methodology/custom-ssp.md).

O Credential Guard pode ser **ativado de diferentes maneiras**. Para verificar se ele foi ativado usando o registro, você pode verificar o valor da chave _**LsaCfgFlags**_ em _**HKLM\System\CurrentControlSet\Control\LSA**_. Se o valor for **"1"**, está ativo com bloqueio UEFI, se **"2"**, está ativo sem bloqueio e se **"0"**, não está habilitado.\
Isso **não é suficiente para habilitar o Credential Guard** (mas é um indicador forte).\
Mais informações e um script PS1 para habilitar o Credential Guard [podem ser encontrados aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
## Modo RestrictedAdmin do RDP

Com o Windows 8.1 e o Windows Server 2012 R2, foram introduzidos novos recursos de segurança. Um desses recursos de segurança é o _modo Restricted Admin para RDP_. Esse novo recurso de segurança é introduzido para mitigar o risco de ataques de [pass the hash](https://blog.ahasayen.com/pass-the-hash/).

Quando você se conecta a um computador remoto usando o RDP, suas credenciais são armazenadas no computador remoto em que você se conecta. Geralmente, você está usando uma conta poderosa para se conectar a servidores remotos, e ter suas credenciais armazenadas em todos esses computadores é realmente uma ameaça à segurança.

Usando o _modo Restricted Admin para RDP_, quando você se conecta a um computador remoto usando o comando **mstsc.exe /RestrictedAdmin**, você será autenticado no computador remoto, mas **suas credenciais não serão armazenadas nesse computador remoto**, como teriam sido no passado. Isso significa que se um malware ou até mesmo um usuário malicioso estiver ativo nesse servidor remoto, suas credenciais não estarão disponíveis nesse servidor de desktop remoto para o malware atacar.

Observe que, como suas credenciais não estão sendo salvas na sessão RDP, se **você tentar acessar recursos de rede**, suas credenciais não serão usadas. **A identidade da máquina será usada em vez disso**.

![](../../.gitbook/assets/ram.png)

De [aqui](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credenciais em cache

As **credenciais de domínio** são usadas pelos componentes do sistema operacional e são **autenticadas** pela **Autoridade de Segurança Local** (LSA). Normalmente, as credenciais de domínio são estabelecidas para um usuário quando um pacote de segurança registrado autentica os dados de logon do usuário. Esse pacote de segurança registrado pode ser o protocolo **Kerberos** ou **NTLM**.

**O Windows armazena as últimas dez credenciais de login de domínio no caso de o controlador de domínio ficar offline**. Se o controlador de domínio ficar offline, um usuário ainda poderá fazer login em seu computador. Esse recurso é principalmente para usuários de laptops que não fazem login regularmente no domínio da empresa. O número de credenciais que o computador armazena pode ser controlado pela seguinte **chave do registro ou por meio de uma política de grupo**:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
As credenciais são ocultadas dos usuários normais, inclusive das contas de administrador. O usuário **SYSTEM** é o único usuário que possui **privilégios** para **visualizar** essas **credenciais**. Para um administrador visualizar essas credenciais no registro, é necessário acessar o registro como usuário SYSTEM.\
As credenciais em cache são armazenadas no registro no seguinte local do registro:
```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```
**Extraindo do Mimikatz**: `lsadump::cache`\
De [aqui](http://juggernaut.wikidot.com/cached-credentials).

## Usuários Protegidos

Quando o usuário logado é membro do grupo Usuários Protegidos, as seguintes proteções são aplicadas:

* A delegação de credenciais (CredSSP) não armazenará em cache as credenciais em texto simples do usuário, mesmo quando a configuração de política de grupo **Permitir a delegação de credenciais padrão** estiver habilitada.
* A partir do Windows 8.1 e do Windows Server 2012 R2, o Windows Digest não armazenará em cache as credenciais em texto simples do usuário, mesmo quando o Windows Digest estiver habilitado.
* O **NTLM** não armazenará em cache as credenciais em texto simples do usuário ou a função unidirecional NT (NTOWF).
* O **Kerberos** não criará mais chaves DES ou RC4. Além disso, não armazenará em cache as credenciais em texto simples do usuário ou chaves de longo prazo após a aquisição do TGT inicial.
* Um verificador em cache não é criado no momento do login ou desbloqueio, portanto, o login offline não é mais suportado.

Após a adição da conta de usuário ao grupo Usuários Protegidos, a proteção começará quando o usuário fizer login no dispositivo. **De** [**aqui**](https://docs.microsoft.com/pt-br/windows-server/security/credentials-protection-and-management/protected-users-security-group)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Operadores de Conta     | Operadores de Conta      | Operadores de Conta                                                          | Operadores de Conta          |
| Administrador           | Administrador            | Administrador                                                                 | Administrador                |
| Administradores         | Administradores          | Administradores                                                               | Administradores              |
| Operadores de Backup    | Operadores de Backup     | Operadores de Backup                                                          | Operadores de Backup         |
| Publicadores de Cert.   |                          |                                                                               |                              |
| Administradores de Domínio | Administradores de Domínio | Administradores de Domínio                                                 | Administradores de Domínio   |
| Controladores de Domínio | Controladores de Domínio | Controladores de Domínio                                                    | Controladores de Domínio     |
| Administradores da Empresa | Administradores da Empresa | Administradores da Empresa                                                 | Administradores da Empresa   |
|                         |                          |                                                                               | Administradores de Chave da Empresa |
|                         |                          |                                                                               | Administradores de Chave     |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Operadores de Impressão | Operadores de Impressão  | Operadores de Impressão                                                       | Operadores de Impressão      |
|                         |                          | Controladores de Domínio Somente Leitura                                      | Controladores de Domínio Somente Leitura |
| Replicador              | Replicador               | Replicador                                                                    | Replicador                   |
| Administradores de Esquema | Administradores de Esquema | Administradores de Esquema                                                 | Administradores de Esquema   |
| Operadores de Servidor  | Operadores de Servidor   | Operadores de Servidor                                                        | Operadores de Servidor       |

**Tabela de** [**aqui**](https://docs.microsoft.com/pt-br/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
