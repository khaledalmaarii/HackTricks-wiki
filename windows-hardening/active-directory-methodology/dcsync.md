# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
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

To perform a DCSync attack, the attacker needs to have administrative privileges on a compromised machine within the domain. Once access is gained, the attacker can use the `mimikatz` tool to execute the DCSync command and retrieve the password hashes.

The DCSync command can be executed using the following syntax:

```
mimikatz # lsadump::dcsync /domain:<domain_name> /user:<username>
```

Replace `<domain_name>` with the name of the target domain and `<username>` with the username of the account whose password hash is to be retrieved.

By successfully executing the DCSync command, the attacker can obtain the password hashes of domain user accounts, including those of privileged users such as administrators. These password hashes can then be cracked offline using tools like `hashcat` to obtain the actual passwords.

It is important to note that the DCSync technique requires administrative privileges on a compromised machine within the domain. Therefore, it is crucial to implement strong security measures to prevent unauthorized access and privilege escalation within the Active Directory environment.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Explorar Remotamente

DCSync is a technique that allows an attacker to impersonate a domain controller and request the replication of password data from the targeted domain controller. This technique can be used remotely to extract password hashes from the Active Directory database without the need for administrative privileges.

To exploit this vulnerability remotely, follow these steps:

1. Identify the target domain controller: Determine the IP address or hostname of the domain controller you want to exploit.

2. Enumerate domain users: Use tools like `ldapsearch` or `PowerView` to enumerate the users in the target domain.

3. Identify a user with sufficient privileges: Look for a user account with the "Replicating Directory Changes All" or "Replicating Directory Changes" permissions. These permissions allow the user to replicate the Active Directory database.

4. Extract the user's NTLM hash: Use the DCSync command to request the replication of password data for the identified user. The command syntax is as follows:

   ```
   mimikatz # lsadump::dcsync /domain:<domain_name> /user:<username>
   ```

   Replace `<domain_name>` with the name of the target domain and `<username>` with the username of the user account with sufficient privileges.

5. Retrieve the NTLM hash: Once the DCSync command is executed successfully, the NTLM hash of the user's password will be displayed in the output.

By following these steps, you can remotely exploit the DCSync vulnerability to extract password hashes from a target domain controller. These password hashes can then be used for further attacks, such as password cracking or pass-the-hash attacks.
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

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
