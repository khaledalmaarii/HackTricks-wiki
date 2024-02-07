# Informations d'identification fantômes

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez** le [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le **groupe Telegram** ou **suivez** moi sur **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introduction <a href="#3f17" id="3f17"></a>

Consultez le post original pour [**toutes les informations sur cette technique**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

En **résumé** : si vous pouvez écrire dans la propriété **msDS-KeyCredentialLink** d'un utilisateur/ordinateur, vous pouvez récupérer le **hachage NT de cet objet**.

Cela est possible car vous pourrez définir des **informations d'identification d'authentification clé publique-privée** pour l'objet et les utiliser pour obtenir un **billet de service spécial contenant son hachage NT** à l'intérieur du certificat d'attribut de privilège (PAC) dans une entité chiffrée NTLM\_SUPPLEMENTAL\_CREDENTIAL que vous pouvez décrypter.

### Exigences <a href="#2de4" id="2de4"></a>

Cette technique nécessite ce qui suit :

* Au moins un contrôleur de domaine Windows Server 2016.
* Un certificat numérique pour l'authentification du serveur installé sur le contrôleur de domaine.
* Niveau fonctionnel Windows Server 2016 dans Active Directory.
* Compromettre un compte avec les droits délégués pour écrire dans l'attribut msDS-KeyCredentialLink de l'objet cible.

## Abus

L'abus de Key Trust pour les objets informatiques nécessite des étapes supplémentaires après l'obtention d'un TGT et du hachage NT pour le compte. Il existe généralement deux options :

1. Forger un **billet d'argent RC4** pour se faire passer pour des utilisateurs privilégiés sur l'hôte correspondant.
2. Utiliser le TGT pour appeler **S4U2Self** pour se faire passer pour des **utilisateurs privilégiés** sur l'hôte correspondant. Cette option nécessite de modifier le billet de service obtenu pour inclure une classe de service dans le nom du service.

L'abus de Key Trust présente l'avantage supplémentaire de ne pas déléguer l'accès à un autre compte qui pourrait être compromis - il est **limité à la clé privée générée par l'attaquant**. De plus, cela ne nécessite pas la création d'un compte informatique qui pourrait être difficile à nettoyer jusqu'à ce que l'élévation de privilèges soit réalisée.

Whisker

En parallèle de ce post, je publie un outil appelé " [Whisker](https://github.com/eladshamir/Whisker) ". Basé sur le code de DSInternals de Michael, Whisker fournit un wrapper C# pour effectuer cette attaque lors d'engagements. Whisker met à jour l'objet cible en utilisant LDAP, tandis que DSInternals permet de mettre à jour des objets à la fois en utilisant LDAP et RPC avec le service de réplication de répertoire (DRS) Remote Protocol.

[Whisker](https://github.com/eladshamir/Whisker) a quatre fonctions :

* Ajouter - Cette fonction génère une paire de clés publique-privée et ajoute une nouvelle clé d'informations d'identification à l'objet cible comme si l'utilisateur s'était inscrit à WHfB à partir d'un nouveau périphérique.
* Liste - Cette fonction répertorie toutes les entrées de l'attribut msDS-KeyCredentialLink de l'objet cible.
* Supprimer - Cette fonction supprime une clé d'informations d'identification de l'objet cible spécifiée par un GUID DeviceID.
* Effacer - Cette fonction supprime toutes les valeurs de l'attribut msDS-KeyCredentialLink de l'objet cible. Si l'objet cible utilise légitimement WHfB, cela le cassera.

## [Whisker](https://github.com/eladshamir/Whisker) <a href="#7e2e" id="7e2e"></a>

Whisker est un outil C# pour prendre le contrôle des comptes d'utilisateurs et d'ordinateurs Active Directory en manipulant leur attribut `msDS-KeyCredentialLink`, ajoutant efficacement des "Informations d'identification fantômes" au compte cible.

[**Whisker**](https://github.com/eladshamir/Whisker) a quatre fonctions :

* **Ajouter** - Cette fonction génère une paire de clés publique-privée et ajoute une nouvelle clé d'informations d'identification à l'objet cible comme si l'utilisateur s'était inscrit à WHfB à partir d'un nouveau périphérique.
* **Liste** - Cette fonction répertorie toutes les entrées de l'attribut msDS-KeyCredentialLink de l'objet cible.
* **Supprimer** - Cette fonction supprime une clé d'informations d'identification de l'objet cible spécifiée par un GUID DeviceID.
* **Effacer** - Cette fonction supprime toutes les valeurs de l'attribut msDS-KeyCredentialLink de l'objet cible. Si l'objet cible utilise légitimement WHfB, cela le cassera.

### Ajouter

Ajouter une nouvelle valeur à l'attribut **`msDS-KeyCredentialLink`** d'un objet cible :

* `/cible:<samAccountName>`: Requis. Définir le nom de la cible. Les objets informatiques doivent se terminer par un signe '$'.
* `/domaine:<FQDN>`: Optionnel. Définir le nom de domaine complet de la cible (FQDN). Si non fourni, tentera de résoudre le FQDN de l'utilisateur actuel.
* `/dc:<IP/HOSTNAME>`: Optionnel. Définir le contrôleur de domaine cible (DC). Si non fourni, ciblera le contrôleur de domaine principal (PDC).
* `/chemin:<CHEMIN>`: Optionnel. Définir le chemin pour stocker le certificat auto-signé généré pour l'authentification. Si non fourni, le certificat sera affiché sous forme de blob Base64.
* `/motdepasse:<MOTDEPASSE>`: Optionnel. Définir le mot de passe pour le certificat auto-signé stocké. Si non fourni, un mot de passe aléatoire sera généré.

Exemple : **`Whisker.exe add /cible:nomordinateur$ /domaine:constoso.local /dc:dc1.contoso.local /chemin:C:\chemin\vers\fichier.pfx /motdepasse:P@ssword1`**

{% hint style="info" %}
Plus d'options sur le [**Readme**](https://github.com/eladshamir/Whisker).
{% endhint %}

## [pywhisker](https://github.com/ShutdownRepo/pywhisker) <a href="#7e2e" id="7e2e"></a>

pyWhisker est l'équivalent en Python du Whisker original créé par Elad Shamir et écrit en C#. Cet outil permet aux utilisateurs de manipuler l'attribut msDS-KeyCredentialLink d'un utilisateur/ordinateur cible pour obtenir un contrôle total sur cet objet.

Il est basé sur Impacket et sur un équivalent en Python de DSInternals de Michael Grafnetter appelé PyDSInternals créé par podalirius.
Cet outil, avec les PKINITtools de Dirk-jan, permet une exploitation primitive complète uniquement sur les systèmes basés sur UNIX.

pyWhisker peut être utilisé pour effectuer diverses actions sur l'attribut msDs-KeyCredentialLink d'une cible

- *liste* : liste tous les ID et l'heure de création actuels des KeyCredentials
- *info* : affiche toutes les informations contenues dans une structure KeyCredential
- *ajouter* : ajoute un nouveau KeyCredential au msDs-KeyCredentialLink
- *supprimer* : supprime un KeyCredential du msDs-KeyCredentialLink
- *effacer* : supprime tous les KeyCredentials du msDs-KeyCredentialLink
- *exporter* : exporte tous les KeyCredentials du msDs-KeyCredentialLink en JSON
- *importer* : écrase le msDs-KeyCredentialLink avec les KeyCredentials d'un fichier JSON

pyWhisker prend en charge les authentifications suivantes :
- (NTLM) Mot de passe en clair
- (NTLM) Pass-the-hash
- (Kerberos) Mot de passe en clair
- (Kerberos) Pass-the-key / Overpass-the-hash
- (Kerberos) Pass-the-cache (type de Pass-the-ticket)

![](https://github.com/ShutdownRepo/pywhisker/blob/main/.assets/add_pfx.png)

{% hint style="info" %}
Plus d'options sur le [**Readme**](https://github.com/ShutdownRepo/pywhisker).
{% endhint %}

## [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

Dans plusieurs cas, le groupe "Everyone" / "Authenticated Users" / "Domain Users" ou un autre **groupe étendu** contient presque tous les utilisateurs du domaine et a des DACLs **GenericWrite**/**GenericAll** **sur d'autres objets** dans le domaine. [**ShadowSpray**](https://github.com/Dec0ne/ShadowSpray/) tente donc d'**abuser** des **Informations d'identification fantômes** sur tous ces objets

Cela se déroule comme suit :

1. **Connectez-vous** au domaine avec les informations d'identification fournies (ou utilisez la session actuelle).
2. Vérifiez que le **niveau fonctionnel du domaine est 2016** (sinon arrêtez car l'attaque des Informations d'identification fantômes ne fonctionnera pas)
3. Rassemblez une **liste de tous les objets** dans le domaine (utilisateurs et ordinateurs) à partir de LDAP.
4. **Pour chaque objet** de la liste, faites ce qui suit :
1. Essayez d'**ajouter une KeyCredential** à l'attribut `msDS-KeyCredentialLink` de l'objet.
2. Si cela est **réussi**, utilisez **PKINIT** pour demander un **TGT** en utilisant la KeyCredential ajoutée.
3. Si cela est **réussi**, effectuez une attaque **UnPACTheHash** pour révéler le hachage NT de l'utilisateur/ordinateur.
4. Si **`--RestoreShadowCred`** a été spécifié : Supprimez la KeyCredential ajoutée (nettoyez après vous...)
5. Si **`--Recursive`** a été spécifié : Faites le **même processus** en utilisant chacun des comptes d'utilisateur/ordinateur **que nous avons réussi à posséder**.

## Références

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
