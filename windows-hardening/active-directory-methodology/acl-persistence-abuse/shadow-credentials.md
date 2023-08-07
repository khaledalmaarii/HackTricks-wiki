# Shadow Credentials

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introduction <a href="#3f17" id="3f17"></a>

Consultez le billet original pour [**toutes les informations sur cette technique**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

En résumé : si vous pouvez écrire dans la propriété **msDS-KeyCredentialLink** d'un utilisateur/ordinateur, vous pouvez récupérer le **hachage NT de cet objet**.

Cela est possible car vous pourrez définir des **informations d'authentification de clé publique-privée** pour l'objet et les utiliser pour obtenir un **ticket de service spécial qui contient son hachage NTLM** à l'intérieur du certificat d'attribut de privilège (PAC) dans une entité NTLM\_SUPPLEMENTAL\_CREDENTIAL chiffrée que vous pouvez déchiffrer.

### Prérequis <a href="#2de4" id="2de4"></a>

Cette technique nécessite les éléments suivants :

* Au moins un contrôleur de domaine Windows Server 2016.
* Un certificat numérique pour l'authentification du serveur installé sur le contrôleur de domaine.
* Niveau fonctionnel Windows Server 2016 dans Active Directory.
* Compromettre un compte avec les droits délégués pour écrire dans l'attribut msDS-KeyCredentialLink de l'objet cible.

## Abus

L'abus de la confiance des clés pour les objets d'ordinateur nécessite des étapes supplémentaires après l'obtention d'un TGT et du hachage NTLM du compte. Il existe généralement deux options :

1. Forger un **ticket d'argent RC4** pour se faire passer pour des utilisateurs privilégiés sur l'hôte correspondant.
2. Utiliser le TGT pour appeler **S4U2Self** afin de se faire passer pour des **utilisateurs privilégiés** sur l'hôte correspondant. Cette option nécessite de modifier le ticket de service obtenu pour inclure une classe de service dans le nom du service.

L'abus de la confiance des clés présente l'avantage supplémentaire de ne pas déléguer l'accès à un autre compte qui pourrait être compromis - il est **limité à la clé privée générée par l'attaquant**. De plus, cela ne nécessite pas la création d'un compte d'ordinateur qui peut être difficile à nettoyer tant que l'élévation de privilèges n'est pas réalisée.

Whisker

En complément de ce billet, je publie un outil appelé " [Whisker](https://github.com/eladshamir/Whisker) ". Basé sur le code de DSInternals de Michael, Whisker fournit une interface C# pour effectuer cette attaque lors d'engagements. Whisker met à jour l'objet cible en utilisant LDAP, tandis que DSInternals permet de mettre à jour les objets à la fois en utilisant LDAP et RPC avec le service de réplication de répertoire (DRS) Remote Protocol.

[Whisker](https://github.com/eladshamir/Whisker) dispose de quatre fonctions :

* Add - Cette fonction génère une paire de clés publique-privée et ajoute une nouvelle clé d'authentification à l'objet cible comme si l'utilisateur s'était inscrit à WHfB depuis un nouvel appareil.
* List - Cette fonction répertorie toutes les entrées de l'attribut msDS-KeyCredentialLink de l'objet cible.
* Remove - Cette fonction supprime une clé d'authentification de l'objet cible spécifié par un GUID DeviceID.
* Clear - Cette fonction supprime toutes les valeurs de l'attribut msDS-KeyCredentialLink de l'objet cible. Si l'objet cible utilise légitimement WHfB, cela le cassera.

## [Whisker](https://github.com/eladshamir/Whisker) <a href="#7e2e" id="7e2e"></a>

Whisker est un outil C# permettant de prendre le contrôle des comptes d'utilisateurs et d'ordinateurs Active Directory en manipulant leur attribut `msDS-KeyCredentialLink`, ajoutant ainsi des "Shadow Credentials" au compte cible.

[**Whisker**](https://github.com/eladshamir/Whisker) dispose de quatre fonctions :

* **Add** - Cette fonction génère une paire de clés publique-privée et ajoute une nouvelle clé d'authentification à l'objet cible comme si l'utilisateur s'était inscrit à WHfB depuis un nouvel appareil.
* **List** - Cette fonction répertorie toutes les entrées de l'attribut msDS-KeyCredentialLink de l'objet cible.
* **Remove** - Cette fonction supprime une clé d'authentification de l'objet cible spécifié par un GUID DeviceID.
* **Clear** - Cette fonction supprime toutes les valeurs de l'attribut msDS-KeyCredentialLink de l'objet cible. Si l'objet cible utilise légitimement WHfB, cela le cassera.

### Add

Ajoute une nouvelle valeur à l'attribut **`msDS-KeyCredentialLink`** d'un objet cible :

* `/target:<samAccountName>` : Obligatoire. Définit le nom de la cible. Les objets d'ordinateur doivent se terminer par un signe '$'.
* `/domain:<FQDN>` : Facultatif. Définit le nom de domaine complet (FQDN) de la cible. Si non fourni, tentera de résoudre le FQDN de l'utilisateur actuel.
* `/dc:<IP/HOSTNAME>` : Facultatif. Définit le contrôleur de domaine cible (DC). Si non fourni, tentera de cibler le contrôleur de domaine principal (PDC).
* `/path:<PATH>` : Facultatif. Définit le chemin pour stocker le certificat auto-signé généré pour l'authentification. Si non fourni, le certificat sera affiché sous forme de bloc Base64.
* `/password:<PASWORD>` : Facultatif. Définit le mot de passe du certificat auto-signé stocké. Si non fourni, un mot de passe aléatoire sera généré.

Exemple : **`Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1`**

{% hint style="info" %}
Plus d'options sur le [**Readme**](https://github.com/eladshamir/Whisker).
{% endhint %}
## [pywhisker](https://github.com/ShutdownRepo/pywhisker) <a href="#7e2e" id="7e2e"></a>

pyWhisker est l'équivalent en Python de l'outil Whisker original créé par Elad Shamir et écrit en C#. Cet outil permet aux utilisateurs de manipuler l'attribut msDS-KeyCredentialLink d'un utilisateur/ordinateur cible pour obtenir un contrôle total sur cet objet.

Il est basé sur Impacket et sur une version Python de DSInternals de Michael Grafnetter appelée PyDSInternals créée par podalirius.
Cet outil, ainsi que PKINITtools de Dirk-jan, permettent une exploitation primitive complète uniquement sur les systèmes basés sur UNIX.

pyWhisker peut être utilisé pour effectuer différentes actions sur l'attribut msDs-KeyCredentialLink d'une cible :

- *list* : liste tous les ID et les horaires de création des KeyCredentials actuels
- *info* : affiche toutes les informations contenues dans une structure KeyCredential
- *add* : ajoute un nouveau KeyCredential au msDs-KeyCredentialLink
- *remove* : supprime un KeyCredential du msDs-KeyCredentialLink
- *clear* : supprime tous les KeyCredentials du msDs-KeyCredentialLink
- *export* : exporte tous les KeyCredentials du msDs-KeyCredentialLink au format JSON
- *import* : écrase le msDs-KeyCredentialLink avec les KeyCredentials d'un fichier JSON

pyWhisker prend en charge les authentifications suivantes :
- (NTLM) Mot de passe en clair
- (NTLM) Pass-the-hash
- (Kerberos) Mot de passe en clair
- (Kerberos) Pass-the-key / Overpass-the-hash
- (Kerberos) Pass-the-cache (type de Pass-the-ticket)

![](https://github.com/ShutdownRepo/pywhisker/blob/main/.assets/add_pfx.png)


{% hint style="info" %}
Plus d'options dans le [**Readme**](https://github.com/ShutdownRepo/pywhisker).
{% endhint %}

## [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

Dans plusieurs cas, le groupe "Everyone" / "Authenticated Users" / "Domain Users" ou un autre **groupe étendu** contient presque tous les utilisateurs du domaine et possède des DACLs **GenericWrite**/**GenericAll** **sur d'autres objets** du domaine. [**ShadowSpray**](https://github.com/Dec0ne/ShadowSpray/) tente donc d'**exploiter** les **ShadowCredentials** sur tous ces objets.

Le processus se déroule comme suit :

1. **Se connecter** au domaine avec les informations d'identification fournies (ou utiliser la session en cours).
2. Vérifier que le **niveau fonctionnel du domaine est 2016** (sinon arrêter car l'attaque Shadow Credentials ne fonctionnera pas).
3. Rassembler une **liste de tous les objets** du domaine (utilisateurs et ordinateurs) à partir de LDAP.
4. **Pour chaque objet** de la liste, effectuer les opérations suivantes :
   1. Essayer d'**ajouter un KeyCredential** à l'attribut `msDS-KeyCredentialLink` de l'objet.
   2. Si cela est **réussi**, utiliser **PKINIT** pour demander un **TGT** en utilisant le KeyCredential ajouté.
   3. Si cela est **réussi**, effectuer une attaque **UnPACTheHash** pour révéler le **hachage NT** de l'utilisateur/ordinateur.
   4. Si l'option **`--RestoreShadowCred`** a été spécifiée : supprimer le KeyCredential ajouté (nettoyer après soi-même...).
   5. Si l'option **`--Recursive`** a été spécifiée : effectuer le **même processus** en utilisant chacun des comptes d'utilisateur/ordinateur que nous avons réussi à posséder.

## Références

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com).
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au référentiel [hacktricks](https://github.com/carlospolop/hacktricks) et au référentiel [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
