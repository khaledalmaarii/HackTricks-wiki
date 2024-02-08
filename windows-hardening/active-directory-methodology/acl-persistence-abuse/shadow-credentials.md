# Informations d'identification fantômes

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Vous voulez voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introduction <a href="#3f17" id="3f17"></a>

**Consultez le post original pour [toutes les informations sur cette technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

En **résumé**: si vous pouvez écrire dans la propriété **msDS-KeyCredentialLink** d'un utilisateur/ordinateur, vous pouvez récupérer le **hachage NT de cet objet**.

Dans le post, une méthode est décrite pour configurer des **informations d'identification d'authentification clé publique-privée** afin d'acquérir un **billet de service** unique qui inclut le hachage NTLM de la cible. Ce processus implique le hachage NTLM_SUPPLEMENTAL_CREDENTIAL crypté dans le Certificat d'Attribut de Privilège (PAC), qui peut être déchiffré.

### Conditions requises

Pour appliquer cette technique, certaines conditions doivent être remplies :
- Un minimum d'un contrôleur de domaine Windows Server 2016 est nécessaire.
- Le contrôleur de domaine doit avoir un certificat numérique d'authentification de serveur installé.
- L'Active Directory doit être au niveau fonctionnel Windows Server 2016.
- Un compte avec des droits délégués pour modifier l'attribut msDS-KeyCredentialLink de l'objet cible est requis.

## Abus

L'abus de Key Trust pour les objets informatiques englobe des étapes au-delà de l'obtention d'un Ticket Granting Ticket (TGT) et du hachage NTLM. Les options incluent :
1. Créer un **billet d'argent RC4** pour agir en tant qu'utilisateurs privilégiés sur l'hôte prévu.
2. Utiliser le TGT avec **S4U2Self** pour l'usurpation d'**utilisateurs privilégiés**, nécessitant des modifications au billet de service pour ajouter une classe de service au nom du service.

Un avantage significatif de l'abus de Key Trust est sa limitation à la clé privée générée par l'attaquant, évitant la délégation à des comptes potentiellement vulnérables et ne nécessitant pas la création d'un compte informatique, ce qui pourrait être difficile à supprimer.

## Outils

### [**Whisker**](https://github.com/eladshamir/Whisker)

Basé sur DSInternals fournissant une interface C# pour cette attaque. Whisker et son homologue Python, **pyWhisker**, permettent la manipulation de l'attribut `msDS-KeyCredentialLink` pour prendre le contrôle des comptes Active Directory. Ces outils prennent en charge diverses opérations telles que l'ajout, la liste, la suppression et l'effacement des informations d'identification clés de l'objet cible.

Les fonctions de **Whisker** incluent :
- **Ajouter** : Génère une paire de clés et ajoute une information d'identification clé.
- **Lister** : Affiche toutes les entrées d'informations d'identification clé.
- **Supprimer** : Supprime une information d'identification clé spécifiée.
- **Effacer** : Efface toutes les informations d'identification clés, perturbant potentiellement l'utilisation légitime de WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Il étend la fonctionnalité de Whisker aux systèmes **basés sur UNIX**, en exploitant Impacket et PyDSInternals pour des capacités d'exploitation complètes, y compris la liste, l'ajout et la suppression de KeyCredentials, ainsi que leur importation et exportation au format JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray vise à **exploiter les autorisations GenericWrite/GenericAll que de larges groupes d'utilisateurs peuvent avoir sur les objets de domaine** pour appliquer largement les ShadowCredentials. Cela implique de se connecter au domaine, de vérifier le niveau fonctionnel du domaine, d'énumérer les objets de domaine, et de tenter d'ajouter des KeyCredentials pour l'acquisition de TGT et la révélation du hachage NT. Les options de nettoyage et les tactiques d'exploitation récursive améliorent son utilité.


## Références

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
