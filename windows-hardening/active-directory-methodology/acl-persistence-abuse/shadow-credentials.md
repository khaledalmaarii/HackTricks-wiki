# Credentials Shadow

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introduction <a href="#3f17" id="3f17"></a>

Consultez le post original pour [**toutes les informations sur cette technique**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

En **résumé** : si vous pouvez écrire dans la propriété **msDS-KeyCredentialLink** d'un utilisateur/ordinateur, vous pouvez récupérer le **hachage NT de cet objet**.

Cela est possible car vous pourrez définir des **informations d'identification d'authentification clé publique-privée** pour l'objet et les utiliser pour obtenir un **ticket de service spécial qui contient son hachage NTLM** à l'intérieur du certificat d'attribut de privilège (PAC) dans une entité chiffrée NTLM\_SUPPLEMENTAL\_CREDENTIAL que vous pouvez décrypter.

### Exigences <a href="#2de4" id="2de4"></a>

Cette technique nécessite les éléments suivants :

* Au moins un contrôleur de domaine Windows Server 2016.
* Un certificat numérique pour l'authentification du serveur installé sur le contrôleur de domaine.
* Niveau fonctionnel Windows Server 2016 dans Active Directory.
* Compromettre un compte avec les droits délégués pour écrire dans l'attribut msDS-KeyCredentialLink de l'objet cible.

## Abus

L'abus de Key Trust pour les objets informatiques nécessite des étapes supplémentaires après l'obtention d'un TGT et du hachage NTLM pour le compte. Il y a généralement deux options :

1. Forger un **ticket argent RC4** pour se faire passer pour des utilisateurs privilégiés sur l'hôte correspondant.
2. Utilisez le TGT pour appeler **S4U2Self** pour se faire passer pour des **utilisateurs privilégiés** sur l'hôte correspondant. Cette option nécessite de modifier le ticket de service obtenu pour inclure une classe de service dans le nom du service.

L'abus de Key Trust présente l'avantage supplémentaire de ne pas déléguer l'accès à un autre compte qui pourrait être compromis - il est **restreint à la clé privée générée par l'attaquant**. De plus, il ne nécessite pas la création d'un compte informatique qui peut être difficile à nettoyer jusqu'à ce que l'élévation de privilèges soit réalisée.

Whisker

Aux côtés de ce post, je publie un outil appelé " [Whisker](https://github.com/eladshamir/Whisker) ". Basé sur le code de DSInternals de Michael, Whisker fournit une enveloppe C# pour effectuer cette attaque lors d'engagements. Whisker met à jour l'objet cible en utilisant LDAP, tandis que DSInternals permet de mettre à jour les objets à la fois en utilisant LDAP et RPC avec le service de réplication d'annuaire (DRS) Remote Protocol.

[Whisker](https://github.com/eladshamir/Whisker) a quatre fonctions :

* Ajouter - Cette fonction génère une paire de clés publique-privée et ajoute une nouvelle clé d'informations d'identification à l'objet cible comme si
