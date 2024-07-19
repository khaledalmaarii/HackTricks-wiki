# Shadow Credentials

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Intro <a href="#3f17" id="3f17"></a>

**Check the original post for [all the information about this technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

En **résumé** : si vous pouvez écrire dans la propriété **msDS-KeyCredentialLink** d'un utilisateur/d'un ordinateur, vous pouvez récupérer le **hash NT de cet objet**.

Dans le post, une méthode est décrite pour configurer des **informations d'authentification par clé publique-privée** afin d'acquérir un **Ticket de Service** unique qui inclut le hash NTLM de la cible. Ce processus implique le NTLM_SUPPLEMENTAL_CREDENTIAL chiffré dans le Certificat d'Attribut de Privilège (PAC), qui peut être déchiffré.

### Requirements

Pour appliquer cette technique, certaines conditions doivent être remplies :
- Un minimum d'un contrôleur de domaine Windows Server 2016 est nécessaire.
- Le contrôleur de domaine doit avoir un certificat numérique d'authentification de serveur installé.
- L'Active Directory doit être au niveau fonctionnel Windows Server 2016.
- Un compte avec des droits délégués pour modifier l'attribut msDS-KeyCredentialLink de l'objet cible est requis.

## Abuse

L'abus de Key Trust pour les objets informatiques englobe des étapes au-delà de l'obtention d'un Ticket Granting Ticket (TGT) et du hash NTLM. Les options incluent :
1. Créer un **ticket argent RC4** pour agir en tant qu'utilisateurs privilégiés sur l'hôte prévu.
2. Utiliser le TGT avec **S4U2Self** pour l'imitation des **utilisateurs privilégiés**, nécessitant des modifications du Ticket de Service pour ajouter une classe de service au nom du service.

Un avantage significatif de l'abus de Key Trust est sa limitation à la clé privée générée par l'attaquant, évitant la délégation à des comptes potentiellement vulnérables et ne nécessitant pas la création d'un compte d'ordinateur, ce qui pourrait être difficile à supprimer.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Il est basé sur DSInternals fournissant une interface C# pour cette attaque. Whisker et son homologue Python, **pyWhisker**, permettent de manipuler l'attribut `msDS-KeyCredentialLink` pour prendre le contrôle des comptes Active Directory. Ces outils prennent en charge diverses opérations telles que l'ajout, la liste, la suppression et l'effacement des informations d'identification clés de l'objet cible.

Les fonctions de **Whisker** incluent :
- **Add** : Génère une paire de clés et ajoute une information d'identification clé.
- **List** : Affiche toutes les entrées d'informations d'identification clés.
- **Remove** : Supprime une information d'identification clé spécifiée.
- **Clear** : Efface toutes les informations d'identification clés, perturbant potentiellement l'utilisation légitime de WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Il étend la fonctionnalité de Whisker aux **systèmes basés sur UNIX**, en s'appuyant sur Impacket et PyDSInternals pour des capacités d'exploitation complètes, y compris la liste, l'ajout et la suppression de KeyCredentials, ainsi que l'importation et l'exportation au format JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray vise à **exploiter les permissions GenericWrite/GenericAll que de larges groupes d'utilisateurs peuvent avoir sur les objets de domaine** pour appliquer les ShadowCredentials de manière étendue. Cela implique de se connecter au domaine, de vérifier le niveau fonctionnel du domaine, d'énumérer les objets de domaine et d'essayer d'ajouter des KeyCredentials pour l'acquisition de TGT et la révélation du hachage NT. Les options de nettoyage et les tactiques d'exploitation récursive améliorent son utilité.


## Références

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
