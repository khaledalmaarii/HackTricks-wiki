# Diamond Ticket

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Diamond Ticket

**Comme un golden ticket**, un diamond ticket est un TGT qui peut être utilisé pour **accéder à n'importe quel service en tant que n'importe quel utilisateur**. Un golden ticket est forgé entièrement hors ligne, chiffré avec le hash krbtgt de ce domaine, puis inséré dans une session de connexion pour utilisation. Comme les contrôleurs de domaine ne suivent pas les TGTs qu'ils ont légitimement émis, ils accepteront volontiers les TGTs qui sont chiffrés avec leur propre hash krbtgt.

Il existe deux techniques courantes pour détecter l'utilisation de golden tickets :

* Rechercher des TGS-REQs qui n'ont pas de AS-REQ correspondant.
* Rechercher des TGTs qui ont des valeurs absurdes, telles que la durée de vie par défaut de 10 ans de Mimikatz.

Un **diamond ticket** est créé en **modifiant les champs d'un TGT légitime qui a été émis par un DC**. Cela est réalisé en **demandant** un **TGT**, en le **déchiffrant** avec le hash krbtgt du domaine, en **modifiant** les champs souhaités du ticket, puis en le **rechiffrant**. Cela **surmonte les deux inconvénients mentionnés ci-dessus** d'un golden ticket car :

* Les TGS-REQs auront un AS-REQ précédent.
* Le TGT a été émis par un DC, ce qui signifie qu'il aura tous les détails corrects de la politique Kerberos du domaine. Même si ces détails peuvent être forgés avec précision dans un golden ticket, c'est plus complexe et sujet à des erreurs.
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
```markdown
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
