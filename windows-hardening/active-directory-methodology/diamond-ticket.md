# Diamond Ticket

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

## Diamond Ticket

**Comme un ticket en or**, un ticket en diamant est un TGT qui peut être utilisé pour **accéder à n'importe quel service en tant que n'importe quel utilisateur**. Un ticket en or est forgé complètement hors ligne, crypté avec le hash krbtgt de ce domaine, puis passé dans une session de connexion pour utilisation. Parce que les contrôleurs de domaine ne suivent pas les TGT qu'ils (ou ils) ont légitimement émis, ils accepteront volontiers les TGT qui sont cryptés avec leur propre hash krbtgt.

Il existe deux techniques courantes pour détecter l'utilisation de tickets en or :

* Rechercher des TGS-REQ qui n'ont pas de AS-REQ correspondant.
* Rechercher des TGT qui ont des valeurs absurdes, comme la durée de vie par défaut de 10 ans de Mimikatz.

Un **ticket en diamant** est créé en **modifiant les champs d'un TGT légitime qui a été émis par un DC**. Cela est réalisé en **demandant** un **TGT**, en **le décryptant** avec le hash krbtgt du domaine, en **modifiant** les champs souhaités du ticket, puis en **le recryptant**. Cela **surmonte les deux inconvénients mentionnés précédemment** d'un ticket en or car :

* Les TGS-REQ auront un AS-REQ précédent.
* Le TGT a été émis par un DC, ce qui signifie qu'il aura tous les détails corrects de la politique Kerberos du domaine. Même si ceux-ci peuvent être forgés avec précision dans un ticket en or, c'est plus complexe et sujet à des erreurs.
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
{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
