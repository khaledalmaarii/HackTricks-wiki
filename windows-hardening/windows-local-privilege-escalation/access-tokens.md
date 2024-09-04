# Access Tokens

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


## Access Tokens

Chaque **utilisateur connecté** au système **possède un jeton d'accès avec des informations de sécurité** pour cette session de connexion. Le système crée un jeton d'accès lorsque l'utilisateur se connecte. **Chaque processus exécuté** au nom de l'utilisateur **a une copie du jeton d'accès**. Le jeton identifie l'utilisateur, les groupes de l'utilisateur et les privilèges de l'utilisateur. Un jeton contient également un SID de connexion (Identifiant de sécurité) qui identifie la session de connexion actuelle.

Vous pouvez voir ces informations en exécutant `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![](<../../.gitbook/assets/image (772).png>)

### Administrateur local

Lorsque un administrateur local se connecte, **deux jetons d'accès sont créés** : Un avec des droits d'administrateur et l'autre avec des droits normaux. **Par défaut**, lorsque cet utilisateur exécute un processus, celui avec des **droits réguliers** (non-administrateur) **est utilisé**. Lorsque cet utilisateur essaie d'**exécuter** quoi que ce soit **en tant qu'administrateur** ("Exécuter en tant qu'administrateur" par exemple), le **UAC** sera utilisé pour demander la permission.\
Si vous voulez [**en savoir plus sur le UAC, lisez cette page**](../authentication-credentials-uac-and-efs/#uac)**.**

### Usurpation d'identité des utilisateurs avec des identifiants

Si vous avez **des identifiants valides d'un autre utilisateur**, vous pouvez **créer** une **nouvelle session de connexion** avec ces identifiants :
```
runas /user:domain\username cmd.exe
```
Le **jeton d'accès** a également une **référence** des sessions de connexion à l'intérieur de **LSASS**, ce qui est utile si le processus doit accéder à certains objets du réseau.\
Vous pouvez lancer un processus qui **utilise des identifiants différents pour accéder aux services réseau** en utilisant :
```
runas /user:domain\username /netonly cmd.exe
```
Ceci est utile si vous avez des identifiants utiles pour accéder à des objets dans le réseau, mais ces identifiants ne sont pas valides à l'intérieur de l'hôte actuel car ils ne seront utilisés que dans le réseau (dans l'hôte actuel, vos privilèges d'utilisateur actuels seront utilisés).

### Types de jetons

Il existe deux types de jetons disponibles :

* **Jeton principal** : Il sert de représentation des identifiants de sécurité d'un processus. La création et l'association de jetons principaux avec des processus sont des actions qui nécessitent des privilèges élevés, soulignant le principe de séparation des privilèges. En général, un service d'authentification est responsable de la création de jetons, tandis qu'un service de connexion gère son association avec le shell du système d'exploitation de l'utilisateur. Il convient de noter que les processus héritent du jeton principal de leur processus parent lors de leur création.
* **Jeton d'imitation** : Permet à une application serveur d'adopter temporairement l'identité du client pour accéder à des objets sécurisés. Ce mécanisme est stratifié en quatre niveaux de fonctionnement :
* **Anonyme** : Accorde un accès serveur similaire à celui d'un utilisateur non identifié.
* **Identification** : Permet au serveur de vérifier l'identité du client sans l'utiliser pour l'accès aux objets.
* **Imitation** : Permet au serveur d'opérer sous l'identité du client.
* **Délégation** : Semblable à l'imitation, mais inclut la capacité d'étendre cette hypothèse d'identité aux systèmes distants avec lesquels le serveur interagit, garantissant la préservation des identifiants.

#### Jetons d'imitation

En utilisant le module _**incognito**_ de metasploit, si vous avez suffisamment de privilèges, vous pouvez facilement **lister** et **imiter** d'autres **jetons**. Cela pourrait être utile pour effectuer des **actions comme si vous étiez l'autre utilisateur**. Vous pourriez également **escalader les privilèges** avec cette technique.

### Privilèges des jetons

Apprenez quels **privilèges de jeton peuvent être abusés pour escalader les privilèges :**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Jetez un œil à [**tous les privilèges de jeton possibles et quelques définitions sur cette page externe**](https://github.com/gtworek/Priv2Admin).

## Références

En savoir plus sur les jetons dans ces tutoriels : [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) et [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)


{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR au** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
