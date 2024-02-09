# Jetons d'accès

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Vous voulez voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Jetons d'accès

Chaque **utilisateur connecté** au système **détient un jeton d'accès avec des informations de sécurité** pour cette session de connexion. Le système crée un jeton d'accès lorsque l'utilisateur se connecte. **Chaque processus exécuté** au nom de l'utilisateur **dispose d'une copie du jeton d'accès**. Le jeton identifie l'utilisateur, les groupes de l'utilisateur et les privilèges de l'utilisateur. Un jeton contient également un SID de connexion (Security Identifier) qui identifie la session de connexion actuelle.

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
ou en utilisant _Process Explorer_ de Sysinternals (sélectionnez le processus et accédez à l'onglet "Sécurité") :

![](<../../.gitbook/assets/image (321).png>)

### Administrateur local

Lorsqu'un administrateur local se connecte, **deux jetons d'accès sont créés** : un avec des droits d'administrateur et un autre avec des droits normaux. **Par défaut**, lorsque cet utilisateur exécute un processus, celui avec des **droits normaux (non administrateur) est utilisé**. Lorsque cet utilisateur essaie d'**exécuter** quelque chose **en tant qu'administrateur** (par exemple, "Exécuter en tant qu'administrateur"), l'**UAC** sera utilisé pour demander la permission.\
Si vous souhaitez [**en savoir plus sur l'UAC, lisez cette page**](../authentication-credentials-uac-and-efs.md#uac)**.**

### Impersonation d'utilisateur avec des informations d'identification

Si vous avez les **informations d'identification valides d'un autre utilisateur**, vous pouvez **créer** une **nouvelle session de connexion** avec ces informations d'identification :
```
runas /user:domain\username cmd.exe
```
L'**jeton d'accès** contient également une **référence** des sessions de connexion à l'intérieur du **LSASS**, ce qui est utile si le processus doit accéder à certains objets du réseau.\
Vous pouvez lancer un processus qui **utilise des informations d'identification différentes pour accéder aux services réseau** en utilisant :
```
runas /user:domain\username /netonly cmd.exe
```
Cela est utile si vous avez des informations d'identification utiles pour accéder à des objets dans le réseau mais que ces informations d'identification ne sont pas valides à l'intérieur de l'hôte actuel car elles ne seront utilisées que dans le réseau (dans l'hôte actuel, vos privilèges utilisateur actuels seront utilisés).

### Types de jetons

Il existe deux types de jetons disponibles :

* **Jeton principal** : Il sert de représentation des informations d'identification de sécurité d'un processus. La création et l'association de jetons principaux avec des processus sont des actions qui nécessitent des privilèges élevés, mettant en avant le principe de séparation des privilèges. En général, un service d'authentification est responsable de la création du jeton, tandis qu'un service de connexion gère son association avec l'interpréteur de commandes de l'utilisateur. Il convient de noter que les processus héritent du jeton principal de leur processus parent lors de leur création.

* **Jeton d'usurpation** : Permet à une application serveur d'adopter temporairement l'identité du client pour accéder à des objets sécurisés. Ce mécanisme est stratifié en quatre niveaux d'opération :
- **Anonyme** : Accorde à un serveur un accès similaire à celui d'un utilisateur non identifié.
- **Identification** : Permet au serveur de vérifier l'identité du client sans l'utiliser pour accéder aux objets.
- **Usurpation** : Permet au serveur de fonctionner sous l'identité du client.
- **Délégation** : Similaire à l'Usurpation mais inclut la capacité d'étendre cette supposition d'identité aux systèmes distants avec lesquels le serveur interagit, garantissant la préservation des informations d'identification.

#### Usurper des jetons

En utilisant le module _**incognito**_ de Metasploit, si vous avez suffisamment de privilèges, vous pouvez facilement **list** et **usurper** d'autres **jetons**. Cela pourrait être utile pour effectuer des **actions comme si vous étiez l'autre utilisateur**. Vous pourriez également **escalader les privilèges** avec cette technique.

### Privilèges des jetons

Apprenez quels **privilèges des jetons peuvent être abusés pour escalader les privilèges :**

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

Jetez un œil à [**tous les privilèges de jetons possibles et quelques définitions sur cette page externe**](https://github.com/gtworek/Priv2Admin).

## Références

Apprenez-en plus sur les jetons dans ces tutoriels : [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) et [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
