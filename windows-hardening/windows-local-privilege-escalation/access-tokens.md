# Jetons d'accès

Chaque **utilisateur connecté** au système **possède un jeton d'accès avec des informations de sécurité** pour cette session de connexion. Le système crée un jeton d'accès lorsque l'utilisateur se connecte. **Chaque processus exécuté** au nom de l'utilisateur **a une copie du jeton d'accès**. Le jeton identifie l'utilisateur, les groupes de l'utilisateur et les privilèges de l'utilisateur. Un jeton contient également un SID de connexion (identificateur de sécurité) qui identifie la session de connexion actuelle.

Vous pouvez voir ces informations en exécutant `whoami /all`.
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

Lorsqu'un administrateur local se connecte, **deux jetons d'accès sont créés** : un avec des droits d'administrateur et l'autre avec des droits normaux. **Par défaut**, lorsque cet utilisateur exécute un processus, celui avec des droits **normaux est utilisé**. Lorsque cet utilisateur essaie d'**exécuter** quelque chose **en tant qu'administrateur** ("Exécuter en tant qu'administrateur", par exemple), l'**UAC** sera utilisé pour demander la permission.\
Si vous voulez [**en savoir plus sur l'UAC, lisez cette page**](../authentication-credentials-uac-and-efs.md#uac)**.**

### Impersonation d'utilisateur de crédential

Si vous avez les **crédentials valides de tout autre utilisateur**, vous pouvez **créer** une **nouvelle session de connexion** avec ces crédentials :
```
runas /user:domain\username cmd.exe
```
Le **jeton d'accès** contient également une **référence** des sessions de connexion à l'intérieur de **LSASS**, ce qui est utile si le processus doit accéder à certains objets du réseau.\
Vous pouvez lancer un processus qui **utilise des informations d'identification différentes pour accéder aux services réseau** en utilisant:
```
runas /user:domain\username /netonly cmd.exe
```
Ceci est utile si vous avez des informations d'identification pour accéder à des objets dans le réseau, mais que ces informations d'identification ne sont pas valides à l'intérieur de l'hôte actuel car elles ne seront utilisées que dans le réseau (dans l'hôte actuel, les privilèges de votre utilisateur actuel seront utilisés).

### Types de jetons

Il existe deux types de jetons disponibles :

* **Jeton primaire** : Les jetons primaires ne peuvent être **associés qu'à des processus**, et ils représentent le sujet de sécurité d'un processus. La création de jetons primaires et leur association à des processus sont toutes deux des opérations privilégiées, nécessitant deux privilèges différents au nom de la séparation des privilèges - le scénario typique voit le service d'authentification créer le jeton, et un service de connexion l'associer à la coquille du système d'exploitation de l'utilisateur. Les processus héritent initialement d'une copie du jeton primaire du processus parent.
* **Jeton d'usurpation** : L'usurpation est un concept de sécurité implémenté dans Windows NT qui **permet** à une application serveur de "**devenir**" **temporairement** **le client** en termes d'accès aux objets sécurisés. L'usurpation a **quatre niveaux possibles** :

    * **anonyme**, donnant au serveur l'accès d'un utilisateur anonyme/non identifié
    * **identification**, permettant au serveur d'inspecter l'identité du client mais de ne pas utiliser cette identité pour accéder aux objets
    * **usurpation**, permettant au serveur d'agir au nom du client
    * **délégation**, identique à l'usurpation mais étendue aux systèmes distants auxquels le serveur se connecte (par la préservation des informations d'identification).

    Le client peut choisir le niveau d'usurpation maximal (s'il y en a un) disponible pour le serveur en tant que paramètre de connexion. L'usurpation et la délégation sont des opérations privilégiées (l'usurpation ne l'était pas initialement, mais la négligence historique dans la mise en œuvre des API client qui ont omis de restreindre le niveau par défaut à "identification", permettant à un serveur non privilégié d'usurper un client privilégié réticent, a appelé à cela). **Les jetons d'usurpation ne peuvent être associés qu'à des threads**, et ils représentent le sujet de sécurité d'un processus client. Les jetons d'usurpation sont généralement créés et associés au thread actuel implicitement, par des mécanismes IPC tels que DCE RPC, DDE et les pipes nommées.

#### Jetons d'usurpation

En utilisant le module _**incognito**_\*\* de Metasploit, si vous avez suffisamment de privilèges, vous pouvez facilement **list** et **usurper** d'autres **jetons**. Cela pourrait être utile pour effectuer des **actions comme si vous étiez l'autre utilisateur**. Vous pourriez également **escalader les privilèges** avec cette technique.

### Privilèges de jeton

Apprenez quels **privilèges de jeton peuvent être abusés pour escalader les privilèges** :

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

Jetez un coup d'œil à [**tous les privilèges de jeton possibles et certaines définitions sur cette page externe**](https://github.com/gtworek/Priv2Admin).

## Références

En savoir plus sur les jetons dans ces tutoriels : [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) et [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
