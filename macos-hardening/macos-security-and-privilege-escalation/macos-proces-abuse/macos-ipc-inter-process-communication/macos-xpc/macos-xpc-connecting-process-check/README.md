# Vérification de la connexion des processus XPC sur macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Vérification de la connexion des processus XPC

Lorsqu'une connexion est établie vers un service XPC, le serveur vérifie si la connexion est autorisée. Voici les vérifications qu'il effectue généralement :

1. Vérifier si le **processus connectant est signé avec un certificat signé par Apple** (uniquement délivré par Apple).
* Si cela **n'est pas vérifié**, un attaquant peut créer un **faux certificat** pour correspondre à toute autre vérification.
2. Vérifier si le processus connectant est signé avec le **certificat de l'organisation** (vérification de l'ID de l'équipe).
* Si cela **n'est pas vérifié**, **n'importe quel certificat de développeur** d'Apple peut être utilisé pour la signature et la connexion au service.
3. Vérifier si le processus connectant **contient un ID de bundle approprié**.
* Si cela **n'est pas vérifié**, n'importe quel outil **signé par la même organisation** pourrait être utilisé pour interagir avec le service XPC.
4. (4 ou 5) Vérifier si le processus connectant a un **numéro de version logicielle approprié**.
* Si cela **n'est pas vérifié**, des clients anciens et non sécurisés, vulnérables à l'injection de processus, pourraient être utilisés pour se connecter au service XPC même avec les autres vérifications en place.
5. (4 ou 5) Vérifier si le processus connectant a un runtime renforcé sans autorisations dangereuses (comme celles qui permettent de charger des bibliothèques arbitraires ou d'utiliser des variables d'environnement DYLD).
* Si cela **n'est pas vérifié**, le client pourrait être **vulnérable à l'injection de code**.
6. Vérifier si le processus connectant possède une **autorisation** qui lui permet de se connecter au service. Cela s'applique aux binaires Apple.
7. La **vérification** doit être **basée** sur le **jeton d'audit du client connectant** plutôt que sur son ID de processus (**PID**), car cela empêche les attaques de réutilisation de PID.
* Les développeurs utilisent rarement l'appel API du jeton d'audit car il est **privé**, donc Apple pourrait le **modifier** à tout moment. De plus, l'utilisation d'API privées n'est pas autorisée dans les applications du Mac App Store.
* **`xpc_dictionary_get_audit_token`** doit être utilisé à la place de **`xpc_connection_get_audit_token`**, car ce dernier pourrait également être [vulnérable dans certaines situations](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Attaques de communication

Pour plus d'informations sur l'attaque de réutilisation de PID, consultez :

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Pour plus d'informations sur l'attaque **`xpc_connection_get_audit_token`**, consultez :

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Prévention des attaques de rétrogradation Trustcache

Trustcache est une méthode de défense introduite dans les machines Apple Silicon qui stocke une base de données de CDHSAH des binaires Apple, de sorte que seuls les binaires non modifiés autorisés peuvent être exécutés. Cela empêche l'exécution de versions rétrogradées.

### Exemples de code

Le serveur implémentera cette **vérification** dans une fonction appelée **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

L'objet NSXPCConnection possède une propriété **privée** appelée **`auditToken`** (celle qui devrait être utilisée mais qui pourrait changer) et une propriété **publique** appelée **`processIdentifier`** (celle qui ne devrait pas être utilisée).

Le processus de connexion peut être vérifié avec quelque chose comme :

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
Si un développeur ne souhaite pas vérifier la version du client, il peut au moins vérifier que le client n'est pas vulnérable à l'injection de processus :

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
