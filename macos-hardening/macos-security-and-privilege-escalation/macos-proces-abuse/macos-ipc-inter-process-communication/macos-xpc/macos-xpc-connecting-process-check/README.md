# Vérification du processus de connexion macOS XPC

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Vérification du processus de connexion XPC

Lorsqu'une connexion est établie avec un service XPC, le serveur vérifie si la connexion est autorisée. Voici les vérifications habituellement effectuées :

1. Vérifier si le processus de connexion est signé avec un certificat **signé par Apple** (uniquement délivré par Apple).
   * Si cela n'est **pas vérifié**, un attaquant pourrait créer un **faux certificat** pour correspondre à tout autre contrôle.
2. Vérifier si le processus de connexion est signé avec le certificat de **l'organisation** (vérification de l'ID de l'équipe).
   * Si cela n'est **pas vérifié**, **n'importe quel certificat de développeur** d'Apple peut être utilisé pour signer et se connecter au service.
3. Vérifier si le processus de connexion **contient un ID de bundle approprié**.
   * Si cela n'est **pas vérifié**, n'importe quel outil **signé par la même organisation** pourrait être utilisé pour interagir avec le service XPC.
4. (4 ou 5) Vérifier si le processus de connexion a un **numéro de version logicielle approprié**.
   * Si cela n'est **pas vérifié**, des clients anciens et non sécurisés, vulnérables à l'injection de processus, pourraient être utilisés pour se connecter au service XPC même avec les autres contrôles en place.
5. (4 ou 5) Vérifier si le processus de connexion a un runtime renforcé sans droits dangereux (comme ceux qui permettent de charger des bibliothèques arbitraires ou d'utiliser des variables d'environnement DYLD)
   * Si cela n'est **pas vérifié**, le client pourrait être **vulnérable à l'injection de code**
6. Vérifier si le processus de connexion a un **droit** qui lui permet de se connecter au service. Cela s'applique aux binaires Apple.
7. La **vérification** doit être **basée** sur le **jeton d'audit du client** **au lieu** de son ID de processus (**PID**) car cela empêche les **attaques de réutilisation de PID**.
   * Les développeurs **utilisent rarement l'appel API du jeton d'audit** car il est **privé**, donc Apple pourrait **changer** à tout moment. De plus, l'utilisation d'API privées n'est pas autorisée dans les applications Mac App Store.
   * Si la méthode **`processIdentifier`** est utilisée, elle pourrait être vulnérable
   * **`xpc_dictionary_get_audit_token`** devrait être utilisé à la place de **`xpc_connection_get_audit_token`**, car le dernier pourrait également être [vulnérable dans certaines situations](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Attaques de communication

Pour plus d'informations sur l'attaque de réutilisation de PID, consultez :

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Pour plus d'informations sur l'attaque **`xpc_connection_get_audit_token`**, consultez :

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Prévention des attaques par rétrogradation

Trustcache est une méthode défensive introduite dans les machines Apple Silicon qui stocke une base de données de CDHSAH des binaires Apple afin que seuls les binaires non modifiés autorisés puissent être exécutés. Ce qui empêche l'exécution de versions antérieures.

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

L'objet NSXPCConnection possède une propriété **privée** **`auditToken`** (celle qui devrait être utilisée mais qui pourrait changer) et une propriété **publique** **`processIdentifier`** (celle qui ne devrait pas être utilisée).

Le processus de connexion pourrait être vérifié avec quelque chose comme :

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
{% endcode %}

Si un développeur ne souhaite pas vérifier la version du client, il pourrait au moins s'assurer que le client n'est pas vulnérable à l'injection de processus :

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
```markdown
{% endcode %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
