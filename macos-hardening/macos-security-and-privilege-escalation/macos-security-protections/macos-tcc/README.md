# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Informations de base**

**TCC (Transparence, Consentement et Contrôle)** est un mécanisme dans macOS pour **limiter et contrôler l'accès des applications à certaines fonctionnalités**, généralement d'un point de vue de la confidentialité. Cela peut inclure des choses telles que les services de localisation, les contacts, les photos, le microphone, la caméra, l'accessibilité, l'accès complet au disque et bien plus encore.

Du point de vue de l'utilisateur, il voit TCC en action **lorsqu'une application veut accéder à l'une des fonctionnalités protégées par TCC**. Lorsque cela se produit, l'**utilisateur est invité** avec une boîte de dialogue lui demandant s'il souhaite autoriser l'accès ou non.

Il est également possible de **donner aux applications l'accès** aux fichiers par des **intentions explicites** des utilisateurs, par exemple lorsque l'utilisateur **glisse et dépose un fichier dans un programme** (évidemment, le programme doit y avoir accès).

![Un exemple de boîte de dialogue TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** est géré par le **démon** situé dans `/System/Library/PrivateFrameworks/TCC.framework/Resources/tccd` configuré dans `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (enregistrant le service mach `com.apple.tccd.system`).

Il y a un **tccd en mode utilisateur** en cours d'exécution par utilisateur connecté défini dans `/System/Library/LaunchAgents/com.apple.tccd.plist` enregistrant les services mach `com.apple.tccd` et `com.apple.usernotifications.delegate.com.apple.tccd`.

Les autorisations sont **héritées du parent** de l'application et les **autorisations** sont **suivies** en fonction de l'**ID de bundle** et de l'**ID de développeur**.

### Base de données TCC

Les sélections sont ensuite stockées dans la base de données TCC à l'échelle du système dans **`/Library/Application Support/com.apple.TCC/TCC.db`** ou dans **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** pour les préférences par utilisateur. La base de données est **protégée contre la modification avec SIP** (Protection de l'intégrité du système), mais vous pouvez les lire en accordant **un accès complet au disque**.

{% hint style="info" %}
L'**interface utilisateur du centre de notification** peut apporter des **changements dans la base de données TCC du système** :

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Cependant, les utilisateurs peuvent **supprimer ou interroger des règles** avec l'utilitaire en ligne de commande **`tccutil`**.
{% endhint %}

{% tabs %}
{% tab title="user DB" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}

{% tab title="macOS TCC" %}
# Protection de la confidentialité de macOS

macOS TCC (Transparency, Consent, and Control) est un cadre de sécurité qui aide à protéger la confidentialité de l'utilisateur en limitant l'accès des applications aux données sensibles telles que les contacts, les calendriers, les photos et le microphone. Les applications doivent demander l'autorisation de l'utilisateur avant de pouvoir accéder à ces données.

Le TCC est implémenté en utilisant une base de données système appelée `tcc.db`. Cette base de données contient des informations sur les autorisations accordées aux applications pour accéder aux données sensibles. Les autorisations sont stockées sous forme de chaînes de caractères cryptées dans la base de données.

Le TCC est conçu pour être résistant aux attaques de type injection SQL. Les chaînes de caractères sont cryptées à l'aide d'une clé de chiffrement stockée dans le trousseau d'accès. Cette clé est protégée par un mot de passe utilisateur et ne peut être déverrouillée que par l'utilisateur.

Le TCC est également conçu pour être résistant aux attaques de type escalade de privilèges. Les autorisations sont stockées dans la base de données système, qui est protégée par les mécanismes de sécurité de macOS. Les applications ne peuvent pas modifier directement la base de données système sans les autorisations appropriées.

Cependant, il est possible pour un attaquant d'obtenir des autorisations en trompant l'utilisateur pour qu'il donne son consentement. Par exemple, un attaquant peut créer une application malveillante qui demande l'autorisation d'accéder aux contacts de l'utilisateur, mais qui utilise ensuite ces informations à des fins malveillantes telles que le spam ou le phishing.

Pour éviter cela, il est important de ne donner des autorisations qu'aux applications de confiance et de vérifier régulièrement les autorisations accordées aux applications.
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}
{% endtabs %}

{% hint style="success" %}
En vérifiant les deux bases de données, vous pouvez vérifier les autorisations qu'une application a autorisées, interdites ou qu'elle n'a pas (elle demandera l'autorisation).
{% endhint %}

* La **`auth_value`** peut avoir différentes valeurs : denied(0), unknown(1), allowed(2), ou limited(3).
* La **`auth_reason`** peut prendre les valeurs suivantes : Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* Pour plus d'informations sur les **autres champs** de la table, [**consultez ce billet de blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

{% hint style="info" %}
Certaines autorisations TCC sont : kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Il n'y a pas de liste publique qui les définit toutes, mais vous pouvez consulter cette [**liste de celles connues**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).
{% endhint %}

Vous pouvez également vérifier les **autorisations déjà accordées** aux applications dans `Préférences Système --> Sécurité et confidentialité --> Confidentialité --> Fichiers et dossiers`.

### Vérifications de signature TCC

La **base de données** TCC stocke l'**ID de bundle** de l'application, mais elle stocke également des **informations** sur la **signature** pour **s'assurer** que l'application qui demande l'autorisation d'utiliser une permission est la bonne.
```bash
# From sqlite
sqlite> select hex(csreq) from access where client="ru.keepcoder.Telegram";
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"

```
{% endcode %}

### Attributions

Les applications **n'ont pas seulement besoin** de **demander** et d'obtenir **l'accès** à certaines ressources, elles doivent également **avoir les autorisations pertinentes**.\
Par exemple, **Telegram** a l'autorisation `com.apple.security.device.camera` pour demander **l'accès à la caméra**. Une **application** qui **n'a pas cette autorisation ne pourra pas** accéder à la caméra (et l'utilisateur ne sera même pas invité à donner les autorisations).

Cependant, pour que les applications **accèdent** à certains dossiers utilisateur, tels que `~/Desktop`, `~/Downloads` et `~/Documents`, elles **n'ont pas besoin** d'avoir des **autorisations spécifiques**. Le système gérera l'accès de manière transparente et **invitera l'utilisateur** si nécessaire.

Les applications d'Apple **ne génèrent pas de pop-ups**. Elles contiennent des **droits préalablement accordés** dans leur liste d'autorisations, ce qui signifie qu'elles ne **généreront jamais de pop-up**, **ni** n'apparaîtront dans l'une des **bases de données TCC**. Par exemple:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```
Cela évitera que Calendrier demande à l'utilisateur d'accéder aux rappels, au calendrier et au carnet d'adresses.

### Endroits sensibles non protégés

* $HOME (lui-même)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### Intention de l'utilisateur / com.apple.macl

Comme mentionné précédemment, il est possible d'accorder l'accès à une application à un fichier en le faisant glisser-déposer dessus. Cet accès ne sera pas spécifié dans une base de données TCC mais en tant qu'**attribut étendu du fichier**. Cet attribut stockera l'UUID de l'application autorisée :
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
{% hint style="info" %}
Il est curieux que l'attribut **`com.apple.macl`** soit géré par le **bac à sable**, et non par tccd
{% endhint %}

L'attribut étendu `com.apple.macl` **ne peut pas être effacé** comme les autres attributs étendus car il est **protégé par SIP**. Cependant, comme [**expliqué dans ce post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), il est possible de le désactiver en **compressant** le fichier, en le **supprimant** et en le **décompressant**.

## Références

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
