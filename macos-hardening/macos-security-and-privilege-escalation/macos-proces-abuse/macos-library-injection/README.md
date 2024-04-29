# macOS Library Injection

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

{% hint style="danger" %}
Der Code von **dyld ist Open Source** und kann unter [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) gefunden und als Tar unter Verwendung einer **URL wie** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) heruntergeladen werden.
{% endhint %}

## **Dyld-Prozess**

Werfen Sie einen Blick darauf, wie Dyld Bibliotheken in Binärdateien lädt:

{% content-ref url="macos-dyld-process.md" %}
[macos-dyld-process.md](macos-dyld-process.md)
{% endcontent-ref %}

## **DYLD\_INSERT\_LIBRARIES**

Dies ist wie das [**LD\_PRELOAD unter Linux**](../../../../linux-hardening/privilege-escalation/#ld\_preload). Es ermöglicht, einem Prozess anzuzeigen, dass eine bestimmte Bibliothek aus einem Pfad geladen werden soll (wenn die Umgebungsvariable aktiviert ist).

Diese Technik kann auch als ASEP-Technik verwendet werden, da jede installierte Anwendung eine sogenannte "Info.plist" hat, die das Zuweisen von Umgebungsvariablen mit einem Schlüssel namens `LSEnvironmental` ermöglicht.

{% hint style="info" %}
Seit 2012 hat **Apple die Macht des** **`DYLD_INSERT_LIBRARIES`** **drastisch reduziert**.

Gehen Sie zum Code und überprüfen Sie `src/dyld.cpp`. In der Funktion **`pruneEnvironmentVariables`** können Sie sehen, dass **`DYLD_*`**-Variablen entfernt werden.

In der Funktion **`processRestricted`** wird der Grund für die Einschränkung festgelegt. Wenn Sie diesen Code überprüfen, sehen Sie, dass die Gründe sind:

* Die Binärdatei ist `setuid/setgid`
* Vorhandensein des Abschnitts `__RESTRICT/__restrict` in der Macho-Binärdatei.
* Die Software verfügt über Berechtigungen (gehärtete Laufzeit) ohne die Berechtigung [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Überprüfen Sie die **Berechtigungen** einer Binärdatei mit: `codesign -dv --entitlements :- </Pfad/zur/Binärdatei>`

In neueren Versionen finden Sie diese Logik im zweiten Teil der Funktion **`configureProcessRestrictions`.** Was jedoch in neueren Versionen ausgeführt wird, sind die **Anfangsprüfungen der Funktion** (Sie können die Bedingungen im Zusammenhang mit iOS oder Simulation entfernen, da diese in macOS nicht verwendet werden).
{% endhint %}

### Bibliotheksvalidierung

Auch wenn die Binärdatei die Verwendung der **`DYLD_INSERT_LIBRARIES`**-Umgebungsvariable zulässt, wird eine benutzerdefinierte Bibliothek nicht geladen, wenn die Binärdatei die Signatur der Bibliothek überprüft.

Um eine benutzerdefinierte Bibliothek zu laden, muss die Binärdatei eine der folgenden Berechtigungen haben:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

oder die Binärdatei darf nicht das gehärtete Laufzeitflag oder das Bibliotheksvalidierungsflag haben.

Sie können überprüfen, ob eine Binärdatei das **gehärtete Laufzeit** hat, mit `codesign --display --verbose <bin>` und das Laufzeitflag in **`CodeDirectory`** überprüfen, z. B.: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Sie können auch eine Bibliothek laden, wenn sie **mit demselben Zertifikat wie die Binärdatei signiert ist**.

Finden Sie ein Beispiel, wie Sie dies (miss)brauchen können, und überprüfen Sie die Einschränkungen in:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib-Hijacking

{% hint style="danger" %}
Denken Sie daran, dass **frühere Einschränkungen der Bibliotheksvalidierung** auch für Dylib-Hijacking-Angriffe gelten.
{% endhint %}

Wie in Windows können Sie auch in MacOS **dylibs hijacken**, um **Anwendungen** dazu zu bringen, **beliebigen** **Code** auszuführen (nun, tatsächlich könnte dies von einem regulären Benutzer aus nicht möglich sein, da Sie möglicherweise eine TCC-Berechtigung benötigen, um in einem `.app`-Bundle zu schreiben und eine Bibliothek zu hijacken).\
Der Weg, wie **MacOS**-Anwendungen Bibliotheken **laden**, ist jedoch **stärker eingeschränkt** als in Windows. Dies bedeutet, dass **Malware**-Entwickler diese Technik immer noch für **Stealth** verwenden können, aber die Wahrscheinlichkeit, dies zu missbrauchen, um Berechtigungen zu eskalieren, ist viel geringer.

Zunächst ist es **häufiger**, dass **MacOS-Binärdateien den vollständigen Pfad** zu den zu ladenden Bibliotheken angeben. Zweitens **sucht MacOS nie** in den Ordnern des **$PATH** nach Bibliotheken.

Der **Hauptteil** des **Codes** im Zusammenhang mit dieser Funktionalität befindet sich in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Es gibt **4 verschiedene Header-Befehle**, die eine Macho-Binärdatei verwenden kann, um Bibliotheken zu laden:

* Der Befehl **`LC_LOAD_DYLIB`** ist der übliche Befehl zum Laden einer dylib.
* Der Befehl **`LC_LOAD_WEAK_DYLIB`** funktioniert wie der vorherige, aber wenn die dylib nicht gefunden wird, wird die Ausführung ohne Fehler fortgesetzt.
* Der Befehl **`LC_REEXPORT_DYLIB`** leitet (oder reexportiert) die Symbole aus einer anderen Bibliothek weiter.
* Der Befehl **`LC_LOAD_UPWARD_DYLIB`** wird verwendet, wenn zwei Bibliotheken voneinander abhängen (dies wird als _upward dependency_ bezeichnet).

Es gibt jedoch **2 Arten von Dylib-Hijacking**:

* **Fehlende schwach verknüpfte Bibliotheken**: Dies bedeutet, dass die Anwendung versuchen wird, eine Bibliothek zu laden, die nicht existiert und mit **LC\_LOAD\_WEAK\_DYLIB** konfiguriert ist. Dann wird die Bibliothek geladen, **wenn ein Angreifer eine Bibliothek dort platziert, wo sie erwartet wird**.
* Die Tatsache, dass die Verknüpfung "schwach" ist, bedeutet, dass die Anwendung weiterhin ausgeführt wird, auch wenn die Bibliothek nicht gefunden wird.
* Der **Code** dazu befindet sich in der Funktion `ImageLoaderMachO::doGetDependentLibraries` in `ImageLoaderMachO.cpp`, wo `lib->required` nur `false` ist, wenn `LC_LOAD_WEAK_DYLIB` wahr ist.
* **Suchen Sie nach schwach verknüpften Bibliotheken** in Binärdateien (Sie haben später ein Beispiel, wie Sie Hijacking-Bibliotheken erstellen können):
* ```bash
otool -l </Pfad/zur/Binärdatei> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **Konfiguriert mit @rpath**: Mach-O-Binärdateien können die Befehle **`LC_RPATH`** und **`LC_LOAD_DYLIB`** haben. Abhängig von den **Werten** dieser Befehle werden **Bibliotheken** aus **verschiedenen Verzeichnissen** geladen.
* **`LC_RPATH`** enthält die Pfade einiger Ordner, die von der Binärdatei zum Laden von Bibliotheken verwendet werden.
* **`LC_LOAD_DYLIB`** enthält den Pfad zu spezifischen Bibliotheken zum Laden. Diese Pfade können **`@rpath`** enthalten, das durch die Werte in **`LC_RPATH`** ersetzt wird. Wenn mehrere Pfade in **`LC_RPATH`** vorhanden sind, werden alle verwendet, um die zu ladende Bibliothek zu suchen. Beispiel:
* Wenn **`LC_LOAD_DYLIB`** `@rpath/library.dylib` enthält und **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` und `/application/app.app/Contents/Framework/v2/` enthält. Beide Ordner werden verwendet, um `library.dylib` zu laden. Wenn die Bibliothek nicht in `[...]/v1/` existiert und ein Angreifer sie dort platzieren könnte, um das Laden der Bibliothek in `[...]/v2/` zu übernehmen, da die Reihenfolge der Pfade in **`LC_LOAD_DYLIB`** befolgt wird.
* **Suche rpath-Pfade und Bibliotheken** in Binärdateien mit: `otool -l </path/zur/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Ist der **Pfad** zum Verzeichnis, das die **Hauptausführungsdatei** enthält.

**`@loader_path`**: Ist der **Pfad** zum **Verzeichnis**, das die **Mach-O-Binärdatei** enthält, die den Ladungsbefehl enthält.

* Wenn es in einer Ausführbaren verwendet wird, ist **`@loader_path`** effektiv das **gleiche** wie **`@executable_path`**.
* Wenn es in einem **dylib** verwendet wird, gibt **`@loader_path`** den **Pfad** zur **dylib** an.
{% endhint %}

Der Weg zur **Privilegieneskalation** durch den Missbrauch dieser Funktionalität wäre im seltenen Fall, dass eine **Anwendung**, die von **root** ausgeführt wird, nach einer **Bibliothek in einem Ordner sucht, in dem der Angreifer Schreibberechtigungen hat.**

{% hint style="success" %}
Ein nützlicher **Scanner** zum Auffinden von **fehlenden Bibliotheken** in Anwendungen ist [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) oder eine [**CLI-Version**](https://github.com/pandazheng/DylibHijack).\
Ein guter **Bericht mit technischen Details** zu dieser Technik finden Sie [**hier**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Beispiel**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Denken Sie daran, dass auch die **früheren Einschränkungen der Bibliotheksvalidierung** gelten, um Dlopen-Hijacking-Angriffe durchzuführen.
{% endhint %}

Aus **`man dlopen`**:

* Wenn der Pfad **kein Schrägstrichzeichen enthält** (d.h. es handelt sich nur um einen Blattnamen), wird **dlopen() eine Suche durchführen**. Wenn **`$DYLD_LIBRARY_PATH`** beim Start festgelegt war, sucht dyld zuerst in diesem Verzeichnis. Als Nächstes, wenn die aufrufende Mach-O-Datei oder die Hauptausführbare eine **`LC_RPATH`** angeben, sucht dyld in diesen Verzeichnissen. Als Nächstes, wenn der Prozess **unbeschränkt** ist, sucht dyld im **aktuellen Arbeitsverzeichnis**. Schließlich versucht dyld für alte Binärdateien einige Ausweichmöglichkeiten. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start festgelegt war, sucht dyld in **diesen Verzeichnissen**, andernfalls sucht dyld in **`/usr/local/lib/`** (wenn der Prozess unbeschränkt ist), und dann in **`/usr/lib/`** (diese Informationen stammen aus **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (wenn unbeschränkt)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (wenn unbeschränkt)
6. `/usr/lib/`

{% hint style="danger" %}
Wenn kein Schrägstrich im Namen vorhanden ist, gibt es 2 Möglichkeiten, ein Hijacking durchzuführen:

* Wenn ein **`LC_RPATH`** **beschreibbar** ist (aber die Signatur überprüft wird, daher benötigen Sie auch, dass die Binärdatei unbeschränkt ist)
* Wenn die Binärdatei **unbeschränkt** ist und dann etwas aus dem CWD geladen werden kann (oder durch den Missbrauch einer der genannten Umgebungsvariablen)
{% endhint %}

* Wenn der Pfad **wie ein Framework-Pfad aussieht** (z.B. `/stuff/foo.framework/foo`), sucht dyld zuerst im Verzeichnis nach dem **Framework-Teilpfad** (z.B. `foo.framework/foo`), wenn **`$DYLD_FRAMEWORK_PATH`** beim Start festgelegt war. Als Nächstes versucht dyld den **angegebenen Pfad wie angegeben** (verwendet das aktuelle Arbeitsverzeichnis für relative Pfade). Schließlich versucht dyld für alte Binärdateien einige Ausweichmöglichkeiten. Wenn **`$DYLD_FALLBACK_FRAMEWORK_PATH`** beim Start festgelegt war, sucht dyld in diesen Verzeichnissen. Andernfalls sucht dyld in **`/Library/Frameworks`** (auf macOS, wenn der Prozess unbeschränkt ist), dann in **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. angegebener Pfad (verwendet das aktuelle Arbeitsverzeichnis für relative Pfade, wenn unbeschränkt)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (wenn unbeschränkt)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Bei einem Framework-Pfad wäre der Weg, es zu übernehmen:

* Wenn der Prozess **unbeschränkt** ist, Missbrauch des **relativen Pfads vom CWD** der genannten Umgebungsvariablen (auch wenn in den Dokumenten nicht gesagt wird, ob die Prozesse eingeschränkt sind, werden DYLD\_\* Umgebungsvariablen entfernt)
{% endhint %}

* Wenn der Pfad **ein Schrägstrich enthält, aber kein Framework-Pfad ist** (d.h. ein vollständiger Pfad oder ein Teilpfad zu einer dylib), sucht dlopen() zuerst (falls festgelegt) in **`$DYLD_LIBRARY_PATH`** (mit dem Blattteil des Pfads). Als Nächstes versucht dyld den angegebenen Pfad (verwendet das aktuelle Arbeitsverzeichnis für relative Pfade (aber nur für unbeschränkte Prozesse)). Schließlich versucht dyld für ältere Binärdateien einige Ausweichmöglichkeiten. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start festgelegt war, sucht dyld in diesen Verzeichnissen, andernfalls sucht dyld in **`/usr/local/lib/`** (wenn der Prozess unbeschränkt ist), und dann in **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. angegebener Pfad (verwendet das aktuelle Arbeitsverzeichnis für relative Pfade, wenn unbeschränkt)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (wenn unbeschränkt)
5. `/usr/lib/`

{% hint style="danger" %}
Wenn Schrägstriche im Namen vorhanden sind und es sich nicht um einen Framework-Pfad handelt, wäre der Weg, es zu übernehmen:

* Wenn die Binärdatei **unbeschränkt** ist und dann etwas aus dem CWD oder `/usr/local/lib` geladen werden kann (oder durch den Missbrauch einer der genannten Umgebungsvariablen)
{% endhint %}

{% hint style="info" %}
Hinweis: Es gibt **keine** Konfigurationsdateien, um die **dlopen-Suche zu steuern**.

Hinweis: Wenn die Hauptausführbare eine **set\[ug\]id-Binärdatei oder mit Berechtigungen signiert** ist, werden **alle Umgebungsvariablen ignoriert**, und es kann nur ein vollständiger Pfad verwendet werden ([überprüfen Sie die Einschränkungen von DYLD\_INSERT\_LIBRARIES](macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions) für detailliertere Informationen)

Hinweis: Apple-Plattformen verwenden "universelle" Dateien, um 32-Bit- und 64-Bit-Bibliotheken zu kombinieren. Dies bedeutet, dass es **keine separaten Suchpfade für 32-Bit und 64-Bit** gibt.

Hinweis: Auf Apple-Plattformen werden die meisten OS-Dylibs in den dyld-Cache **kombiniert** und existieren nicht auf der Festplatte. Daher funktioniert das Aufrufen von **`stat()`** zur Vorabprüfung, ob eine OS-Dylib existiert, **nicht**. Jedoch verwendet **`dlopen_preflight()`** die gleichen Schritte wie **`dlopen()`**, um eine kompatible Mach-O-Datei zu finden.
{% endhint %}

**Pfade überprüfen**

Lassen Sie uns alle Optionen mit dem folgenden Code überprüfen:
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Wenn Sie es kompilieren und ausführen, können Sie sehen, **wo jede Bibliothek erfolglos gesucht wurde**. Außerdem könnten Sie **die FS-Protokolle filtern**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Wenn ein **privilegiertes Binary/App** (wie ein SUID oder ein Binary mit leistungsstarken Berechtigungen) eine **relative Pfad**-Bibliothek lädt (zum Beispiel mit `@executable_path` oder `@loader_path`) und die **Library Validation deaktiviert** ist, könnte es möglich sein, das Binary an einen Ort zu verschieben, an dem der Angreifer die geladene relative Pfadbibliothek **modifizieren** und sie missbrauchen könnte, um Code in den Prozess einzuspeisen.

## Bereinigen von `DYLD_*` und `LD_LIBRARY_PATH` Umgebungsvariablen

In der Datei `dyld-dyld-832.7.1/src/dyld2.cpp` ist es möglich, die Funktion **`pruneEnvironmentVariables`** zu finden, die jede Umgebungsvariable entfernt, die mit `DYLD_` beginnt und `LD_LIBRARY_PATH=`.

Es setzt auch explizit die Umgebungsvariablen **`DYLD_FALLBACK_FRAMEWORK_PATH`** und **`DYLD_FALLBACK_LIBRARY_PATH`** für **suid** und **sgid** Binaries auf **null**.

Diese Funktion wird aus der **`_main`** Funktion derselben Datei auf OSX abzielen, wie folgt aufgerufen:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
und diese booleschen Flags werden im gleichen Codefile gesetzt:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
Das bedeutet im Grunde genommen, dass wenn die Binärdatei **suid** oder **sgid** ist, oder ein **RESTRICT**-Segment in den Headern hat oder mit dem **CS\_RESTRICT**-Flag signiert wurde, dann ist **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** wahr und die Umgebungsvariablen werden beschnitten.

Beachten Sie, dass wenn CS\_REQUIRE\_LV wahr ist, dann werden die Variablen nicht beschnitten, aber die Bibliotheksvalidierung wird überprüfen, ob sie dasselbe Zertifikat wie die originale Binärdatei verwenden.

## Überprüfen von Einschränkungen

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
### Abschnitt `__RESTRICT` mit Segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Gehärtete Laufzeit

Erstellen Sie ein neues Zertifikat im Schlüsselbund und verwenden Sie es, um die Binärdatei zu signieren:

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
Beachten Sie, dass auch wenn Binärdateien mit Flags **`0x0(none)`** signiert sind, sie das Flag **`CS_RESTRICT`** dynamisch erhalten können, wenn sie ausgeführt werden, und daher diese Technik bei ihnen nicht funktioniert.

Sie können überprüfen, ob ein Prozess dieses Flag mit (erhalten Sie [**hier csops**](https://github.com/axelexic/CSOps)):
```bash
csops -status <pid>
```
und überprüfen Sie dann, ob die Flagge 0x800 aktiviert ist.
{% endhint %}

## Referenzen

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)
* [**\*OS Internals, Band I: Benutzermodus. Von Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys einreichen.

</details>
