# macOS Library Injection

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

{% hint style="danger" %}
Der Code von **dyld ist Open Source** und kann unter [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) gefunden werden und kann über eine **URL wie** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) heruntergeladen werden.
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

Dies ist ähnlich wie das [**LD\_PRELOAD auf Linux**](../../../../linux-hardening/privilege-escalation/#ld\_preload). Es ermöglicht die Angabe eines Prozesses, der ausgeführt wird, um eine bestimmte Bibliothek von einem Pfad zu laden (wenn die Umgebungsvariable aktiviert ist).

Diese Technik kann auch als ASEP-Technik verwendet werden, da jede installierte Anwendung eine Plist namens "Info.plist" hat, die die Zuweisung von Umgebungsvariablen mit einem Schlüssel namens `LSEnvironmental` ermöglicht.

{% hint style="info" %}
Seit 2012 hat **Apple die Macht von `DYLD_INSERT_LIBRARIES` drastisch reduziert**.

Gehen Sie zum Code und überprüfen Sie `src/dyld.cpp`. In der Funktion `pruneEnvironmentVariables` können Sie sehen, dass `DYLD_*`-Variablen entfernt werden.

In der Funktion `processRestricted` wird der Grund für die Einschränkung festgelegt. Wenn Sie diesen Code überprüfen, können Sie sehen, dass die Gründe sind:

* Die Binärdatei ist `setuid/setgid`
* Vorhandensein des Abschnitts `__RESTRICT/__restrict` in der Macho-Binärdatei.
* Die Software verfügt über Berechtigungen (gehärtete Laufzeit) ohne [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) Berechtigung
* Überprüfen Sie die **Berechtigungen** einer Binärdatei mit: `codesign -dv --entitlements :- </path/to/bin>`

In neueren Versionen finden Sie diese Logik im zweiten Teil der Funktion `configureProcessRestrictions`. Was jedoch in neueren Versionen ausgeführt wird, sind die **Anfangsprüfungen der Funktion** (Sie können die mit iOS oder Simulation zusammenhängenden Bedingungen entfernen, da diese in macOS nicht verwendet werden).
{% endhint %}

### Bibliotheksvalidierung

Auch wenn die Binärdatei die Verwendung der **`DYLD_INSERT_LIBRARIES`** Umgebungsvariable zulässt, wird sie keine benutzerdefinierte Bibliothek laden, wenn die Binärdatei die Signatur der Bibliothek überprüft.

Um eine benutzerdefinierte Bibliothek zu laden, muss die Binärdatei eine der folgenden Berechtigungen haben:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

oder die Binärdatei darf nicht das gehärtete Laufzeitflag oder das Bibliotheksvalidierungsflag haben.

Sie können überprüfen, ob eine Binärdatei das **gehärtete Laufzeitflag** hat, indem Sie `codesign --display --verbose <bin>` ausführen und die Laufzeitflag in **`CodeDirectory`** überprüfen, z. B.: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Sie können auch eine Bibliothek laden, wenn sie mit demselben Zertifikat wie die Binärdatei signiert ist.

Ein Beispiel, wie dies (miss)braucht werden kann, und die Einschränkungen finden Sie unter:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib-Hijacking

{% hint style="danger" %}
Denken Sie daran, dass **die zuvor genannten Einschränkungen für die Bibliotheksvalidierung** auch für Dylib-Hijacking-Angriffe gelten.
{% endhint %}

Wie in Windows können Sie auch in MacOS **dylibs hijacken**, um Anwendungen zur Ausführung von beliebigem Code zu bringen (nun, tatsächlich könnte dies von einem normalen Benutzer aus nicht möglich sein, da möglicherweise eine TCC-Berechtigung erforderlich ist, um in ein `.app`-Bundle zu schreiben und eine Bibliothek zu hijacken).\
Die Art und Weise, wie **MacOS** Anwendungen Bibliotheken laden, ist jedoch **stärker eingeschränkt** als in Windows. Dies bedeutet, dass **Malware-Entwickler** diese Technik immer noch für **Tarnung** verwenden können, aber die Wahrscheinlichkeit, dass sie dies zur **Privileg-Eskalation missbrauchen können, ist viel geringer**.

Zunächst ist es **häufiger**, dass **MacOS-Binärdateien den vollständigen Pfad** zu den zu ladenden Bibliotheken angeben. Und zweitens **sucht MacOS niemals** in den Ordnern des **$PATH** nach Bibliotheken.

Der **Hauptteil des Codes**, der mit dieser Funktionalität zusammenhängt, befindet sich in **`ImageLoader::recursiveLoadLibraries`** in `ImageLoader.cpp`.

Es gibt **4 verschiedene Befehle im Header**, die eine Macho-Binärdatei zum Laden von Bibliotheken verwenden kann:

* Der Befehl **`LC_LOAD_DYLIB`** ist der übliche Befehl zum Laden einer dylib.
* Der Befehl **`LC_LOAD_WEAK_DYLIB`** funktioniert wie der vorherige, aber wenn die dylib nicht gefunden wird, wird die Ausführung ohne Fehler fortgesetzt.
* Der Befehl **`LC_REEXPORT_DYLIB`** leitet (oder re-exportiert) die Symbole aus einer anderen Bibliothek weiter.
* Der Befehl **`LC_LOAD_UPWARD_DYLIB`** wird verwendet, wenn zwei Bibliotheken voneinander abhängen (dies wird als _upward dependency_ bezeichnet).

Es gibt jedoch **2 Arten von Dylib-Hijacking**:

* \*\*Fehlende schwach verknüpfte Bibliotheken
* Wenn **`LC_LOAD_DYLIB`** `@rpath/library.dylib` enthält und **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` und `/application/app.app/Contents/Framework/v2/` enthält. Beide Ordner werden verwendet, um `library.dylib` zu laden. Wenn die Bibliothek nicht in `[...]/v1/` existiert und der Angreifer sie dort platzieren kann, kann er den Ladevorgang der Bibliothek in `[...]/v2/` übernehmen, da die Reihenfolge der Pfade in **`LC_LOAD_DYLIB`** befolgt wird.
* **Finde rpath-Pfade und Bibliotheken** in Binärdateien mit: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Ist der **Pfad** zum Verzeichnis, das die **Hauptausführungsdatei** enthält.

**`@loader_path`**: Ist der **Pfad** zum **Verzeichnis**, das die **Mach-O-Binärdatei** enthält, die den Ladebefehl enthält.

* Wenn es in einer ausführbaren Datei verwendet wird, ist **`@loader_path`** effektiv dasselbe wie **`@executable_path`**.
* Wenn es in einer **dylib** verwendet wird, gibt **`@loader_path`** den **Pfad** zur **dylib** an.
{% endhint %}

Die Möglichkeit, Privilegien zu eskalieren, indem diese Funktion missbraucht wird, besteht im seltenen Fall, dass eine **Anwendung**, die von **root** ausgeführt wird, nach einer **Bibliothek in einem Ordner sucht, in dem der Angreifer Schreibberechtigungen hat**.

{% hint style="success" %}
Ein nützlicher **Scanner**, um **fehlende Bibliotheken** in Anwendungen zu finden, ist [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) oder eine [**CLI-Version**](https://github.com/pandazheng/DylibHijack).\
Ein guter **Bericht mit technischen Details** zu dieser Technik finden Sie [**hier**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Beispiel**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen-Hijacking

{% hint style="danger" %}
Denken Sie daran, dass auch die **vorherigen Einschränkungen der Bibliotheksvalidierung** für Dlopen-Hijacking-Angriffe gelten.
{% endhint %}

Aus **`man dlopen`**:

* Wenn der Pfad **kein Schrägstrich-Zeichen** enthält (d.h. es handelt sich nur um einen Blattnamen), sucht dlopen() nach der Bibliothek. Wenn **`$DYLD_LIBRARY_PATH`** beim Start festgelegt wurde, sucht dyld zuerst in diesem Verzeichnis. Anschließend sucht dyld in den Verzeichnissen, die vom aufrufenden Mach-O-Datei oder der Hauptausführungsdatei angegeben sind, wenn ein **`LC_RPATH`** vorhanden ist. Wenn der Prozess **unbeschränkt** ist, sucht dyld im **aktuellen Arbeitsverzeichnis**. Schließlich versucht dyld bei alten Binärdateien einige Fallbacks. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start festgelegt wurde, sucht dyld in diesen Verzeichnissen. Andernfalls sucht dyld in **`/usr/local/lib/`** (wenn der Prozess unbeschränkt ist) und dann in **`/usr/lib/`** (diese Informationen stammen aus **`man dlopen`**).

1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (wenn unbeschränkt)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (wenn unbeschränkt)
6. `/usr/lib/`

{% hint style="danger" %}
Wenn kein Schrägstrich im Namen enthalten ist, gibt es 2 Möglichkeiten, ein Hijacking durchzuführen:

* Wenn ein **`LC_RPATH`** **beschreibbar** ist (aber die Signatur überprüft wird, daher muss die Binärdatei auch unbeschränkt sein)
* Wenn die Binärdatei **unbeschränkt** ist und dann etwas aus dem CWD geladen werden kann (oder indem eine der genannten Umgebungsvariablen missbraucht wird)
{% endhint %}

* Wenn der Pfad **wie ein Framework-Pfad aussieht** (z.B. `/stuff/foo.framework/foo`), sucht dyld zuerst in **`$DYLD_FRAMEWORK_PATH`**, wenn es beim Start festgelegt wurde, nach dem **Framework-Teilpfad** (z.B. `foo.framework/foo`). Anschließend versucht dyld den **angegebenen Pfad** (unter Verwendung des aktuellen Arbeitsverzeichnisses für relative Pfade). Schließlich versucht dyld bei alten Binärdateien einige Fallbacks. Wenn **`$DYLD_FALLBACK_FRAMEWORK_PATH`** beim Start festgelegt wurde, sucht dyld in diesen Verzeichnissen. Andernfalls sucht dyld in **`/Library/Frameworks`** (auf macOS, wenn der Prozess unbeschränkt ist) und dann in **`/System/Library/Frameworks`**.

1. `$DYLD_FRAMEWORK_PATH`
2. angegebener Pfad (unter Verwendung des aktuellen Arbeitsverzeichnisses für relative Pfade, wenn unbeschränkt)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (wenn unbeschränkt)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Wenn es sich um einen Framework-Pfad handelt, besteht die Möglichkeit, ihn zu hijacken:

* Wenn der Prozess **unbeschränkt** ist, indem der relative Pfad vom CWD oder die genannten Umgebungsvariablen missbraucht werden (auch wenn in der Dokumentation nicht angegeben ist, ob der Prozess beschränkt ist, werden DYLD\_\* Umgebungsvariablen entfernt)
{% endhint %}

* Wenn der Pfad **einen Schrägstrich enthält, aber kein Framework-Pfad ist** (d.h. ein vollständiger Pfad oder ein Teilpfad zu einer dylib), sucht dlopen() zuerst in (falls festgelegt) **`$DYLD_LIBRARY_PATH`** (mit dem Blattnamen aus dem Pfad). Anschließend versucht dyld den angegebenen Pfad (unter Verwendung des aktuellen Arbeitsverzeichnisses für relative Pfade (aber nur für unbeschränkte Prozesse)). Schließlich versucht dyld bei älteren Binärdateien einige Fallbacks. Wenn **`$DYLD_FALLBACK_LIBRARY_PATH`** beim Start festgelegt wurde, sucht dyld in diesen Verzeichnissen. Andernfalls sucht dyld in **`/usr/local/lib/`** (wenn der Prozess unbeschränkt ist) und dann in **`/usr/lib/`**.

1. `$DYLD_LIBRARY_PATH`
2. angegebener Pfad (unter Verwendung des aktuellen Arbeitsverzeichnisses für relative Pfade, wenn unbeschränkt)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (wenn unbeschränkt)
5. `/usr/lib/`

{% hint style="danger" %}
Wenn Schrägstriche im Namen enthalten sind und es sich nicht um einen Framework-Pfad handelt, besteht die Möglichkeit, ihn zu hijacken:

* Wenn die Binärdatei **unbeschränkt** ist und dann etwas aus dem CWD oder `/usr/local/lib` geladen werden kann (oder indem eine der genannten Umgebungsvariablen missbraucht wird)
{% endhint %}

Hinweis: Es gibt **keine** Konfigurationsdateien, um die dlopen-Suche zu steuern.

Hinweis: Wenn die Hauptausführungsdatei ein **set\[ug]id-Binary oder mit Berechtigungen signiert** ist, werden **alle Umgebungsvariablen ignoriert** und es kann nur ein vollständiger Pfad verwendet werden (weitere Informationen finden Sie unter **Überprüfen der Einschränkungen von DYLD\_INSERT\_LIBRARIES**).

Hinweis: Apple-Plattformen verwenden "universelle" Dateien, um 32-Bit- und 64-Bit-Bibliotheken zu kombinieren. Dies bedeutet, dass es **keine separaten Suchpfade für 32-Bit- und 64-Bit-Bibliotheken** gibt.

Hinweis: Auf Apple-Plattformen sind die meisten Betriebssystem-Dylibs in den dyld-Cache **kombiniert** und existieren nicht auf der Festplatte. Daher funktioniert der Aufruf von **`stat()`**, um vorab zu überprüfen, ob eine Betriebssystem-Dylib vorhanden ist, **nicht**. Die Funktion **`dlopen_preflight()`** verwendet jedoch die gleichen Schritte wie **`dlopen()`**, um eine kom

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

Wenn eine **privilegierte Binärdatei/App** (wie eine SUID oder eine Binärdatei mit mächtigen Berechtigungen) eine **relative Pfadbibliothek lädt** (zum Beispiel mit `@executable_path` oder `@loader_path`) und die **Bibliotheksvalidierung deaktiviert** ist, könnte es möglich sein, die Binärdatei an einen Ort zu verschieben, an dem der Angreifer die geladene relative Pfadbibliothek **ändern** und sie missbrauchen kann, um Code in den Prozess einzuspritzen.

## Bereinigung der `DYLD_*` und `LD_LIBRARY_PATH` Umgebungsvariablen

In der Datei `dyld-dyld-832.7.1/src/dyld2.cpp` befindet sich die Funktion **`pruneEnvironmentVariables`**, die alle Umgebungsvariablen entfernt, die mit `DYLD_` beginnen und `LD_LIBRARY_PATH=` enthalten.

Sie setzt auch speziell die Umgebungsvariablen **`DYLD_FALLBACK_FRAMEWORK_PATH`** und **`DYLD_FALLBACK_LIBRARY_PATH`** für **suid** und **sgid** Binärdateien auf **null**.

Diese Funktion wird aus der **`_main`** Funktion derselben Datei aufgerufen, wenn OSX als Zielplattform verwendet wird:

```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```

und diese booleschen Flags werden in derselben Datei im Code festgelegt:

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

Das bedeutet im Grunde genommen, dass wenn die Binärdatei **suid** oder **sgid** ist, einen **RESTRICT**-Segment in den Headern hat oder mit dem **CS\_RESTRICT**-Flag signiert wurde, dann ist **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** wahr und die Umgebungsvariablen werden entfernt.

Beachten Sie, dass wenn CS\_REQUIRE\_LV wahr ist, die Variablen nicht entfernt werden, sondern die Bibliotheksvalidierung überprüft, ob sie dasselbe Zertifikat wie die ursprüngliche Binärdatei verwenden.

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

In macOS können Bibliotheken mit dem `__RESTRICT`-Segment verwendet werden, um die Ausführung von Code in bestimmten Prozessen einzuschränken. Dieses Segment kann verwendet werden, um die Sicherheit und Privilegien von Prozessen zu erhöhen.

Das `__RESTRICT`-Segment ermöglicht es, dass nur bestimmte Prozesse auf den Code in der Bibliothek zugreifen können. Dies kann nützlich sein, um die Ausführung von bösartigem Code in privilegierten Prozessen zu verhindern.

Um das `__RESTRICT`-Segment zu verwenden, muss der Code in der Bibliothek so konfiguriert werden, dass er nur in den gewünschten Prozessen ausgeführt wird. Dies kann durch Überprüfung der Prozess-ID oder anderer Prozessattribute erreicht werden.

Es ist wichtig zu beachten, dass das `__RESTRICT`-Segment allein nicht ausreicht, um die Sicherheit eines Prozesses zu gewährleisten. Es sollte als Teil eines umfassenden Sicherheitskonzepts verwendet werden, das andere Schutzmechanismen wie Sandboxing und Berechtigungsprüfungen umfasst.

Die Verwendung des `__RESTRICT`-Segments erfordert ein gründliches Verständnis der macOS-Systemarchitektur und der Prozessverwaltung. Es ist ratsam, sich mit den offiziellen Dokumentationen und Best Practices von Apple vertraut zu machen, um sicherzustellen, dass die Implementierung korrekt und sicher ist.

**Hinweis:** Das `__RESTRICT`-Segment ist eine fortgeschrittene Technik und erfordert spezifisches Wissen über macOS-Sicherheit und Privilegien-Eskalation. Es sollte nur von erfahrenen Entwicklern und Sicherheitsexperten verwendet werden.

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
Beachten Sie, dass auch wenn es Binärdateien gibt, die mit den Flags **`0x0(none)`** signiert sind, sie das Flag **`CS_RESTRICT`** dynamisch erhalten können, wenn sie ausgeführt werden, und daher funktioniert diese Technik nicht bei ihnen.

Sie können überprüfen, ob ein Prozess dieses Flag hat, indem Sie (holen Sie sich [**hier csops**](https://github.com/axelexic/CSOps)):

```bash
csops -status <pid>
```

und überprüfen Sie dann, ob die Flagge 0x800 aktiviert ist.
{% endhint %}

## Referenzen

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
