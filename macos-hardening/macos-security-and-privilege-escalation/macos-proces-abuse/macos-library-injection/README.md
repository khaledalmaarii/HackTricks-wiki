# macOS 라이브러리 주입

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

{% hint style="danger" %}
**dyld의 코드는 오픈 소스**이며 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)에서 찾을 수 있으며 **URL을 사용하여 tar를 다운로드**할 수 있습니다. 예: [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

이는 [**Linux의 LD\_PRELOAD**](../../../../linux-hardening/privilege-escalation#ld\_preload)와 유사합니다. 환경 변수가 활성화되면 특정 경로에서 라이브러리를 로드하기 위해 실행될 프로세스를 지정할 수 있습니다.

이 기술은 또한 **ASEP 기술로 사용**될 수 있으며, 설치된 각 애플리케이션에는 "Info.plist"라는 plist가 있어 `LSEnvironmental`이라는 키를 사용하여 환경 변수를 할당할 수 있습니다.

{% hint style="info" %}
2012년 이후로 **Apple은 `DYLD_INSERT_LIBRARIES`의 권한을 크게 제한**했습니다.

코드로 이동하여 **`src/dyld.cpp`**를 확인하세요. 함수 **`pruneEnvironmentVariables`**에서 **`DYLD_*`** 변수가 제거되는 것을 볼 수 있습니다.

함수 **`processRestricted`**에서 제한의 이유가 설정됩니다. 해당 코드를 확인하면 다음과 같은 이유를 볼 수 있습니다.

* 이진 파일이 `setuid/setgid`입니다.
* macho 바이너리에 `__RESTRICT/__restrict` 섹션이 존재합니다.
* 소프트웨어에 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) 권한이 있는 하드닝 런타임이 있습니다.
* 이진 파일의 **권한**을 다음과 같이 확인할 수 있습니다. `codesign -dv --entitlements :- </path/to/bin>`

더 최신 버전에서는 이 논리를 함수 **`configureProcessRestrictions`**의 두 번째 부분에서 찾을 수 있습니다. 그러나 더 최신 버전에서 실행되는 것은 함수의 **처음 검사**입니다 (iOS 또는 시뮬레이션과 관련된 if문은 macOS에서 사용되지 않으므로 제거할 수 있습니다).
{% endhint %}

### 라이브러리 유효성 검사

바이너리가 **`DYLD_INSERT_LIBRARIES`** 환경 변수를 사용할 수 있더라도, 바이너리가 라이브러리의 서명을 확인하고 로드하지 않을 경우 사용자 정의 라이브러리를 로드하지 않습니다.

사용자 정의 라이브러리를 로드하려면 바이너리에 다음 중 하나의 권한이 있어야 합니다.

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

또는 바이너리에 **하드닝 런타임 플래그** 또는 **라이브러리 유효성 검사 플래그**가 없어야 합니다.

`codesign --display --verbose <bin>`을 사용하여 바이너리에 **하드닝 런타임**이 있는지 확인할 수 있습니다. **`CodeDirectory`**에서 플래그 런타임을 확인합니다. 예: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

또한, 바이너리와 **동일한 인증서로 서명된 경우** 라이브러리를 로드할 수도 있습니다.

이를 (남용하여) 사용하고 제한 사항을 확인하는 예제를 다음에서 찾을 수 있습니다:

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib 하이재킹

{% hint style="danger" %}
이전 라이브러리 유효성 검사 제한도 Dylib 하이재킹 공격에 적용됩니다.
{% endhint %}

Windows와 마찬가지로 MacOS에서도 **dylib을 하이재킹**하여 **애플리케이션**에서 **임의의 코드를 실행**할 수 있습니다 (사실 일반 사용자로서는 `.app` 번들 내부에 쓰기 권한을 얻기 위해 TCC 권한이 필요할 수 있으므로 이것이 불가능할 수도 있습니다).\
그러나 MacOS 애플리케이션에서 라이브러리를 로드하는 방식은 Windows보다 **더 제한적**입니다. 이는 **악성 소프트웨어** 개발자가 이 기술을 **은닉**하기 위해 여전히 사용할 수 있지만 권한 상승을 위해 이를 남용할 가능성은 훨씬 낮습니다.

먼저, **MacOS 바이너리에서 라이브러리의 전체 경로를 지정하는 것이 더 일반적**입니다. 그리고 두 번째로, **MacOS는 라이브러리를 검색하기 위해 $PATH의 폴더
* 만약 **`LC_LOAD_DYLIB`**에 `@rpath/library.dylib`가 포함되어 있고 **`LC_RPATH`**에 `/application/app.app/Contents/Framework/v1/`과 `/application/app.app/Contents/Framework/v2/`가 포함되어 있다면, 두 폴더는 `library.dylib`를 로드하는 데 사용될 것입니다. 만약 라이브러리가 `[...]/v1/`에 존재하지 않고 공격자가 그곳에 라이브러리를 배치할 수 있다면, **`LC_LOAD_DYLIB`**의 경로 순서에 따라 `library.dylib`를 `[...]/v2/`에서 로드하는 것을 탈취할 수 있습니다.
* **바이너리에서 rpath 경로와 라이브러리를 찾으려면**: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: **메인 실행 파일**을 포함하는 디렉토리의 **경로**입니다.

**`@loader_path`**: **로드 명령어**를 포함하는 **Mach-O 바이너리**가 있는 **디렉토리**의 **경로**입니다.

* 실행 파일에서 사용되는 경우, **`@loader_path`**는 **`@executable_path`**와 **동일**합니다.
* **dylib**에서 사용되는 경우, **`@loader_path`**는 **dylib**의 **경로**를 제공합니다.
{% endhint %}

이 기능을 악용하여 **권한 상승**을 하는 방법은 **루트**에 의해 실행되는 **응용 프로그램**이 **공격자가 쓰기 권한을 가진 폴더**에서 **라이브러리를 찾는 경우**에만 발생합니다.

{% hint style="success" %}
응용 프로그램에서 **누락된 라이브러리**를 찾는 좋은 **스캐너**는 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) 또는 [**CLI 버전**](https://github.com/pandazheng/DylibHijack)입니다.\
이 기술에 대한 기술적인 세부 정보가 포함된 좋은 **보고서**는 [**여기**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)에서 찾을 수 있습니다.
{% endhint %}

**예시**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
**이전의 Library Validation 제한 사항도** Dlopen 히재킹 공격을 수행하기 위해 적용됩니다.
{% endhint %}

**`man dlopen`**에서:

* 경로에 **슬래시 문자가 없는 경우** (즉, 단순한 파일 이름인 경우), **dlopen()은 검색**을 수행합니다. **`$DYLD_LIBRARY_PATH`**가 실행 시 설정되었다면, dyld는 먼저 해당 디렉토리에서 검색합니다. 그 다음, 호출하는 mach-o 파일이나 메인 실행 파일이 **`LC_RPATH`**를 지정한 경우, dyld는 해당 디렉토리에서 검색합니다. 그 다음, 프로세스가 **제한되지 않은 경우**, dyld는 **현재 작업 디렉토리**에서 검색합니다. 마지막으로, 오래된 바이너리의 경우, dyld는 일부 대체 방법을 시도합니다. **`$DYLD_FALLBACK_LIBRARY_PATH`**가 실행 시 설정되었다면, dyld는 해당 디렉토리에서 검색합니다. 그렇지 않으면, dyld는 **`/usr/local/lib/`** (프로세스가 제한되지 않은 경우) 그리고 **`/usr/lib/`**에서 검색합니다. (이 정보는 **`man dlopen`**에서 가져온 것입니다).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(제한되지 않은 경우)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (제한되지 않은 경우)
6. `/usr/lib/`

{% hint style="danger" %}
이름에 슬래시가 없는 경우, 히재킹을 수행하는 두 가지 방법이 있습니다:

* **`LC_RPATH`** 중 하나가 **쓰기 가능**한 경우 (하지만 서명이 확인되므로, 여기에는 바이너리가 제한되지 않아야 함)
* 바이너리가 **제한되지 않은 경우** CWD에서 무언가를 로드할 수 있습니다 (또는 언급된 환경 변수 중 하나를 악용)
{% endhint %}

* 경로가 **프레임워크 경로처럼 보이는 경우** (예: `/stuff/foo.framework/foo`), **`$DYLD_FRAMEWORK_PATH`**가 실행 시 설정되었다면, dyld는 먼저 해당 디렉토리에서 **프레임워크 부분 경로** (예: `foo.framework/foo`)를 찾습니다. 그 다음, dyld는 **제공된 경로를 그대로** 시도합니다 (상대 경로의 경우 현재 작업 디렉토리를 사용). 마지막으로, 오래된 바이너리의 경우, dyld는 일부 대체 방법을 시도합니다. **`$DYLD_FALLBACK_FRAMEWORK_PATH`**가 실행 시 설정되었다면, dyld는 해당 디렉토리에서 검색합니다. 그렇지 않으면, dyld는 **`/Library/Frameworks`** (macOS에서 프로세스가 제한되지 않은 경우) 그리고 **`/System/Library/Frameworks`**에서 검색합니다.
1. `$DYLD_FRAMEWORK_PATH`
2. 제공된 경로 (상대 경로의 경우 현재 작업 디렉토리를 사용, 제한되지 않은 프로세스의 경우)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (제한되지 않은 경우)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
프레임워크 경로인 경우, 히재킹하는 방법은 다음과 같습니다:

* 프로세스가 **제한되지 않은 경우**, CWD의 **상대 경로** 또는 언급된 환경 변수를 악용합니다 (문서에 제한된 프로세스인 경우 DYLD\_\* 환경 변수가 제거되는지 여부는 언급되지 않았습니다).
{% endhint %}

* 슬래시를 포함하지만 프레임워크 경로가 아닌 경우 (즉, 전체 경로 또는 dylib의 부분 경로), dlopen()은 먼저 (설정된 경우) **`$DYLD_LIBRARY_PATH`**에서 (경로의 리프 부분과 함께) 검색합니다. 그 다음, dyld는 **제공된 경로를 시도**합니다 (제한되지 않은 프로세스의 경우 상대 경로에 대해 현재 작업 디렉토리를 사용). 마지막으로, 오래된 바이너리의 경우, dyld는 일부 대체 방법을 시도합니다. **`$DYLD_FALLBACK_LIBRARY_PATH`**가 실행 시 설정되었다면, dyld는 해당 디렉토리에서 검색합니다. 그렇지 않으면, dyld는 **`/usr/local/lib/`** (제한되지 않은 프로세스의 경우) 그리고 **`/usr/lib/`**에서 검색합니다.
1. `$DYLD_LIBRARY_PATH`
2. 제공된 경로 (제한되지 않은 프로세스의 경우 상대 경로에 대해 현재 작업 디렉토리를 사용)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (제한되지 않은 프로세스의 경우)
5. `/usr/lib/`

{% hint style="danger" %}
이름에 슬래시가 포함되어 있고 프레임워크가 아닌 경우, 히재킹하는 방법은 다음과 같습니다:
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
만약 컴파일하고 실행한다면, **각 라이브러리가 실패로 끝난 위치를 확인**할 수 있습니다. 또한, **파일 시스템 로그를 필터링**할 수도 있습니다:
```bash
sudo fs_usage | grep "dlopentest"
```
## 상대 경로 탈취

만약 **권한이 있는 이진 파일/앱** (예: SUID 또는 강력한 권한을 가진 이진 파일)이 **상대 경로** 라이브러리를 로드하고 **라이브러리 유효성 검사가 비활성화**되어 있다면, 공격자가 이진 파일을 수정할 수 있는 위치로 이진 파일을 이동시키고, 해당 라이브러리를 악용하여 코드를 프로세스에 주입할 수 있습니다.

## `DYLD_*` 및 `LD_LIBRARY_PATH` 환경 변수 제거

`dyld-dyld-832.7.1/src/dyld2.cpp` 파일에서 **`pruneEnvironmentVariables`** 함수를 찾을 수 있습니다. 이 함수는 **`DYLD_`**로 시작하고 **`LD_LIBRARY_PATH=`**인 모든 환경 변수를 제거합니다.

또한, **suid** 및 **sgid** 이진 파일의 경우, 이 함수는 특히 **`DYLD_FALLBACK_FRAMEWORK_PATH`** 및 **`DYLD_FALLBACK_LIBRARY_PATH`** 환경 변수를 **null**로 설정합니다.

이 함수는 동일한 파일의 **`_main`** 함수에서 OSX를 대상으로 하는 경우에 호출됩니다:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
그리고 이러한 부울 플래그들은 코드 내에서 동일한 파일에 설정됩니다:
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
이는 바이너리가 **suid** 또는 **sgid**이거나 헤더에 **RESTRICT** 세그먼트가 있거나 **CS\_RESTRICT** 플래그로 서명된 경우, **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`**가 true이며 환경 변수가 제거됩니다.

참고로, CS\_REQUIRE\_LV가 true인 경우 변수는 제거되지 않지만 라이브러리 유효성 검사에서 원래 바이너리와 동일한 인증서를 사용하는지 확인합니다.

## 제한 사항 확인

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
### 섹션 `__RESTRICT`와 세그먼트 `__restrict`

The `__RESTRICT` section is a special section in macOS that is used for library injection and privilege escalation techniques. It is typically found within the `__restrict` segment.

The `__RESTRICT` section contains code that is executed with elevated privileges, allowing an attacker to gain unauthorized access to sensitive system resources. By injecting malicious code into this section, an attacker can exploit vulnerabilities in the macOS operating system and escalate their privileges.

It is important for system administrators and developers to be aware of the existence of the `__RESTRICT` section and take appropriate measures to secure it. Regular security audits and vulnerability assessments can help identify and mitigate potential risks associated with this section.

By understanding the purpose and implications of the `__RESTRICT` section, security professionals can better protect macOS systems from library injection attacks and privilege escalation attempts.
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

새 인증서를 Keychain에 생성하고 이를 사용하여 이진 파일에 서명합니다:

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
참고로, **`0x0(none)`** 플래그로 서명된 이진 파일이 있더라도, 실행될 때 동적으로 **`CS_RESTRICT`** 플래그를 얻을 수 있으므로 이 기술은 그들에게는 작동하지 않을 수 있습니다.

다음 명령어로 프로세스가 이 플래그를 가지고 있는지 확인할 수 있습니다 (여기에서 [**csops를 받으세요**](https://github.com/axelexic/CSOps)):&#x20;
```bash
csops -status <pid>
```
그리고 플래그 0x800이 활성화되어 있는지 확인하십시오.
{% endhint %}

## 참고 자료
* [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
