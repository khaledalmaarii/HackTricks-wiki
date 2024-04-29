# macOS 라이브러리 주입

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로에서 영웅까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를** 팔로우하세요.
* **해킹 요령을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

{% hint style="danger" %}
**dyld의 코드는 오픈 소스**이며 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)에서 찾을 수 있으며 **URL을 사용하여 tar를 다운로드**할 수 있습니다. [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **Dyld 프로세스**

바이너리 내에서 Dyld가 라이브러리를 로드하는 방법을 살펴보세요:

{% content-ref url="macos-dyld-process.md" %}
[macos-dyld-process.md](macos-dyld-process.md)
{% endcontent-ref %}

## **DYLD\_INSERT\_LIBRARIES**

이는 [**Linux의 LD\_PRELOAD와 유사한**](../../../../linux-hardening/privilege-escalation/#ld\_preload) 것입니다. 환경 변수가 활성화된 경우 특정 경로에서 라이브러리를 로드할 프로세스를 지정할 수 있습니다.

이 기술은 또한 **ASEP 기술로 사용**될 수 있습니다. 설치된 모든 응용 프로그램에는 `LSEnvironmental`이라는 키를 사용하여 **환경 변수를 할당**하는 "Info.plist"라는 plist가 있습니다.

{% hint style="info" %}
2012년 이후 **Apple은 DYLD_INSERT_LIBRARIES의 권한을 크게 제한**했습니다.

코드로 이동하여 **`src/dyld.cpp`**를 확인하세요. 함수 **`pruneEnvironmentVariables`**에서 **`DYLD_*`** 변수가 제거되는 것을 볼 수 있습니다.

함수 **`processRestricted`**에서 제한 사유가 설정됩니다. 해당 코드를 확인하면 제한 사유가 다음과 같음을 알 수 있습니다:

* 이진 파일이 `setuid/setgid` 상태임
* macho 이진 파일에 `__RESTRICT/__restrict` 섹션이 존재함
* 소프트웨어에 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) 권한이 있는 경우
* 이진 파일의 **권한**을 다음과 같이 확인할 수 있습니다: `codesign -dv --entitlements :- </path/to/bin>`

더 최신 버전에서는 이 논리를 함수 **`configureProcessRestrictions`**의 두 번째 부분에서 찾을 수 있습니다. 그러나 더 최신 버전에서 실행되는 것은 함수의 **첫 번째 부분의 체크**입니다 (iOS 또는 시뮬레이션과 관련된 if문은 macOS에서 사용되지 않으므로 제거할 수 있습니다).
{% endhint %}

### 라이브러리 유효성 검사

바이너리가 **`DYLD_INSERT_LIBRARIES`** 환경 변수를 사용할 수 있더라도, 라이브러리의 서명을 확인하는 경우 사용자 정의 라이브러리를 로드하지 않습니다.

사용자 정의 라이브러리를 로드하려면 바이너리에 다음과 같은 권한이 있어야 합니다:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

또는 바이너리에 **하드단화 런타임 플래그** 또는 **라이브러리 유효성 검사 플래그**가 없어야 합니다.

바이너리가 **하드단화 런타임**을 가지고 있는지 확인하려면 `codesign --display --verbose <bin>`을 사용하여 **`CodeDirectory`**에서 런타임 플래그를 확인하세요. **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**와 같이 플래그를 확인할 수 있습니다.

또한 바이너리와 **동일한 인증서로 서명된 라이브러리를 로드**할 수 있습니다.

이를 (남용하여) 어떻게 사용하고 제한 사항을 확인하는 예제를 찾으세요:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib 해킹

{% hint style="danger" %}
**이전 라이브러리 유효성 검사 제한도** Dylib 해킹 공격을 수행하는 데 적용됩니다.
{% endhint %}

Windows와 마찬가지로 MacOS에서도 **dylibs를 해킹**하여 **응용 프로그램이** **임의의** **코드를 실행**하도록 할 수 있습니다 (사실 정상 사용자로부터 이를 수행하는 것은 `.app` 번들 내부에 쓰기 권한을 얻기 위해 TCC 권한이 필요할 수 있습니다).\
그러나 **MacOS** 응용 프로그램이 라이브러리를 로드하는 방식은 **Windows**보다 **제한적**입니다. 이는 **악성 코드** 개발자가 이 기술을 **은폐**하는 데는 사용할 수 있지만 **권한 상승을 악용하는 것은 훨씬 어려울 수 있음**을 의미합니다.

먼저, **MacOS 바이너리에서 라이브러리의 전체 경로를 지정하는 것이 더 일반적**입니다. 둘째, **MacOS는** **$PATH** 폴더에서 **라이브러리를 검색하지 않습니다**.

이 기능과 관련된 **주요 부분**은 `ImageLoader.cpp`의 **`ImageLoader::recursiveLoadLibraries`**에 있습니다.

macho 바이너리가 라이브러리를 로드하는 데 사용할 수 있는 **4가지 다른 헤더 명령**이 있습니다:

* **`LC_LOAD_DYLIB`** 명령은 dylib를 로드하는 일반적인 명령입니다.
* **`LC_LOAD_WEAK_DYLIB`** 명령은 이전 명령과 유사하게 작동하지만 dylib를 찾을 수 없는 경우 오류 없이 실행이 계속됩니다.
* **`LC_REEXPORT_DYLIB`** 명령은 다른 라이브러리에서 심볼을 프록시(또는 다시 내보냄)합니다.
* **`LC_LOAD_UPWARD_DYLIB`** 명령은 서로 의존하는 두 라이브러리가 있을 때 사용됩니다(이를 _upward dependency_라고 합니다).

그러나 **2가지 유형의 dylib 해킹**이 있습니다:

* **부재한 약한 링크된 라이브러리**: 이는 응용 프로그램이 **LC\_LOAD\_WEAK\_DYLIB**로 구성된 존재하지 않는 라이브러리를 로드하려고 시도할 것을 의미합니다. 그런 다음 **공격자가 예상대로 dylib를 배치하면 로드됩니다**.
* 링크가 "약한"이라는 사실은 라이브러리를 찾을 수 없어도 응용 프로그램이 계속 실행됨을 의미합니다.
* 이와 관련된 **코드**는 `ImageLoaderMachO.cpp`의 `ImageLoaderMachO::doGetDependentLibraries` 함수에 있으며 `lib->required`는 `LC_LOAD_WEAK_DYLIB`가 true일 때에만 `false`입니다.
* 이진 파일에서 **약한 링크된 라이브러리**를 찾으려면 (나중에 해킹 라이브러리를 만드는 방법에 대한 예제가 있습니다):
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **@rpath로 구성**: Mach-O 바이너리에는 **`LC_RPATH`** 및 **`LC_LOAD_DYLIB`** 명령이 있을 수 있습니다. 이러한 명령의 **값**에 따라 **다른 디렉토리**에서 **라이브러리가 로드**됩니다.
* **`LC_RPATH`**는 바이너리에서 라이브러리를 로드하는 데 사용되는 일부 폴더의 경로를 포함합니다.
* **`LC_LOAD_DYLIB`**에는 로드할 특정 라이브러리의 경로가 포함됩니다. 이러한 경로에는 **`@rpath`**가 포함될 수 있으며, 이는 **`LC_RPATH`**의 값으로 **대체**됩니다. **`LC_RPATH`**에 여러 경로가 있는 경우 모든 경로가 라이브러리를 로드하기 위해 사용됩니다. 예시:
* 만약 **`LC_LOAD_DYLIB`**에 `@rpath/library.dylib`가 포함되어 있고 **`LC_RPATH`**에 `/application/app.app/Contents/Framework/v1/` 및 `/application/app.app/Contents/Framework/v2/`가 포함되어 있다면, 두 폴더가 `library.dylib`를 로드하는 데 사용됩니다. 라이브러리가 `[...]/v1/`에 존재하지 않고 공격자가 해당 위치에 라이브러리를 배치하여 `[...]/v2/`의 라이브러리 로드를 탈취할 수 있습니다. 이는 **`LC_LOAD_DYLIB`**의 경로 순서에 따라 진행됩니다.
* 이진 파일에서 **rpath 경로 및 라이브러리**를 찾으려면 다음을 사용하십시오: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: **주 실행 파일이 있는 디렉토리**의 **경로**입니다.

**`@loader_path`**: **로드 명령을 포함하는 Mach-O 이진 파일이 있는 디렉토리**의 **경로**입니다.

* 실행 파일에서 사용될 때 **`@loader_path`**는 사실상 **`@executable_path`**와 **동일**합니다.
* **dylib**에서 사용될 때 **`@loader_path`**는 **dylib의 경로**를 제공합니다.
{% endhint %}

이 기능을 악용하여 **권한 상승**하는 방법은 **루트**에 의해 실행되는 **어플리케이션이** **공격자가 쓰기 권한을 가진 폴더**에서 **라이브러리를 찾는** 드문 경우입니다.

{% hint style="success" %}
어플리케이션에서 **누락된 라이브러리**를 찾는 좋은 **스캐너**는 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) 또는 [**CLI 버전**](https://github.com/pandazheng/DylibHijack)입니다.\
이 기술에 대한 기술적인 세부 정보가 포함된 좋은 **보고서**는 [**여기**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)에서 찾을 수 있습니다.
{% endhint %}

**예시**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
**이전 라이브러리 유효성 검사 제한 사항도** Dlopen hijacking 공격을 수행하기 위해 적용됨을 기억하십시오.
{% endhint %}

**`man dlopen`**에서:

* 경로에 **슬래시 문자가 없는 경우** (즉, 단순히 리프 이름인 경우), **dlopen()은 검색**을 수행합니다. **`$DYLD_LIBRARY_PATH`**가 시작할 때 설정되었다면, dyld는 먼저 해당 디렉토리에서 찾습니다. 그 다음, 호출하는 mach-o 파일이나 주 실행 파일이 **`LC_RPATH`**를 지정하면 dyld는 **해당 디렉토리에서 찾습니다**. 그 다음, 프로세스가 **제한되지 않은 경우**, dyld는 **현재 작업 디렉토리**에서 검색합니다. 마지막으로, 오래된 이진 파일의 경우 dyld는 일부 대체 방법을 시도합니다. **`$DYLD_FALLBACK_LIBRARY_PATH`**가 시작할 때 설정되었다면, dyld는 **해당 디렉토리에서 검색**하고, 그렇지 않으면 dyld는 **`/usr/local/lib/`**에서 검색합니다 (프로세스가 제한되지 않은 경우), 그리고 **`/usr/lib/`**에서 검색합니다. (이 정보는 **`man dlopen`**에서 가져온 것입니다).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(제한되지 않은 경우)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (제한되지 않은 경우)
6. `/usr/lib/`

{% hint style="danger" %}
이름에 슬래시가 없는 경우, hijacking을 수행하는 두 가지 방법이 있습니다:

* 어떤 **`LC_RPATH`**가 **쓰기 가능**한 경우 (그러나 서명이 확인되므로 여기에는 바이너리가 제한되지 않아야 함)
* 바이너리가 **제한되지 않은 경우** CWD에서 무언가를 로드할 수 있습니다 (또는 언급된 환경 변수 중 하나를 악용)
{% endhint %}

* 경로가 **프레임워크 경로처럼 보이는 경우** (예: `/stuff/foo.framework/foo`), **`$DYLD_FRAMEWORK_PATH`**가 시작할 때 설정되었다면, dyld는 먼저 해당 디렉토리에서 **프레임워크 부분 경로** (예: `foo.framework/foo`)를 찾습니다. 그 다음, dyld는 **제공된 경로를 그대로 시도**합니다 (상대 경로의 경우 현재 작업 디렉토리 사용). 마지막으로, 오래된 이진 파일의 경우 dyld는 일부 대체 방법을 시도합니다. **`$DYLD_FALLBACK_FRAMEWORK_PATH`**가 시작할 때 설정되었다면, dyld는 해당 디렉토리에서 검색합니다. 그렇지 않으면, **`/Library/Frameworks`** (macOS에서 프로세스가 제한되지 않은 경우) 및 **`/System/Library/Frameworks`**에서 검색합니다.
1. `$DYLD_FRAMEWORK_PATH`
2. 제공된 경로 (제한되지 않은 프로세스의 경우 상대 경로에 대해 현재 작업 디렉토리 사용)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (제한되지 않은 경우)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
프레임워크 경로인 경우, hijacking하는 방법은 다음과 같습니다:

* 프로세스가 **제한되지 않은 경우**, CWD의 **상대 경로를 악용**하거나 언급된 환경 변수 중 하나를 악용합니다 (문서에 명시되지 않았지만 프로세스가 제한되어 있지 않은 경우 DYLD\_\* 환경 변수가 제거됩니다).
{% endhint %}

* 슬래시가 포함되지만 프레임워크 경로가 아닌 경우 (즉, dylib의 전체 경로 또는 부분 경로인 경우), dlopen()은 먼저 (설정된 경우) **`$DYLD_LIBRARY_PATH`**에서 (경로의 리프 부분 사용) 찾습니다. 그 다음, dyld는 제공된 경로를 시도합니다 (상대 경로의 경우 현재 작업 디렉토리 사용 (제한되지 않은 프로세스의 경우만)). 마지막으로, 오래된 이진 파일의 경우 dyld는 대체 방법을 시도합니다. **`$DYLD_FALLBACK_LIBRARY_PATH`**가 시작할 때 설정되었다면, dyld는 해당 디렉토리에서 검색하고, 그렇지 않으면 dyld는 **`/usr/local/lib/`**에서 검색합니다 (프로세스가 제한되지 않은 경우), 그리고 **`/usr/lib/`**에서 검색합니다.
1. `$DYLD_LIBRARY_PATH`
2. 제공된 경로 (제한되지 않은 프로세스의 경우 상대 경로에 대해 현재 작업 디렉토리 사용)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (제한되지 않은 경우)
5. `/usr/lib/`

{% hint style="danger" %}
이름에 슬래시가 있고 프레임워크가 아닌 경우, hijacking하는 방법은 다음과 같습니다:

* 바이너리가 **제한되지 않은 경우** CWD 또는 `/usr/local/lib`에서 무언가를 로드하거나 언급된 환경 변수 중 하나를 악용합니다.
{% endhint %}

{% hint style="info" %}
참고: **dlopen 검색을 제어하는** 구성 파일이 **없습니다**.

참고: 주 실행 파일이 **set\[ug]id 바이너리이거나 entitlement로 코드 서명**되었으면 **모든 환경 변수가 무시**되며, 전체 경로만 사용할 수 있습니다 ([DYLD\_INSERT\_LIBRARIES 제한 사항 확인](macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions)에서 자세한 정보 확인)

참고: Apple 플랫폼은 32비트 및 64비트 라이브러리를 결합한 "universal" 파일을 사용합니다. 이는 **별도의 32비트 및 64비트 검색 경로가 없음**을 의미합니다.

참고: Apple 플랫폼에서 대부분의 OS dylib은 **dyld 캐시에 통합**되어 있어 디스크에 존재하지 않습니다. 따라서 OS dylib가 존재하는지 사전 확인하기 위해 **`stat()`**을 호출하는 것은 **작동하지 않습니다**. 그러나 **`dlopen_preflight()`**는 호환되는 mach-o 파일을 찾기 위해 **`dlopen()`**과 동일한 단계를 사용합니다.
{% endhint %}

**경로 확인**

다음 코드로 모든 옵션을 확인해봅시다:
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
만약 컴파일하고 실행하면 **각 라이브러리가 어디에서 실패로 검색되었는지** 볼 수 있습니다. 또한 **FS 로그를 필터링할 수 있습니다**:
```bash
sudo fs_usage | grep "dlopentest"
```
## 상대 경로 탈취

만약 **특권이 있는 이진 파일/앱** (예: SUID 또는 강력한 권한을 가진 일부 이진 파일)이 **상대 경로** 라이브러리를 로드하고 있고 **라이브러리 유효성 검사가 비활성화**되어 있다면, 공격자가 이진 파일을 공격자가 상대 경로로 로드된 라이브러리를 수정할 수 있는 위치로 이동시키고, 해당 라이브러리를 악용하여 프로세스에 코드를 주입할 수 있습니다.

## `DYLD_*` 및 `LD_LIBRARY_PATH` 환경 변수 정리

`dyld-dyld-832.7.1/src/dyld2.cpp` 파일에서 **`pruneEnvironmentVariables`** 함수를 찾을 수 있습니다. 이 함수는 **`DYLD_`로 시작하는** 모든 환경 변수와 **`LD_LIBRARY_PATH=`**를 제거합니다.

또한 **suid** 및 **sgid** 이진 파일에 대해 특별히 **`DYLD_FALLBACK_FRAMEWORK_PATH`** 및 **`DYLD_FALLBACK_LIBRARY_PATH`** 환경 변수를 **null**로 설정합니다.

이 함수는 OSX를 대상으로 하는 경우 동일한 파일의 **`_main`** 함수에서 다음과 같이 호출됩니다:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
그 부울 플래그들은 코드 내 동일한 파일에 설정됩니다:
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
이것은 바이너리가 **suid** 또는 **sgid** 상태이거나 헤더에 **RESTRICT** 세그먼트가 있거나 **CS\_RESTRICT** 플래그로 서명된 경우, **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`**가 true이고 환경 변수가 제거된다는 것을 의미합니다.

CS\_REQUIRE\_LV가 true인 경우, 변수가 제거되지 않지만 라이브러리 유효성 검사는 원본 바이너리와 동일한 인증서를 사용하는지 확인합니다.

## 제한 사항 확인

### SUID 및 SGID
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
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### 강화된 런타임

키체인에 새 인증서를 생성하고 해당 인증서를 사용하여 이진 파일에 서명합니다:

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
심지어 플래그가 **`0x0(none)`**으로 서명된 이진 파일이 있더라도, 실행될 때 동적으로 **`CS_RESTRICT`** 플래그를 받을 수 있으므로 이 기술은 그들에게 적용되지 않을 수 있음을 유의하십시오.

이 프로세스가 이 플래그를 가지고 있는지 확인할 수 있습니다 ([**여기에서 csops를 확인하십시오**](https://github.com/axelexic/CSOps)):
```bash
csops -status <pid>
```
그런 다음 플래그 0x800이 활성화되어 있는지 확인하십시오.
{% endhint %}

## 참고 자료

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)
* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 영웅이 되는 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
