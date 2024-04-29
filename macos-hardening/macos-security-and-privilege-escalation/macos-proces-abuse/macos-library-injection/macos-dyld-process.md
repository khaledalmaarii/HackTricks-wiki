# macOS Dyld Process

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로부터 영웅까지 AWS 해킹 배우기</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 기본 정보

Mach-o 이진 파일의 실제 **진입점**은 일반적으로 `/usr/lib/dyld`에 정의된 동적 링크된 `LC_LOAD_DYLINKER`에서 발생합니다.

이 링커는 모든 실행 가능한 라이브러리를 찾아 메모리에 매핑하고 모든 레이지하지 않은 라이브러리를 링크한 후에 이진 파일의 진입점이 실행됩니다.

물론 **`dyld`**에는 종속성이 없습니다 (시스템 호출 및 libSystem 일부를 사용합니다).

{% hint style="danger" %}
이 링커에 취약점이 포함되어 있다면 (심지어 높은 권한을 가진 이진 파일을 실행하기 전에 실행되므로) **권한 상승**이 가능할 수 있습니다.
{% endhint %}

### 흐름

Dyld는 **`dyldboostrap::start`**에 의해 로드되며, 이는 **스택 캐너리**와 같은 것들도 로드합니다. 이는 이 함수가 **`apple`** 인수 벡터에 이와 다른 **민감한 값**을 받기 때문입니다.

**`dyls::_main()`**은 dyld의 진입점이며, 첫 번째 작업은 일반적으로 **`DYLD_*`** 환경 변수를 제한하는 `configureProcessRestrictions()`를 실행하는 것입니다. 이는 다음에서 설명됩니다:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

그런 다음, dyld 공유 캐시를 매핑하고 모든 중요한 시스템 라이브러리를 사전 링크한 다음, 이진 파일이 의존하는 라이브러리를 매핑하고 필요한 모든 라이브러리가 로드될 때까지 재귀적으로 계속합니다. 따라서:

1. `DYLD_INSERT_LIBRARIES`로 삽입된 라이브러리를 로드하기 시작합니다 (허용된 경우)
2. 그런 다음 공유 캐시된 라이브러리
3. 그런 다음 가져온 라이브러리
4. 그런 다음 재귀적으로 라이브러리 가져오기를 계속합니다

모두 로드되면 이러한 라이브러리의 **초기화자**가 실행됩니다. 이들은 `LC_ROUTINES[_64]` (이제는 사용되지 않음)에 정의된 **`__attribute__((constructor))`**를 사용하여 코딩되거나 `S_MOD_INIT_FUNC_POINTERS`로 플래그 지정된 섹션에 포인터로 위치합니다 (일반적으로: **`__DATA.__MOD_INIT_FUNC`**).

종료자는 **`__attribute__((destructor))`**로 코딩되며 `S_MOD_TERM_FUNC_POINTERS`로 플래그 지정된 섹션 (**`__DATA.__mod_term_func`**)에 위치합니다.

### 스텁

macOS의 모든 바이너리는 동적으로 링크됩니다. 따라서 다른 기계 및 컨텍스트에서 올바른 코드로 이동하는 데 도움이 되는 스텁 섹션이 포함되어 있습니다. 이러한 주소를 해결해야 하는 뇌는 이진 파일이 실행될 때 dyld입니다 (적어도 레이지하지 않은 것들).

이진 파일의 일부인 스텁 섹션:

* **`__TEXT.__[auth_]stubs`**: `__DATA` 섹션의 포인터
* **`__TEXT.__stub_helper`**: 호출할 함수에 대한 정보를 포함하는 작은 코드
* **`__DATA.__[auth_]got`**: Global Offset Table (가져온 함수의 주소, 로드 시 바인딩됨 (`S_NON_LAZY_SYMBOL_POINTERS` 플래그로 표시됨))
* **`__DATA.__nl_symbol_ptr`**: 레이지하지 않은 심볼 포인터 (로드 시 바인딩됨 (`S_NON_LAZY_SYMBOL_POINTERS` 플래그로 표시됨))
* **`__DATA.__la_symbol_ptr`**: 레이지 심볼 포인터 (첫 액세스 시 바인딩됨)

{% hint style="warning" %}
접두사 "auth\_"가 있는 포인터는 한 프로세스 암호화 키를 사용하여 보호됩니다 (PAC). 또한, 포인터를 따르기 전에 확인하기 위해 arm64 명령어 `BLRA[A/B]`를 사용할 수 있습니다. 그리고 RETA\[A/B\]는 RET 주소 대신 사용할 수 있습니다.\
실제로 **`__TEXT.__auth_stubs`**의 코드는 요청된 함수를 인증하기 위해 **`bl`** 대신 **`braa`**를 사용할 것입니다.

또한 현재 dyld 버전은 **모두를 레이지하지 않은 것으로 로드**합니다.
{% endhint %}

### 레이지 심볼 찾기
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
흥미로운 어셈블리 부분:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
printf를 호출하는 점프가 **`__TEXT.__stubs`**로 이동하는 것을 확인할 수 있습니다:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
**`__stubs`** 섹션의 분해에서:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
당신은 **GOT 주소로 점프**하는 것을 볼 수 있습니다. 이 경우에는 non-lazy로 해결되며 printf 함수의 주소를 포함할 것입니다.

다른 상황에서는 직접적으로 GOT로 점프하는 대신에 **`__DATA.__la_symbol_ptr`**로 점프할 수 있습니다. 이는 로드하려는 함수를 나타내는 값을 로드하고, 그런 다음 **`__TEXT.__stub_helper`**로 점프하여 **`__DATA.__nl_symbol_ptr`**로 점프할 수 있습니다. 이는 **`dyld_stub_binder`**의 주소를 포함하며, 함수의 번호와 주소를 매개변수로 취합니다.\
이 마지막 함수는 찾은 함수의 주소를 찾은 후, 미래에 조회를 피하기 위해 해당 위치에 쓰입니다.

{% hint style="success" %}
그러나 현재 dyld 버전에서는 모든 것을 non-lazy로 로드한다는 것을 주목하세요.
{% endhint %}

#### Dyld 옵코드

마지막으로, **`dyld_stub_binder`**는 지정된 함수를 찾아 적절한 주소에 쓰기 위해 필요합니다. 이를 위해 dyld 내에서 옵코드(유한 상태 기계)를 사용합니다.

## apple\[] argument vector

macOS에서 main 함수는 실제로 3개가 아닌 4개의 인수를 받습니다. 네 번째는 apple이라고 하며 각 항목은 `key=value` 형식입니다. 예를 들어:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
결과:
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
{% hint style="success" %}
이 값들이 main 함수에 도달할 때까지 민감한 정보가 이미 제거되었거나 데이터 누출이 발생했을 수 있습니다.
{% endhint %}

main 함수에 진입하기 전에 디버깅을 통해 이러한 흥미로운 값들을 모두 볼 수 있습니다:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld\_all\_image\_infos

이는 dyld에 의해 내보내진 dyld 상태에 대한 정보를 포함하는 구조체로, [**소스 코드**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html)에서 찾을 수 있으며, 버전, dyld\_image\_info 배열에 대한 포인터, dyld\_image\_notifier에 대한 정보, 프로세스가 공유 캐시에서 분리되었는지 여부, libSystem 초기화 함수가 호출되었는지 여부, dyld의 자체 Mach 헤더에 대한 포인터, dyld 버전 문자열에 대한 포인터 등의 정보가 포함되어 있습니다.

## dyld 환경 변수

### dyld 디버깅

dyld가 무엇을 하는지 이해하는 데 도움이 되는 흥미로운 환경 변수:

* **DYLD\_PRINT\_LIBRARIES**

로드된 각 라이브러리를 확인합니다.
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
* **DYLD\_PRINT\_SEGMENTS**

각 라이브러리가 어떻게 로드되는지 확인하세요:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
* **DYLD\_PRINT\_INITIALIZERS**

각 라이브러리 이니셜라이저가 실행될 때 출력합니다:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### 기타

* `DYLD_BIND_AT_LAUNCH`: 지연 바인딩이 비지연 바인딩으로 해결됨
* `DYLD_DISABLE_PREFETCH`: \_\_DATA 및 \_\_LINKEDIT 콘텐츠의 사전 로드 비활성화
* `DYLD_FORCE_FLAT_NAMESPACE`: 단일 수준의 바인딩
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: 해결 경로
* `DYLD_INSERT_LIBRARIES`: 특정 라이브러리 로드
* `DYLD_PRINT_TO_FILE`: 파일에 dyld 디버그 작성
* `DYLD_PRINT_APIS`: libdyld API 호출 출력
* `DYLD_PRINT_APIS_APP`: main이 수행한 libdyld API 호출 출력
* `DYLD_PRINT_BINDINGS`: 바인딩될 때 심볼 출력
* `DYLD_WEAK_BINDINGS`: 바인딩될 때 약한 심볼만 출력
* `DYLD_PRINT_CODE_SIGNATURES`: 코드 서명 등록 작업 출력
* `DYLD_PRINT_DOFS`: 로드된 D-Trace 객체 형식 섹션 출력
* `DYLD_PRINT_ENV`: dyld에서 본 환경 출력
* `DYLD_PRINT_INTERPOSTING`: interposting 작업 출력
* `DYLD_PRINT_LIBRARIES`: 로드된 라이브러리 출력
* `DYLD_PRINT_OPTS`: 로드 옵션 출력
* `DYLD_REBASING`: 심볼 리베이스 작업 출력
* `DYLD_RPATHS`: @rpath의 확장 출력
* `DYLD_PRINT_SEGMENTS`: Mach-O 세그먼트 매핑 출력
* `DYLD_PRINT_STATISTICS`: 타이밍 통계 출력
* `DYLD_PRINT_STATISTICS_DETAILS`: 자세한 타이밍 통계 출력
* `DYLD_PRINT_WARNINGS`: 경고 메시지 출력
* `DYLD_SHARED_CACHE_DIR`: 공유 라이브러리 캐시에 사용할 경로
* `DYLD_SHARED_REGION`: "use", "private", "avoid"
* `DYLD_USE_CLOSURES`: 클로저 활성화

더 많은 내용을 다음과 같이 찾을 수 있습니다:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
또는 [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)에서 dyld 프로젝트를 다운로드하고 폴더 내에서 실행하십시오:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## 참고 자료

* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원한다면** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
