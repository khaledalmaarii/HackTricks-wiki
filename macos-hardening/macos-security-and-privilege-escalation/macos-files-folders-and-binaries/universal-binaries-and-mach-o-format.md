# macOS 유니버설 바이너리 및 Mach-O 형식

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 **Discord 그룹**에 **참여**하세요(https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}

## 기본 정보

Mac OS 바이너리는 일반적으로 **유니버설 바이너리**로 컴파일됩니다. **유니버설 바이너리**는 **동일한 파일에서 여러 아키텍처를 지원**할 수 있습니다.

이러한 바이너리는 기본적으로 **Mach-O 구조**를 따릅니다. 이 구조는 다음과 같이 구성됩니다:

* 헤더(Header)
* 로드 명령(Load Commands)
* 데이터(Data)

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Fat Header

다음과 같이 파일을 검색합니다: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* 뒤를 따르는 구조체의 수 */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* CPU 지정자 (int) */
cpu_subtype_t	cpusubtype;	/* 머신 지정자 (int) */
uint32_t	offset;		/* 이 객체 파일의 파일 오프셋 */
uint32_t	size;		/* 이 객체 파일의 크기 */
uint32_t	align;		/* 2의 거듭제곱으로 정렬 */
};
</code></pre>

헤더에는 **매직** 바이트가 있고 파일이 **포함하는** **아키텍처**의 **수**(`nfat_arch`)가 뒤따르며 각 아키텍처는 `fat_arch` 구조체를 가집니다.

다음과 같이 확인합니다:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architecture x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architecture arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

또는 [Mach-O View](https://sourceforge.net/projects/machoview/) 도구를 사용하여 확인할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

일반적으로 2개의 아키텍처를 위해 컴파일된 유니버설 바이너리는 일반적으로 하나의 아키텍처를 위해 컴파일된 것의 **크기를 두 배**로 만듭니다.

## **Mach-O 헤더**

헤더에는 Mach-O 파일로 식별하기 위한 매직 바이트 및 대상 아키텍처에 대한 정보와 같은 파일에 대한 기본 정보가 포함되어 있습니다. 다음 위치에서 찾을 수 있습니다: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
uint32_t	magic;		/* mach magic number identifier */
cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
cpu_subtype_t	cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file (usage and alignment for the file) */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
uint32_t	magic;		/* mach magic number identifier */
int32_t		cputype;	/* cpu specifier */
int32_t		cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
uint32_t	reserved;	/* reserved */
};
```
### Mach-O 파일 유형

다양한 파일 유형이 있으며 이를 찾을 수 있습니다. [**예시로 여기에서 정의된 소스 코드**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h). 가장 중요한 것들은:

* `MH_OBJECT`: 재배치 가능한 오브젝트 파일 (컴파일의 중간 결과물로, 아직 실행 파일이 아님).
* `MH_EXECUTE`: 실행 파일.
* `MH_FVMLIB`: 고정 VM 라이브러리 파일.
* `MH_CORE`: 코드 덤프
* `MH_PRELOAD`: 사전로드된 실행 파일 (XNU에서 더 이상 지원되지 않음)
* `MH_DYLIB`: 동적 라이브러리
* `MH_DYLINKER`: 동적 링커
* `MH_BUNDLE`: "플러그인 파일". gcc의 -bundle을 사용하여 생성되며 `NSBundle` 또는 `dlopen`에 의해 명시적으로 로드됨.
* `MH_DYSM`: 동반 `.dSym` 파일 (디버깅을 위한 심볼이 있는 파일).
* `MH_KEXT_BUNDLE`: 커널 확장.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
또는 [Mach-O View](https://sourceforge.net/projects/machoview/)를 사용하십시오:

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O 플래그**

소스 코드는 또한 라이브러리를 로드하는 데 유용한 여러 플래그를 정의합니다:

* `MH_NOUNDEFS`: 정의되지 않은 참조 없음 (완전히 링크됨)
* `MH_DYLDLINK`: Dyld 링킹
* `MH_PREBOUND`: 동적 참조 사전 바인딩.
* `MH_SPLIT_SEGS`: 파일이 r/o 및 r/w 세그먼트로 분할됨.
* `MH_WEAK_DEFINES`: 이진 파일에 약한 정의된 심볼이 있음
* `MH_BINDS_TO_WEAK`: 이진 파일이 약한 심볼을 사용함
* `MH_ALLOW_STACK_EXECUTION`: 스택을 실행 가능하게 만듦
* `MH_NO_REEXPORTED_DYLIBS`: LC\_REEXPORT 명령이 없는 라이브러리
* `MH_PIE`: 위치 독립 실행 파일
* `MH_HAS_TLV_DESCRIPTORS`: 쓰레드 로컬 변수가 있는 섹션이 있음
* `MH_NO_HEAP_EXECUTION`: 힙/데이터 페이지에 대한 실행 없음
* `MH_HAS_OBJC`: 이진 파일에 Objective-C 섹션이 있음
* `MH_SIM_SUPPORT`: 시뮬레이터 지원
* `MH_DYLIB_IN_CACHE`: 공유 라이브러리 캐시의 dylibs/frameworks에서 사용됨.

## **Mach-O 로드 명령어**

**메모리에 파일의 레이아웃**이 여기에 지정되어 있으며, **심볼 테이블의 위치**, 실행 시작 시 주 스레드의 컨텍스트 및 필요한 **공유 라이브러리**에 대한 내용이 설명됩니다. 이는 메모리로의 바이너리 로딩 과정에 대한 동적 로더 **(dyld)**에게 지침을 제공합니다.

이는 **`loader.h`**에 정의된 **load\_command** 구조를 사용합니다:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
시스템이 다르게 처리하는 **약 50가지의 로드 명령어 유형**이 있습니다. 가장 일반적인 것들은: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, 그리고 `LC_CODE_SIGNATURE`입니다.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
기본적으로 이 유형의 로드 명령어는 **\_\_TEXT** (실행 코드)와 **\_\_DATA** (프로세스용 데이터) **세그먼트를 실행 파일이 실행될 때 데이터 섹션에 표시된 오프셋에 따라 어떻게 로드할지**를 정의합니다.
{% endhint %}

이러한 명령어는 프로세스의 **가상 메모리 공간에 매핑되는 세그먼트를 정의**합니다.

**\_\_TEXT** 세그먼트는 프로그램의 실행 코드를 보유하며, **\_\_DATA** 세그먼트는 프로세스에서 사용되는 데이터를 포함합니다. 이러한 **세그먼트는 Mach-O 파일의 데이터 섹션에 위치**합니다.

**각 세그먼트**는 더 세부적으로 **여러 섹션으로 나뉠** 수 있습니다. **로드 명령어 구조**에는 해당 세그먼트 내의 **이러한 섹션에 대한 정보**가 포함되어 있습니다.

헤더에서 먼저 **세그먼트 헤더**를 찾을 수 있습니다:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* 64비트 아키텍처용 */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* section_64 구조체의 크기를 포함 */
char		segname[16];	/* 세그먼트 이름 */
uint64_t	vmaddr;		/* 이 세그먼트의 메모리 주소 */
uint64_t	vmsize;		/* 이 세그먼트의 메모리 크기 */
uint64_t	fileoff;	/* 이 세그먼트의 파일 오프셋 */
uint64_t	filesize;	/* 파일에서 매핑할 양 */
int32_t		maxprot;	/* 최대 VM 보호 */
int32_t		initprot;	/* 초기 VM 보호 */
<strong>	uint32_t	nsects;		/* 세그먼트 내 섹션 수 */
</strong>	uint32_t	flags;		/* 플래그 */
};
</code></pre>

세그먼트 헤더의 예시:

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

이 헤더는 **그 뒤에 나타나는 섹션 헤더의 수를 정의**합니다.
```c
struct section_64 { /* for 64-bit architectures */
char		sectname[16];	/* name of this section */
char		segname[16];	/* segment this section goes in */
uint64_t	addr;		/* memory address of this section */
uint64_t	size;		/* size in bytes of this section */
uint32_t	offset;		/* file offset of this section */
uint32_t	align;		/* section alignment (power of 2) */
uint32_t	reloff;		/* file offset of relocation entries */
uint32_t	nreloc;		/* number of relocation entries */
uint32_t	flags;		/* flags (section type and attributes)*/
uint32_t	reserved1;	/* reserved (for offset or index) */
uint32_t	reserved2;	/* reserved (for count or sizeof) */
uint32_t	reserved3;	/* reserved */
};
```
예시 **섹션 헤더**:

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

만약 **섹션 오프셋** (0x37DC)에 **아키텍처 시작 오프셋**을 **더한다면**, 이 경우 `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

또한 **커맨드 라인**에서 **헤더 정보**를 얻는 것도 가능합니다:
```bash
otool -lv /bin/ls
```
```markdown
일반적으로이 cmd에 로드 된 공통 세그먼트 :

* **`__PAGEZERO`:** 커널에 **주소 제로를 매핑**하도록 지시하여 **읽을 수 없고 쓸 수 없고 실행할 수 없게**합니다. 구조체의 maxprot 및 minprot 변수는이 페이지에 **읽기-쓰기-실행 권한이 없음**을 나타내도록 0으로 설정됩니다.
* 이 할당은 **NULL 포인터 역참조 취약점을 완화하는 데 중요**합니다. 이는 XNU가 첫 번째 페이지 (i386 제외)가 접근할 수 없게하는 강력한 페이지 제로를 시행하기 때문입니다. 바이너리는 작은 \_\_PAGEZERO를 만들어 이 요구 사항을 충족시킬 수 있습니다 (`-pagezero_size`를 사용하여 처음 4k를 커버하고 나머지 32비트 메모리를 사용자 및 커널 모드에서 모두 접근 가능하게 함).
* **`__TEXT`**: **읽기** 및 **실행** 권한이 있는 **실행 가능한 코드**를 포함합니다 (쓰기 권한 없음)**.** 이 세그먼트의 일반적인 섹션 :
* `__text`: 컴파일된 이진 코드
* `__const`: 상수 데이터 (읽기 전용)
* `__[c/u/os_log]string`: C, Unicode 또는 os 로그 문자열 상수
* `__stubs` 및 `__stubs_helper`: 동적 라이브러리 로드 프로세스 중에 관련됨
* `__unwind_info`: 스택 언와인드 데이터
* 이 모든 내용이 서명되었지만 실행 가능으로 표시되었음을 유의하십시오 (이 권한이 필요하지 않은 섹션의 악용 옵션을 더 만듭니다).
* **`__DATA`**: **읽기** 및 **쓰기** 가능한 데이터를 포함합니다 (실행 불가능)**.**
* `__got:` Global Offset Table
* `__nl_symbol_ptr`: Non lazy (로드시 바인딩) 심볼 포인터
* `__la_symbol_ptr`: Lazy (사용시 바인딩) 심볼 포인터
* `__const`: 읽기 전용 데이터 여야 함 (실제로는 아님)
* `__cfstring`: CoreFoundation 문자열
* `__data`: 초기화된 전역 변수
* `__bss`: 초기화되지 않은 정적 변수
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist 등): Objective-C 런타임에서 사용되는 정보
* **`__DATA_CONST`**: \_\_DATA.\_\_const는 상수가 보장되지 않음 (쓰기 권한), 다른 포인터 및 GOT도 마찬가지입니다. 이 섹션은 `mprotect`를 사용하여 `__const`, 일부 이니셜라이저 및 GOT 테이블 (한 번 해결되면)을 **읽기 전용**으로 만듭니다.
* **`__LINKEDIT`**: 링커 (dyld)를 위한 정보를 포함하며, 심볼, 문자열 및 재배치 테이블 항목 등이 포함됩니다. 이는 `__TEXT` 또는 `__DATA`에 없는 콘텐츠의 일반적인 컨테이너이며, 해당 내용은 다른 로드 명령에서 설명됩니다.
* dyld 정보: Rebase, Non-lazy/lazy/weak 바인딩 옵코드 및 익스포트 정보
* 함수 시작: 함수의 시작 주소 테이블
* 코드 내 데이터: \_\_text의 데이터 아일랜드
* 심볼 테이블: 바이너리의 심볼
* 간접 심볼 테이블: 포인터/스텁 심볼
* 문자열 테이블
* 코드 서명
* **`__OBJC`**: Objective-C 런타임에서 사용되는 정보를 포함합니다. 이 정보는 \_\_DATA 세그먼트 내의 여러 \_\_objc\_\* 섹션에서도 찾을 수 있습니다.
* **`__RESTRICT`**: **`__restrict`**라는 단일 섹션을 포함하지 않은 콘텐츠가있는 세그먼트로, 바이너리를 실행할 때 DYLD 환경 변수를 무시하도록 보장합니다.

코드에서 볼 수 있듯이 **세그먼트는 플래그도 지원**합니다 (그러나 그들은 많이 사용되지는 않음) :

* `SG_HIGHVM`: Core 전용 (사용되지 않음)
* `SG_FVMLIB`: 사용되지 않음
* `SG_NORELOC`: 세그먼트에 재배치가 없음
* `SG_PROTECTED_VERSION_1`: 암호화. 예를 들어 Finder가 텍스트 `__TEXT` 세그먼트를 암호화하는 데 사용됨.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**은 **entryoff 속성**에 진입점을 포함합니다. 로드 시, **dyld**는 단순히 이 값을 (메모리 내) **바이너리의 베이스에 추가**하고, 그런 다음 이 명령으로 이동하여 바이너리 코드의 실행을 시작합니다.

**`LC_UNIXTHREAD`**는 주 스레드를 시작할 때 레지스터가 가져야 하는 값들을 포함합니다. 이것은 이미 사용되지 않았지만 **`dyld`**는 여전히 사용합니다. 이를 통해이로 설정된 레지스터의 값을 볼 수 있습니다 :
```
```bash
otool -l /usr/lib/dyld
[...]
Load command 13
cmd LC_UNIXTHREAD
cmdsize 288
flavor ARM_THREAD_STATE64
count ARM_THREAD_STATE64_COUNT
x0  0x0000000000000000 x1  0x0000000000000000 x2  0x0000000000000000
x3  0x0000000000000000 x4  0x0000000000000000 x5  0x0000000000000000
x6  0x0000000000000000 x7  0x0000000000000000 x8  0x0000000000000000
x9  0x0000000000000000 x10 0x0000000000000000 x11 0x0000000000000000
x12 0x0000000000000000 x13 0x0000000000000000 x14 0x0000000000000000
x15 0x0000000000000000 x16 0x0000000000000000 x17 0x0000000000000000
x18 0x0000000000000000 x19 0x0000000000000000 x20 0x0000000000000000
x21 0x0000000000000000 x22 0x0000000000000000 x23 0x0000000000000000
x24 0x0000000000000000 x25 0x0000000000000000 x26 0x0000000000000000
x27 0x0000000000000000 x28 0x0000000000000000  fp 0x0000000000000000
lr 0x0000000000000000 sp  0x0000000000000000  pc 0x0000000000004b70
cpsr 0x00000000

[...]
```
### **`LC_CODE_SIGNATURE`**

Macho-O 파일의 코드 서명에 관한 정보를 포함합니다. 일반적으로 파일의 맨 끝에 있는 서명 blob을 가리키는 오프셋만 포함합니다.\
그러나 [이 블로그 게시물](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)과 [이 gist](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)에서 이 섹션에 대한 정보를 찾을 수 있습니다.

### **`LC_ENCRYPTION_INFO[_64]`**

바이너리 암호화를 지원합니다. 그러나 공격자가 프로세스를 침해하면 메모리를 암호화 해제하여 덤프할 수 있습니다.

### **`LC_LOAD_DYLINKER`**

공유 라이브러리를 프로세스 주소 공간에 매핑하는 동적 링커 실행 파일의 경로를 포함합니다. 값은 항상 `/usr/lib/dyld`로 설정됩니다. macOS에서 dylib 매핑은 커널 모드가 아닌 사용자 모드에서 발생한다는 점을 강조해야 합니다.

### **`LC_IDENT`**

사용되지 않지만 패닉 시 덤프 생성이 구성되어 있으면 Mach-O 코어 덤프가 생성되고 커널 버전이 `LC_IDENT` 명령에 설정됩니다.

### **`LC_UUID`**

랜덤 UUID입니다. 직접적으로는 유용하지 않지만 XNU는 프로세스 정보와 함께 캐시하며, 충돌 보고서에 사용될 수 있습니다.

### **`LC_DYLD_ENVIRONMENT`**

프로세스가 실행되기 전에 dyld에 환경 변수를 지정할 수 있습니다. 이는 프로세스 내에서 임의의 코드를 실행할 수 있기 때문에 매우 위험할 수 있습니다. 이 로드 명령은 `#define SUPPORT_LC_DYLD_ENVIRONMENT`로 빌드된 dyld에서만 사용되며, `DYLD_..._PATH` 형식의 변수만 처리하도록 추가 제한이 있습니다.

### **`LC_LOAD_DYLIB`**

이 로드 명령은 **로더**(dyld)에게 해당 라이브러리를 **로드하고 링크하도록 지시하는** **동적 라이브러리** 종속성을 설명합니다. Mach-O 바이너리가 필요로 하는 각 라이브러리에 대해 `LC_LOAD_DYLIB` 로드 명령이 있습니다.

* 이 로드 명령은 실제 종속 동적 라이브러리를 설명하는 `dylib` 구조를 포함하는 `dylib_command` 유형의 구조체입니다:
```objectivec
struct dylib_command {
uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
uint32_t        cmdsize;        /* includes pathname string */
struct dylib    dylib;          /* the library identification */
};

struct dylib {
union lc_str  name;                 /* library's path name */
uint32_t timestamp;                 /* library's build time stamp */
uint32_t current_version;           /* library's current version number */
uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```
![](<../../../.gitbook/assets/image (486).png>)

다음 명령어를 사용하여 CLI에서도 이 정보를 얻을 수 있습니다:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
일부 잠재적인 악성 코드 관련 라이브러리는:

* **DiskArbitration**: USB 드라이브 모니터링
* **AVFoundation:** 오디오 및 비디오 캡처
* **CoreWLAN**: Wifi 스캔

{% hint style="info" %}
Mach-O 바이너리에는 **하나 이상의 생성자**가 포함될 수 있으며, 이는 **LC\_MAIN**에 지정된 주소 **앞에서 실행**됩니다.\
어떤 생성자의 오프셋은 **\_\_DATA\_CONST** 세그먼트의 **\_\_mod\_init\_func** 섹션에 저장됩니다.
{% endhint %}

## **Mach-O 데이터**

파일의 핵심에는 로드 명령 영역에서 정의된 여러 세그먼트로 구성된 데이터 영역이 있습니다. **각 세그먼트에는 여러 데이터 섹션이 포함**될 수 있으며, 각 섹션은 **특정 유형에 대한 코드 또는 데이터**를 보유합니다.

{% hint style="success" %}
데이터는 기본적으로 로드 명령 **LC\_SEGMENTS\_64**에 의해 로드되는 모든 **정보**를 포함하는 부분입니다.
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

이에는 다음이 포함됩니다:

* **함수 테이블:** 프로그램 함수에 대한 정보를 보유
* **심볼 테이블**: 바이너리에서 사용되는 외부 함수에 대한 정보를 포함
* 내부 함수, 변수 이름 및 기타 정보도 포함될 수 있습니다.

확인하려면 [**Mach-O View**](https://sourceforge.net/projects/machoview/) 도구를 사용할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

또는 CLI에서:
```bash
size -m /bin/ls
```
## Objective-C 공통 섹션

`__TEXT` 세그먼트 (r-x):

- `__objc_classname`: 클래스 이름 (문자열)
- `__objc_methname`: 메서드 이름 (문자열)
- `__objc_methtype`: 메서드 유형 (문자열)

`__DATA` 세그먼트 (rw-):

- `__objc_classlist`: 모든 Objective-C 클래스에 대한 포인터
- `__objc_nlclslist`: Non-Lazy Objective-C 클래스에 대한 포인터
- `__objc_catlist`: 카테고리에 대한 포인터
- `__objc_nlcatlist`: Non-Lazy 카테고리에 대한 포인터
- `__objc_protolist`: 프로토콜 목록
- `__objc_const`: 상수 데이터
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`
