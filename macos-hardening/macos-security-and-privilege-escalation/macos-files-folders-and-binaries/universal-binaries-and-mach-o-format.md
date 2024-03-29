# macOS Universal binaries & Mach-O Format

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>AWS 해킹을 처음부터 전문가까지 배우세요</strong>!</summary>

HackTricks를 지원하는 다른 방법:

- **회사를 HackTricks에서 광고하거나 PDF로 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 기본 정보

Mac OS 이진 파일은 일반적으로 **universal binaries**로 컴파일됩니다. **Universal binary**는 **동일한 파일에서 여러 아키텍처를 지원**할 수 있습니다.

이러한 이진 파일은 기본적으로 **Mach-O 구조**를 따릅니다. 이 구조는 다음과 같이 구성됩니다:

- 헤더
- 로드 명령
- 데이터

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (559).png>)

## Fat Header

다음 명령을 사용하여 파일을 검색합니다: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* number of structs that follow */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu specifier (int) */
cpu_subtype_t	cpusubtype;	/* machine specifier (int) */
uint32_t	offset;		/* file offset to this object file */
uint32_t	size;		/* size of this object file */
uint32_t	align;		/* alignment as a power of 2 */
};
</code></pre>

헤더에는 **매직** 바이트가 있고 파일이 **포함하는** **archs**의 **수**(`nfat_arch`)가 뒤따르며 각 아키텍처에는 `fat_arch` 구조체가 있습니다.

다음 명령을 사용하여 확인합니다:

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

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

일반적으로 2개 아키텍처용으로 컴파일된 universal binary는 1개 아키텍처용으로 컴파일된 것보다 **크기가 두 배**입니다.

## **Mach-O Header**

헤더에는 Mach-O 파일로 식별하는 매직 바이트와 대상 아키텍처에 대한 정보와 같은 파일에 대한 기본 정보가 포함됩니다. 다음 위치에서 찾을 수 있습니다: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
**파일 유형**:

* MH\_EXECUTE (0x2): 표준 Mach-O 실행 파일
* MH\_DYLIB (0x6): Mach-O 동적 연결 라이브러리 (즉, .dylib)
* MH\_BUNDLE (0x8): Mach-O 번들 (즉, .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
또는 [Mach-O View](https://sourceforge.net/projects/machoview/)를 사용할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Mach-O 로드 명령**

**메모리 내 파일의 레이아웃**이 여기에 지정되어 있으며, **심볼 테이블의 위치**, 실행 시작 시 주 스레드의 컨텍스트 및 필요한 **공유 라이브러리**에 대한 세부 정보가 포함되어 있습니다. 메모리로의 이진 파일 로딩 프로세스에 대한 동적 로더 **(dyld)**에게 명령이 제공됩니다.

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
기본적으로, 이 유형의 로드 명령어는 **바이너리가 실행될 때 데이터 섹션에 표시된 오프셋에 따라 \_\_TEXT** (실행 코드) **및 \_\_DATA** (프로세스용 데이터) **세그먼트를 어떻게 로드할지 정의**합니다.
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

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

만약 **섹션 오프셋** (0x37DC)을 **추가**하고 **아키텍처 시작 오프셋**을 더한다면, 이 경우 `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

또한 **커맨드 라인**에서 **헤더 정보**를 얻는 것도 가능합니다:
```bash
otool -lv /bin/ls
```
다음은이 cmd에 의해로드되는 일반 세그먼트입니다:

* **`__PAGEZERO`:** 커널에 **주소 0을 매핑**하도록 지시하여 **읽거나 쓰거나 실행할 수 없습니다**. 구조체의 maxprot 및 minprot 변수는 **이 페이지에 읽기-쓰기-실행 권한이 없음**을 나타내기 위해 0으로 설정됩니다.
* 이 할당은 **NULL 포인터 역참조 취약점을 완화하는 데 중요**합니다.
* **`__TEXT`**: **읽기** 및 **실행** 권한을 가진 **실행 가능한 코드**를 포함합니다(쓰기 권한 없음)**.** 이 세그먼트의 일반 섹션:
* `__text`: 컴파일된 이진 코드
* `__const`: 상수 데이터
* `__cstring`: 문자열 상수
* `__stubs` 및 `__stubs_helper`: 동적 라이브러리 로딩 프로세스 중에 관련됨
* **`__DATA`**: **읽기** 및 **쓰기** 가능한 데이터를 포함합니다(실행 불가능)**.**
* `__data`: 초기화된 전역 변수
* `__bss`: 초기화되지 않은 정적 변수
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist 등): Objective-C 런타임에서 사용되는 정보
* **`__LINKEDIT`**: 링커(dyld)를 위한 정보를 포함하며, "심볼, 문자열 및 재배치 테이블 항목"을 포함합니다.
* **`__OBJC`**: Objective-C 런타임에서 사용되는 정보를 포함합니다. 그러나 이 정보는 때때로 \_\_DATA 세그먼트 내의 다양한 \_\_objc\_\* 섹션에서도 찾을 수 있습니다.

### **`LC_MAIN`**

**entryoff 속성**에 진입점을 포함합니다. 로드 시, **dyld**는 단순히 이 값을 (메모리 내) **바이너리의 베이스에 추가**하고, 그런 다음 이 명령으로 이동하여 바이너리 코드의 실행을 시작합니다.

### **LC\_CODE\_SIGNATURE**

Macho-O 파일의 **코드 서명에 대한 정보**를 포함합니다. 이는 일반적으로 파일의 매우 끝에 있는 **서명 블롭을 가리키는 오프셋**만을 포함합니다.\
그러나 [**이 블로그 게시물**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) 및 이 [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)에서 이 섹션에 대한 일부 정보를 찾을 수 있습니다.

### **LC\_LOAD\_DYLINKER**

프로세스 주소 공간에 공유 라이브러리를 매핑하는 동적 링커 실행 파일의 **경로**를 포함합니다. **값은 항상 `/usr/lib/dyld`**로 설정됩니다. macOS에서 dylib 매핑은 **커널 모드가 아닌 사용자 모드**에서 발생한다는 점을 강조해야 합니다.

### **`LC_LOAD_DYLIB`**

이 로드 명령은 **로더**(dyld)에게 **해당 라이브러리를 로드하고 링크하도록 지시하는** **동적 라이브러리** 종속성을 설명합니다. Mach-O 바이너리가 필요로 하는 각 라이브러리에 대해 LC\_LOAD\_DYLIB 로드 명령이 있습니다.

* 이 로드 명령은 실제 종속 동적 라이브러리를 설명하는 **`dylib` 구조체를 포함하는** **`dylib_command`** 유형의 구조체입니다:
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
![](<../../../.gitbook/assets/image (558).png>)

이 정보를 CLI에서도 얻을 수 있습니다:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
잠재적인 악성 코드 관련 라이브러리 몇 가지는 다음과 같습니다:

- **DiskArbitration**: USB 드라이브 모니터링
- **AVFoundation**: 오디오 및 비디오 캡처
- **CoreWLAN**: Wifi 스캔

{% hint style="info" %}
Mach-O 바이너리에는 **하나 이상의 생성자**가 포함될 수 있으며, 이는 **LC\_MAIN**에서 지정된 주소 **앞에서 실행**됩니다.\
어떤 생성자의 오프셋은 **\_\_DATA\_CONST** 세그먼트의 **\_\_mod\_init\_func** 섹션에 저장됩니다.
{% endhint %}

## **Mach-O 데이터**

파일의 핵심에는 로드 명령 영역에서 정의된 여러 세그먼트로 구성된 데이터 영역이 있습니다. **각 세그먼트 내에는 다양한 데이터 섹션이 포함**될 수 있으며, 각 섹션은 **특정 유형에 대한 코드 또는 데이터**를 보유합니다.

{% hint style="success" %}
데이터는 기본적으로 로드 명령 **LC\_SEGMENTS\_64**에 의해 로드되는 모든 **정보**를 포함하는 부분입니다.
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

이에는 다음이 포함됩니다:

- **함수 테이블**: 프로그램 함수에 대한 정보를 보유
- **심볼 테이블**: 바이너리에서 사용되는 외부 함수에 대한 정보를 포함
- 내부 함수, 변수 이름 등도 포함될 수 있습니다.

확인하려면 [**Mach-O View**](https://sourceforge.net/projects/machoview/) 도구를 사용할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

또는 CLI에서:
```bash
size -m /bin/ls
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로부터 영웅까지 AWS 해킹 배우기</strong></summary>

다른 방법으로 HackTricks를 지원하는 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원한다면** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 트릭을 공유하고 싶다면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
