# macOS 설치 프로그램 남용

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## Pkg 기본 정보

macOS **설치 프로그램 패키지** (또는 `.pkg` 파일)는 macOS에서 **소프트웨어를 배포**하기 위해 사용되는 파일 형식입니다. 이 파일들은 설치와 실행에 필요한 모든 것을 포함하는 **상자와 같습니다**.

패키지 파일 자체는 대상 컴퓨터에 설치될 파일과 디렉토리의 **계층 구조를 보유하는 아카이브**입니다. 또한 소프트웨어의 구성 파일 설정이나 이전 버전의 소프트웨어 정리와 같은 설치 전후 작업을 수행하는 **스크립트**를 포함할 수도 있습니다.

### 계층 구조

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: 사용자 정의 (제목, 환영 메시지 등) 및 스크립트/설치 확인
* **PackageInfo (xml)**: 정보, 설치 요구 사항, 설치 위치, 실행할 스크립트 경로
* **Bill of materials (bom)**: 파일 목록, 파일 권한과 함께 설치, 업데이트 또는 제거
* **Payload (CPIO 아카이브 gzip 압축)**: PackageInfo의 `install-location`에 설치할 파일
* **Scripts (CPIO 아카이브 gzip 압축)**: 설치 전후 스크립트 및 실행을 위해 임시 디렉토리로 추출된 추가 리소스. 

### 압축 해제
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## DMG 기본 정보

DMG 파일 또는 Apple 디스크 이미지는 Apple의 macOS에서 디스크 이미지로 사용되는 파일 형식입니다. DMG 파일은 기본적으로 **마운트 가능한 디스크 이미지**입니다(자체 파일 시스템을 포함). 이 파일은 일반적으로 압축되고 때로는 암호화된 원시 블록 데이터를 포함합니다. DMG 파일을 열면 macOS가 이를 물리적인 디스크처럼 마운트하여 내용에 액세스할 수 있게 합니다.

### 계층 구조

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

DMG 파일의 계층 구조는 내용에 따라 다를 수 있습니다. 그러나 애플리케이션 DMG의 경우 일반적으로 다음 구조를 따릅니다:

* 최상위 수준: 이것은 디스크 이미지의 루트입니다. 일반적으로 애플리케이션과 Applications 폴더로의 링크를 포함합니다.
* 애플리케이션 (.app): 이것은 실제 애플리케이션입니다. macOS에서 애플리케이션은 일반적으로 애플리케이션을 구성하는 많은 개별 파일과 폴더를 포함하는 패키지입니다.
* Applications 링크: 이것은 macOS의 Applications 폴더로의 바로 가기입니다. 이것의 목적은 애플리케이션을 설치하기 쉽게 만드는 것입니다. .app 파일을 이 바로 가기로 끌어다 놓으면 앱을 설치할 수 있습니다.

## pkg 남용을 통한 권한 상승

### 공개 디렉토리에서 실행

만약 사전 또는 사후 설치 스크립트가 **`/var/tmp/Installerutil`**에서 실행된다면, 공격자는 그 스크립트를 제어할 수 있으므로 실행될 때마다 권한을 상승시킬 수 있습니다. 또 다른 유사한 예제:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

이것은 [공개 함수](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)로, 여러 설치 프로그램과 업데이터가 **루트로 실행**할 때 호출하는 함수입니다. 이 함수는 **실행할 파일**의 **경로**를 매개변수로 받습니다. 그러나 공격자가 이 파일을 **수정**할 수 있다면, 권한 상승을 위해 루트로 실행되는 파일을 **남용**할 수 있습니다.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
더 많은 정보는 이 발표를 확인하세요: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### 마운트를 통한 실행

만약 설치 프로그램이 `/tmp/fixedname/bla/bla`에 쓴다면, `/tmp/fixedname`에 소유자가 없는 **마운트를 생성**하여 설치 과정 중에 **어떤 파일이든 수정**할 수 있어 설치 과정을 악용할 수 있습니다.

이에 대한 예로는 **CVE-2021-26089**가 있으며, 이는 주기적인 스크립트를 덮어쓰고 root로 실행되는 것을 성공했습니다. 자세한 정보는 다음 발표를 참조하세요: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## 악성코드로서의 pkg

### 빈 페이로드

페이로드 없이 **사전 및 사후 설치 스크립트**만 있는 **`.pkg`** 파일을 생성할 수 있습니다.

### Distribution xml에 JS 추가

패키지의 **distribution xml** 파일에 **`<script>`** 태그를 추가하면 해당 코드가 실행되며 **`system.run`**을 사용하여 명령을 실행할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## 참고 자료

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사를 광고**하거나 **PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
