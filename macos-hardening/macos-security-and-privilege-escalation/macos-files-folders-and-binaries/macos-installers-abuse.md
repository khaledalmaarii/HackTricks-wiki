# macOS 설치 프로그램 남용

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅이 되는 AWS 해킹을 배우세요**!</summary>

HackTricks를 지원하는 다른 방법:

- **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>

## Pkg 기본 정보

macOS **설치 프로그램 패키지**(.pkg 파일로도 알려짐)는 macOS에서 **소프트웨어를 배포**하는 데 사용되는 파일 형식입니다. 이러한 파일은 **소프트웨어가 설치되고 올바르게 실행되기 위해 필요한 모든 것을 포함하는 상자와 같습니다**.

패키지 파일 자체는 **대상 컴퓨터에 설치될 파일 및 디렉토리 계층 구조를 보유하는 아카이브**입니다. 또한 **설정 파일 설정 또는 이전 버전의 소프트웨어를 정리하는 작업과 같은 작업을 수행하는 스크립트**를 포함할 수 있습니다.

### 계층 구조

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: 사용자 정의 (제목, 환영 텍스트 등) 및 스크립트/설치 확인
- **PackageInfo (xml)**: 정보, 설치 요구 사항, 설치 위치, 실행할 스크립트 경로
- **Bill of materials (bom)**: 파일 목록 및 파일 권한으로 설치, 업데이트 또는 제거
- **Payload (CPIO 아카이브 gzip 압축)**: PackageInfo의 `install-location`에 설치할 파일
- **Scripts (CPIO 아카이브 gzip 압축)**: 임시 디렉토리로 추출된 사전 및 사후 설치 스크립트 및 기타 리소스.
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

DMG 파일 또는 Apple 디스크 이미지는 Apple의 macOS에서 사용되는 파일 형식입니다. DMG 파일은 기본적으로 **마운트 가능한 디스크 이미지**이며(자체 파일 시스템을 포함), 일반적으로 압축되고 때로는 암호화된 원시 블록 데이터를 포함합니다. DMG 파일을 열면 macOS가 **물리적 디스크처럼 마운트**하여 해당 내용에 액세스할 수 있게 됩니다.

### 계층 구조

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

DMG 파일의 계층 구조는 내용에 따라 다를 수 있습니다. 그러나 응용 프로그램 DMG의 경우 일반적으로 다음 구조를 따릅니다:

- 최상위: 이것은 디스크 이미지의 루트입니다. 일반적으로 응용 프로그램과 macOS의 Applications 폴더로의 링크를 포함합니다.
- 응용 프로그램 (.app): 이것은 실제 응용 프로그램입니다. macOS에서 응용 프로그램은 일반적으로 응용 프로그램을 구성하는 많은 개별 파일과 폴더를 포함하는 패키지입니다.
- 응용 프로그램 링크: 이것은 macOS의 Applications 폴더로의 바로 가기입니다. 이것의 목적은 응용 프로그램을 설치하기 쉽게 만드는 것입니다. .app 파일을 이 바로 가기로 끌어다 놓아 응용 프로그램을 설치할 수 있습니다.

## pkg 남용을 통한 권한 상승

### 공용 디렉토리에서 실행

예를 들어, 사전 또는 사후 설치 스크립트가 **`/var/tmp/Installerutil`**에서 실행되고 있으면, 공격자는 해당 스크립트를 제어하여 실행될 때마다 권한을 상승시킬 수 있습니다. 또 다른 유사한 예는 다음과 같습니다:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

이것은 **루트로 무언가를 실행**하기 위해 여러 설치 프로그램과 업데이터가 호출하는 [공개 함수](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)입니다. 이 함수는 **실행할 파일의 경로**를 매개변수로 받지만, 공격자가 이 파일을 **수정**할 수 있다면, 권한을 **상승**하여 루트로 실행을 **남용**할 수 있습니다.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### 마운트를 통한 실행

만약 설치 프로그램이 `/tmp/fixedname/bla/bla`에 쓴다면, **noowners**로 `/tmp/fixedname` 위에 **마운트를 생성**할 수 있어 설치 중 **어떤 파일이든 수정**하여 설치 과정을 악용할 수 있습니다.

이러한 예시로는 **CVE-2021-26089**가 있으며, 이는 **주기적 스크립트를 덮어쓰고** 루트로 실행하는 것을 성공했습니다. 자세한 정보는 다음 발표를 참고하세요: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## 악성코드로서의 pkg

### 빈 페이로드

**`.pkg`** 파일에 **설치 전 및 후 스크립트**만 포함하여 생성할 수 있습니다.

### Distribution xml에 JS

패키지의 **distribution xml** 파일에 **`<script>`** 태그를 추가하여 해당 코드가 실행되고 **`system.run`**을 사용하여 명령을 **실행**할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## 참고 자료

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
