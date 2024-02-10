# macOS AppleFS

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>로부터 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 PR을 제출**하세요.

</details>

## Apple Propietary File System (APFS)

**Apple File System (APFS)**는 계층적 파일 시스템 플러스(HFS+)를 대체하기 위해 설계된 현대적인 파일 시스템입니다. 이는 **향상된 성능, 보안 및 효율성**의 필요성에 의해 개발되었습니다.

APFS의 주요 기능은 다음과 같습니다:

1. **공간 공유**: APFS는 여러 볼륨이 단일 물리적 장치에서 **동일한 기본 무료 저장소를 공유**할 수 있도록 합니다. 이를 통해 볼륨은 수동 크기 조정이나 재분할 없이 동적으로 확장 및 축소될 수 있어 더 효율적인 공간 활용이 가능합니다.
1. 이는 파일 디스크의 전통적인 파티션과 비교하여 **APFS에서는 다른 파티션(볼륨)이 디스크 공간을 모두 공유**한다는 것을 의미합니다. 반면 일반적인 파티션은 일정한 크기를 가지고 있습니다.
2. **스냅샷**: APFS는 파일 시스템의 **읽기 전용**인 **스냅샷 생성**을 지원합니다. 스냅샷은 추가 저장 공간을 최소한으로 사용하며 빠르게 생성하거나 되돌릴 수 있어 효율적인 백업과 시스템 롤백이 가능합니다.
3. **클론**: APFS는 원본과 동일한 저장 공간을 공유하는 **파일 또는 디렉토리 클론을 생성**할 수 있습니다. 이 기능은 저장 공간을 중복하지 않고 파일 또는 디렉토리의 복사본을 효율적으로 생성하는 방법을 제공합니다.
4. **암호화**: APFS는 전체 디스크 암호화뿐만 아니라 파일별 및 디렉토리별 암호화를 **기본적으로 지원**하여 다양한 사용 사례에서 데이터 보안을 강화합니다.
5. **충돌 보호**: APFS는 파일 시스템 일관성을 보장하기 위해 **복사 후 쓰기 메타데이터 체계**를 사용하여 갑작스러운 전원 손실이나 시스템 충돌의 경우에도 데이터 손상 위험을 줄입니다.

전반적으로 APFS는 Apple 기기에 대해 더 현대적이고 유연하며 효율적인 파일 시스템을 제공하며 성능, 신뢰성 및 보안에 중점을 둡니다.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` 볼륨은 **`/System/Volumes/Data`**에 마운트됩니다 (`diskutil apfs list`로 확인할 수 있습니다).

firmlinks 목록은 **`/usr/share/firmlinks`** 파일에서 찾을 수 있습니다.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
**왼쪽**에는 **시스템 볼륨**의 디렉토리 경로가 있고, **오른쪽**에는 **데이터 볼륨**에 매핑된 디렉토리 경로가 있습니다. 따라서, `/library`는 `/system/Volumes/data/library`로 매핑됩니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
