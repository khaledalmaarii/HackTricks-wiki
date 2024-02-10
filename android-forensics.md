# 안드로이드 포렌식

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>

## 잠긴 장치

안드로이드 장치에서 데이터를 추출하기 위해서는 잠긴 상태에서 해제해야 합니다. 잠긴 상태인 경우 다음을 시도할 수 있습니다:

* 장치가 USB 디버깅이 활성화되어 있는지 확인합니다.
* 가능한 [smudge 공격](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)을 확인합니다.
* [무차별 대입 공격](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)을 시도합니다.

## 데이터 획득

[adb를 사용하여 안드로이드 백업을 생성](mobile-pentesting/android-app-pentesting/adb-commands.md#backup)하고 [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)를 사용하여 추출합니다: `java -jar abe.jar unpack file.backup file.tar`

### 루트 액세스 또는 JTAG 인터페이스에 대한 물리적 연결이 있는 경우

* `cat /proc/partitions` (플래시 메모리의 경로를 검색합니다. 일반적으로 첫 번째 항목은 _mmcblk0_이며 전체 플래시 메모리에 해당합니다).
* `df /data` (시스템의 블록 크기를 확인합니다).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (블록 크기에서 얻은 정보로 실행합니다).

### 메모리

Linux Memory Extractor (LiME)를 사용하여 RAM 정보를 추출합니다. 이는 adb를 통해 로드되어야 하는 커널 확장입니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
