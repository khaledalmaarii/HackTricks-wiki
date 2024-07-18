# 안드로이드 포렌식

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}

## 잠긴 장치

안드로이드 장치에서 데이터를 추출하려면 장치가 잠금 해제되어야 합니다. 잠겨 있다면 다음을 시도할 수 있습니다:

* USB를 통한 디버깅이 활성화되어 있는지 확인합니다.
* 가능한 [스머지 공격](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)을 확인합니다.
* [브루트 포스](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)로 시도해 봅니다.

## 데이터 수집

[adb를 사용하여 안드로이드 백업 생성하기](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) 및 [안드로이드 백업 추출기](https://sourceforge.net/projects/adbextractor/)를 사용하여 추출합니다: `java -jar abe.jar unpack file.backup file.tar`

### 루트 접근 또는 JTAG 인터페이스에 물리적 연결이 있는 경우

* `cat /proc/partitions` (플래시 메모리의 경로를 검색합니다. 일반적으로 첫 번째 항목은 _mmcblk0_이며 전체 플래시 메모리에 해당합니다).
* `df /data` (시스템의 블록 크기를 확인합니다).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (블록 크기에서 수집한 정보를 사용하여 실행합니다).

### 메모리

Linux 메모리 추출기(LiME)를 사용하여 RAM 정보를 추출합니다. 이는 adb를 통해 로드해야 하는 커널 확장입니다.

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
