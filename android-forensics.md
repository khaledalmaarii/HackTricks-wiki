# 안드로이드 포렌식

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}

## 잠긴 장치

안드로이드 장치에서 데이터를 추출하려면 장치가 잠겨 있으면:

* USB를 통한 디버깅이 활성화되어 있는지 확인하세요.
* 가능한 [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)을 확인하세요.
* [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)를 시도하세요.

## 데이터 획득

[adb를 사용하여 안드로이드 백업을 생성](mobile-pentesting/android-app-pentesting/adb-commands.md#backup)하고 [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)를 사용하여 추출하세요: `java -jar abe.jar unpack file.backup file.tar`

### 루트 액세스 또는 JTAG 인터페이스에 물리적 연결이 있는 경우

* `cat /proc/partitions` (플래시 메모리의 경로를 찾으세요. 일반적으로 첫 번째 항목은 _mmcblk0_이며 전체 플래시 메모리에 해당합니다).
* `df /data` (시스템의 블록 크기를 확인하세요).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (블록 크기에서 얻은 정보로 실행하세요).

### 메모리

Linux Memory Extractor (LiME)를 사용하여 RAM 정보를 추출하세요. 이는 adb를 통해 로드해야 하는 커널 확장입니다.

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}
