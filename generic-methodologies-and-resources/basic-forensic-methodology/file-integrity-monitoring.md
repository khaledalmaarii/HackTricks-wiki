{% hint style="success" %}
**AWS 해킹 학습 및 실습:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**GCP 해킹 학습 및 실습:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}


# Baseline

베이스라인은 시스템의 특정 부분의 스냅샷을 찍어 **미래의 상태와 비교하여 변경 사항을 강조하는 것**으로 구성됩니다.

예를 들어, 파일 시스템의 각 파일의 해시를 계산하고 저장하여 수정된 파일을 찾을 수 있습니다.\
이는 생성된 사용자 계정, 실행 중인 프로세스, 실행 중인 서비스 및 변경되지 않아야 할 다른 모든 것들로도 수행할 수 있습니다.

## 파일 무결성 모니터링

파일 무결성 모니터링 (FIM)은 파일의 변경 사항을 추적하여 IT 환경 및 데이터를 보호하는 중요한 보안 기술입니다. 다음 두 가지 주요 단계로 구성됩니다:

1. **베이스라인 비교:** 파일 속성이나 암호화 체크섬 (예: MD5 또는 SHA-2)을 사용하여 베이스라인을 설정하여 변경 사항을 감지하기 위해 미래 비교에 사용합니다.
2. **실시간 변경 알림:** 파일에 액세스되거나 변경될 때 즉시 경고를 받습니다. 일반적으로 OS 커널 확장을 통해 수행됩니다.

## 도구

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## 참고 자료

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


{% hint style="success" %}
**AWS 해킹 학습 및 실습:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**GCP 해킹 학습 및 실습:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}
