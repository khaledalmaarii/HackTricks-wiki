<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>


# 기준선

기준선은 시스템의 특정 부분의 스냅샷을 찍어 **변경 사항을 강조하기 위해 미래 상태와 비교**하는 것으로 구성됩니다.

예를 들어, 파일 시스템의 각 파일의 해시를 계산하고 저장하여 수정된 파일을 찾을 수 있습니다.\
이는 생성된 사용자 계정, 실행 중인 프로세스, 실행 중인 서비스 및 변경되지 않아야 할 다른 모든 것에 대해서도 수행할 수 있습니다.

## 파일 무결성 모니터링

파일 무결성 모니터링(FIM)은 파일의 변경 사항을 추적하여 IT 환경과 데이터를 보호하는 중요한 보안 기술입니다. 다음과 같은 두 가지 주요 단계로 이루어집니다:

1. **기준선 비교:** 파일 속성이나 암호화 체크섬(MD5 또는 SHA-2와 같은)을 사용하여 기준선을 설정하여 변경 사항을 감지합니다.
2. **실시간 변경 알림:** 일반적으로 OS 커널 확장을 통해 파일에 액세스하거나 변경될 때 즉시 알림을 받습니다.

## 도구

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## 참고 자료

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
