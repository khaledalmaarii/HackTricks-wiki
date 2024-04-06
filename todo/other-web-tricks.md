# 기타 웹 트릭

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

### 호스트 헤더

백엔드에서는 종종 **호스트 헤더**를 신뢰하여 일부 작업을 수행합니다. 예를 들어, **비밀번호 재설정을 보내기 위한 도메인으로 그 값을 사용**할 수 있습니다. 따라서 비밀번호 재설정 링크가 포함된 이메일을 받을 때 사용되는 도메인은 호스트 헤더에 입력한 도메인입니다. 그럼으로써, 다른 사용자의 비밀번호 재설정을 요청하고 도메인을 자신이 제어하는 도메인으로 변경하여 비밀번호 재설정 코드를 도용할 수 있습니다. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
사용자가 재설정 비밀번호 링크를 클릭하기를 기다릴 필요 없이, **스팸 필터나 다른 중간 장치/봇이 분석하기 위해 클릭**할 수도 있다는 점에 유의하세요.
{% endhint %}

### 세션 부울 값

일부 경우에는 백엔드에서 일부 확인을 올바르게 완료하면 세션에 **"True" 값으로 부울을 추가**할 수 있습니다. 그런 다음, 다른 엔드포인트는 그 확인을 성공적으로 통과했는지 알 수 있습니다.\
그러나, 확인을 통과하고 세션에 보안 속성에 "True" 값을 부여받은 경우, **접근 권한이 없는** 동일한 속성에 **의존하는 다른 리소스에 액세스**를 시도할 수 있습니다. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### 등록 기능

이미 존재하는 사용자로 등록해 보세요. 또한 등가 문자(점, 공백 및 유니코드)를 사용해 보세요.

### 이메일 탈취

이메일을 등록한 후 확인하기 전에 이메일을 변경한 다음, 새로운 확인 이메일이 처음 등록한 이메일로 전송되면 어떤 이메일이든 탈취할 수 있습니다. 또는 두 번째 이메일을 활성화하여 첫 번째 이메일을 확인할 수 있다면 어떤 계정이든 탈취할 수도 있습니다.

### Atlassian을 사용하여 기업의 내부 서비스 데스크에 액세스

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE 메서드

개발자들은 종종 프로덕션 환경에서 다양한 디버깅 옵션을 비활성화하는 것을 잊을 수 있습니다. 예를 들어, HTTP `TRACE` 메서드는 진단 목적으로 설계되었습니다. 활성화되면 웹 서버는 `TRACE` 메서드를 사용하는 요청에 대해 정확한 요청을 응답으로 되돌려줍니다. 이 동작은 종종 무해하지만, 때로는 내부 인증 헤더의 이름과 같은 정보 노출로 이어질 수 있습니다. 이러한 헤더는 리버스 프록시에 의해 요청에 추가될 수 있습니다.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
