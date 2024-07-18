# 기타 웹 트릭

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리로 **해킹 트릭을 공유**하세요.

</details>
{% endhint %}

### 호스트 헤더

백엔드가 **일부 작업을 수행하기 위해** **호스트 헤더**를 신뢰하는 경우가 있습니다. 예를 들어, 이 값은 **비밀번호 재설정 링크를 보내기 위한 도메인으로 사용**될 수 있습니다. 따라서 비밀번호 재설정 링크가 포함된 이메일을 받으면 사용되는 도메인은 호스트 헤더에 입력한 도메인입니다. 그런 다음, 다른 사용자의 비밀번호 재설정을 요청하고 도메인을 자신이 제어하는 도메인으로 변경하여 그들의 비밀번호 재설정 코드를 훔칠 수 있습니다. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
사용자가 비밀번호 재설정 링크를 클릭하기를 기다릴 필요가 없을 수도 있으므로 **스팸 필터 또는 기타 중개 장치/봇이 분석하기 위해 클릭**할 수도 있습니다.
{% endhint %}

### 세션 부울

가끔 백엔드가 일부 확인을 완료하면 **세션에 "True" 값의 부울을 추가**할 수 있습니다. 그런 다음 다른 엔드포인트는 해당 확인을 성공적으로 통과했는지 알 수 있습니다.\
그러나 **확인을 통과**하고 세션이 해당 보안 속성에 "True" 값을 부여받으면 **해당 속성에 의존하는 다른 리소스에 액세스**를 시도할 수 있지만 **액세스 권한이 없는** 경우도 있습니다. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### 등록 기능

이미 존재하는 사용자로 등록해 보세요. 또한 등가 문자(점, 많은 공백 및 유니코드)를 사용해 보세요.

### 이메일 탈취

이메일을 등록한 후 확인하기 전에 이메일을 변경한 다음, 새 확인 이메일이 처음 등록한 이메일로 전송되면 어떤 이메일이든 탈취할 수 있습니다. 또는 두 번째 이메일을 활성화하여 첫 번째 이메일을 확인할 수 있다면 어떤 계정이든 탈취할 수 있습니다.

### Atlassian을 사용하는 기업의 내부 서비스데스크 액세스

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE 메소드

개발자들은 프로덕션 환경에서 다양한 디버깅 옵션을 비활성화하는 것을 잊을 수 있습니다. 예를 들어, HTTP `TRACE` 메소드는 진단 목적으로 설계되었습니다. 활성화된 경우, 웹 서버는 `TRACE` 메소드를 사용하는 요청에 대해 정확히 받은 요청을 응답으로 다시 에코합니다. 이 동작은 종종 무해하지만 때로는 역방향 프록시에 의해 요청에 추가될 수 있는 내부 인증 헤더의 이름과 같은 정보 노출로 이어질 수 있습니다.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리로 **해킹 트릭을 공유**하세요.

</details>
{% endhint %}
