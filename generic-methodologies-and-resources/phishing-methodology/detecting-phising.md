# 피싱 탐지

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

## 소개

피싱 시도를 탐지하기 위해서는 **현재 사용되고 있는 피싱 기술을 이해하는 것이 중요합니다**. 이 게시물의 부모 페이지에서 이 정보를 찾을 수 있으니, 오늘날 어떤 기술이 사용되고 있는지 모른다면 부모 페이지로 가서 최소한 그 섹션을 읽어보는 것을 추천합니다.

이 게시물은 **공격자가 피해자의 도메인 이름을 어떤 식으로든 모방하거나 사용할 것이라는 아이디어를 기반으로 합니다**. 만약 귀하의 도메인이 `example.com`이고, 어떤 이유로 `youwonthelottery.com`과 같은 완전히 다른 도메인 이름으로 피싱을 당한다면, 이러한 기술로는 이를 밝혀낼 수 없습니다.

## 도메인 이름 변형

이메일 내에서 **유사한 도메인** 이름을 사용하는 **피싱** 시도를 **밝혀내는 것은 꽤 쉽습니다**.\
공격자가 사용할 수 있는 가장 가능성이 높은 피싱 이름 목록을 **생성하고** 그것이 **등록되었는지** 또는 **IP**가 사용되고 있는지 확인하는 것으로 충분합니다.

### 의심스러운 도메인 찾기

이 목적을 위해 다음 도구 중 하나를 사용할 수 있습니다. 이 도구들은 도메인에 IP가 할당되어 있는지 확인하기 위해 DNS 요청을 자동으로 수행합니다:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### 비트플리핑

**이 기술에 대한 간단한 설명은 부모 페이지에서 찾을 수 있습니다. 또는 원본 연구를 읽어보세요** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

예를 들어, 도메인 microsoft.com의 1비트 수정은 _windnws.com_으로 변환할 수 있습니다.\
**공격자는 피해자와 관련된 비트플리핑 도메인을 가능한 한 많이 등록하여 합법적인 사용자를 자신의 인프라로 리디렉션할 수 있습니다**.

**모든 가능한 비트플리핑 도메인 이름도 모니터링해야 합니다.**

### 기본 검사

잠재적인 의심스러운 도메인 이름 목록이 생기면 **확인해야 합니다** (주로 HTTP 및 HTTPS 포트) **피해자의 도메인과 유사한 로그인 양식을 사용하고 있는지 확인하기 위해**.\
포트 3333이 열려 있고 `gophish` 인스턴스가 실행 중인지 확인할 수도 있습니다.\
각 발견된 의심스러운 도메인이 **얼마나 오래되었는지** 아는 것도 흥미롭습니다. 젊을수록 위험합니다.\
의심스러운 웹 페이지의 **스크린샷**을 얻어 의심스러운지 확인하고, 그런 경우 **접속하여 더 깊이 살펴보세요**.

### 고급 검사

한 걸음 더 나아가고 싶다면 **의심스러운 도메인을 모니터링하고 가끔 더 검색하는 것을 추천합니다** (매일? 몇 초/분밖에 걸리지 않습니다). 관련 IP의 열린 **포트**를 **확인하고 `gophish` 또는 유사한 도구의 인스턴스를 검색하세요** (네, 공격자도 실수를 합니다) 그리고 **의심스러운 도메인 및 하위 도메인의 HTTP 및 HTTPS 웹 페이지를 모니터링하여 피해자의 웹 페이지에서 로그인 양식을 복사했는지 확인하세요**.\
이를 **자동화하기 위해** 피해자 도메인의 로그인 양식 목록을 가지고, 의심스러운 웹 페이지를 스파이더링하고, 의심스러운 도메인 내에서 발견된 각 로그인 양식을 피해자 도메인의 각 로그인 양식과 비교하는 것을 추천합니다. `ssdeep`과 같은 도구를 사용할 수 있습니다.\
의심스러운 도메인의 로그인 양식을 찾았다면 **쓰레기 자격 증명을 보내고** **피해자의 도메인으로 리디렉션되는지 확인하세요**.

## 키워드를 사용하는 도메인 이름

부모 페이지는 **피해자의 도메인 이름을 더 큰 도메인 안에 넣는** 도메인 이름 변형 기술도 언급합니다 (예: paypal-financial.com은 paypal.com을 위한 것입니다).

### 인증서 투명성

이전의 "무차별 대입" 접근 방식을 취할 수는 없지만, 인증서 투명성 덕분에 **이러한 피싱 시도를 밝혀내는 것이 가능합니다**. CA에 의해 인증서가 발급될 때마다 세부 사항이 공개됩니다. 이는 인증서 투명성을 읽거나 모니터링함으로써 **이름에 키워드를 사용하는 도메인을 찾는 것이 가능하다는 것을 의미합니다**. 예를 들어, 공격자가 [https://paypal-financial.com](https://paypal-financial.com)의 인증서를 생성하면, 인증서를 보고 "paypal"이라는 키워드를 찾아 의심스러운 이메일이 사용되고 있음을 알 수 있습니다.

게시물 [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)은 특정 키워드에 영향을 미치는 인증서를 검색하고 날짜(오직 "새로운" 인증서) 및 CA 발급자로 "Let's Encrypt"로 필터링하기 위해 Censys를 사용할 수 있다고 제안합니다:

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1115).png>)

그러나 무료 웹 [**crt.sh**](https://crt.sh)를 사용하여 "같은" 작업을 수행할 수 있습니다. **키워드를 검색하고** 원하시면 **날짜 및 CA로 결과를 필터링**할 수 있습니다.

![](<../../.gitbook/assets/image (519).png>)

이 마지막 옵션을 사용하면 실제 도메인에서 어떤 신원이 의심스러운 도메인과 일치하는지 확인하기 위해 Matching Identities 필드를 사용할 수 있습니다 (의심스러운 도메인이 잘못된 긍정일 수 있다는 점에 유의하세요).

**또 다른 대안**은 [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)이라는 환상적인 프로젝트입니다. CertStream은 새로 생성된 인증서의 실시간 스트림을 제공하며, 이를 사용하여 (근사) 실시간으로 지정된 키워드를 탐지할 수 있습니다. 실제로 [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher)라는 프로젝트가 바로 그것을 수행합니다.

### **새로운 도메인**

**마지막 대안**은 일부 TLD에 대해 **새로 등록된 도메인 목록을 수집하고** 이러한 도메인에서 **키워드를 확인하는 것입니다**. 그러나 긴 도메인은 일반적으로 하나 이상의 하위 도메인을 사용하므로 키워드가 FLD에 나타나지 않으며 피싱 하위 도메인을 찾을 수 없습니다.

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
