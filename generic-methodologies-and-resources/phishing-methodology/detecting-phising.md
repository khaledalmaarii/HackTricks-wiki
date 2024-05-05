# 피싱 탐지

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 AWS 해킹을 제로부터 전문가까지 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 제출하세요.

</details>

## 소개

피싱 시도를 탐지하려면 **현재 사용되는 피싱 기술을 이해하는 것이 중요**합니다. 이 게시물의 상위 페이지에서 이 정보를 찾을 수 있으므로 오늘날 사용되는 기술을 알지 못한다면 상위 페이지로 이동하여 적어도 해당 섹션을 읽는 것을 권장합니다.

이 게시물은 **공격자가 피해자의 도메인 이름을 모방하거나 사용하려고 시도할 것**이라는 아이디어를 기반으로 합니다. 예를 들어, 당신의 도메인이 `example.com`이고 `youwonthelottery.com`과 같이 완전히 다른 도메인을 사용하여 피싱당하는 경우 이러한 기술은 그것을 발견하지 못할 것입니다.

## 도메인 이름 변형

이메일 내에서 **유사한 도메인** 이름을 사용할 **피싱** 시도를 **발견**하는 것은 **쉽습니다**.\
공격자가 사용할 수 있는 가장 가능성 있는 피싱 이름 목록을 **생성**하고 해당 도메인이 **등록**되었는지 확인하거나 해당 도메인을 사용하는 **IP**가 있는지 확인하면 됩니다.

### 수상한 도메인 찾기

이를 위해 다음 도구 중 하나를 사용할 수 있습니다. 이 도구들은 도메인이 할당된 IP가 있는지 자동으로 DNS 요청도 수행합니다:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### 비트 플리핑

**이 기술에 대한 간단한 설명은 상위 페이지에서 찾을 수 있습니다. 또는 원본 연구를** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)에서 읽을 수 있습니다.

예를 들어, 도메인 microsoft.com의 1 비트 수정은 _windnws.com._로 변환될 수 있습니다.\
**공격자는 피해자와 관련된 가능한 많은 비트 플리핑 도메인을 등록하여 합법적인 사용자를 자신들의 인프라로 리디렉션할 수 있습니다**.

**모든 가능한 비트 플리핑 도메인 이름도 모니터링해야 합니다.**

### 기본 확인

잠재적으로 수상한 도메인 이름 목록이 있으면 해당 도메인을 (주로 HTTP 및 HTTPS 포트) **확인**하여 **피해자의 도메인과 유사한 로그인 양식을 사용하는지 확인**해야 합니다.\
포트 3333도 열려 있는지 확인하고 `gophish` 인스턴스가 실행 중인지 확인할 수도 있습니다.\
발견된 의심스러운 도메인의 **연령**을 알아두는 것도 흥미로울 것입니다. 더 어릴수록 위험합니다.\
의심스러운 HTTP 및/또는 HTTPS 웹 페이지의 **스크린샷**을 찍어 의심스러운지 확인하고 그렇다면 **더 깊이 살펴보기 위해 액세스**해야 합니다.

### 고급 확인

더 나아가려면 **의심스러운 도메인을 모니터링하고 주기적으로 더 찾아보는 것**을 권장합니다(매일? 몇 초/분이면 충분합니다). 관련 IP의 열린 **포트를 확인**하고 `gophish` 또는 유사한 도구의 인스턴스를 **찾아보세요**(네, 공격자도 실수를 합니다) 그리고 의심스러운 도메인 및 하위 도메인의 HTTP 및 HTTPS 웹 페이지를 **모니터링**하여 피해자의 웹 페이지에서 로그인 양식을 복사한 것이 있는지 확인하세요.\
이를 **자동화**하려면 피해자의 도메인의 로그인 양식 목록을 갖고 의심스러운 웹 페이지를 스파이더링하고 `ssdeep`와 같은 것을 사용하여 의심스러운 도메인의 각 로그인 양식을 피해자의 도메인의 각 로그인 양식과 비교하세요.\
의심스러운 도메인의 로그인 양식을 찾았다면 **잘못된 자격 증명을 보내고 피해자의 도메인으로 리디렉션되는지 확인**해볼 수 있습니다.

## 키워드를 사용하는 도메인 이름

상위 페이지에서 언급된 도메인 이름 변형 기술은 **피해자의 도메인 이름을 더 큰 도메인 안에 넣는 것**으로 구성됩니다 (예: paypal.com의 경우 paypal-financial.com).

### 인증 투명성

이전의 "무차별 대입" 접근 방식을 취할 수는 없지만 인증 투명성 덕분에 실제로 **키워드를 사용하는 도메인을 발견**할 수 있습니다. CA가 인증서를 발급할 때마다 세부 정보가 공개됩니다. 따라서 인증 투명성을 읽거나 모니터링하여 **이름 내에 키워드를 사용하는 도메인을 찾을 수 있습니다**. 예를 들어, 공격자가 [https://paypal-financial.com](https://paypal-financial.com)의 인증서를 생성하면 인증서를 보고 "paypal" 키워드를 찾아 의심스러운 이메일이 사용 중임을 알 수 있습니다.

게시물 [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)은 Censys를 사용하여 특정 키워드를 검색하고 날짜(오직 "새로운" 인증서만) 및 CA 발급자 "Let's Encrypt"로 필터링할 수 있다고 제안합니다:

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1115).png>)

그러나 무료 웹 [**crt.sh**](https://crt.sh)를 사용하여 "동일한" 작업을 수행할 수 있습니다. 원하는 경우 키워드를 **검색**하고 결과를 **날짜 및 CA로 필터링**할 수 있습니다.

![](<../../.gitbook/assets/image (519).png>)

마지막 옵션을 사용하면 실제 도메인의 일치하는 ID를 사용하여 의심스러운 도메인 중 어떤 ID가 일치하는지 확인할 수 있습니다(의심스러운 도메인이 잘못된 양성일 수 있음에 유의하세요).

**또 다른 대안**은 [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)이라는 훌륭한 프로젝트입니다. CertStream은 실시간으로 생성된 인증서 스트림을 제공하며 이를 사용하여 (거의) 실시간으로 지정된 키워드를 감지할 수 있습니다. 사실, [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher)라는 프로젝트가 이를 수행합니다.
### **새로운 도메인**

**마지막 대안**은 일부 TLD에 대해 **새롭게 등록된 도메인 목록을 수집**하고 ([Whoxy](https://www.whoxy.com/newly-registered-domains/)가 이러한 서비스를 제공) **이러한 도메인에서 키워드를 확인하는 것**입니다. 그러나 긴 도메인은 일반적으로 하나 이상의 하위 도메인을 사용하므로 키워드는 FLD 내부에 나타나지 않을 것이며 피싱 하위 도메인을 찾을 수 없을 것입니다.
