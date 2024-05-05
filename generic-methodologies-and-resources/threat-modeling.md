# 위협 모델링

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**당했는지 확인하는 **무료** 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난하는 악성 소프트웨어로 인한 계정 탈취와 랜섬웨어 공격에 대항하는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료**로 사용해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

***

## 위협 모델링

사이버 보안의 중요한 측면인 위협 모델링에 대한 HackTricks의 포괄적인 가이드에 오신 것을 환영합니다! 시스템의 잠재적 취약점을 식별, 이해 및 대비하는 과정에서 우리는 이 분야의 중요성을 탐구합니다. 이 가이드는 현실적인 예제, 유용한 소프트웨어 및 쉽게 이해할 수 있는 설명으로 가득한 단계별 가이드 역할을 합니다. 보안 방어를 강화하려는 초보자와 경험 있는 실무자 모두에게 이상적입니다.

### 일반적으로 사용되는 시나리오

1. **소프트웨어 개발**: 안전한 소프트웨어 개발 수명주기(SSDLC)의 일환으로, 위협 모델링은 개발 초기 단계에서의 **잠재적 취약점 원천 식별**에 도움이 됩니다.
2. **펜트esting**: 펜트esting 실행 표준(PTES) 프레임워크는 **시스템의 취약점을 이해하기 위한 위협 모델링**을 요구합니다.

### 요약된 위협 모델

위협 모델은 일반적으로 응용 프로그램의 계획된 아키텍처 또는 기존 빌드를 나타내는 다이어그램, 이미지 또는 다른 시각적 표현으로 나타냅니다. 이는 **데이터 흐름 다이어그램**과 유사하지만, 보안 중심적인 설계에서 차이가 있습니다.

위협 모델에는 종종 잠재적 취약점, 위험 또는 장벽을 상징하는 빨간색으로 표시된 요소가 포함됩니다. 위험 식별 프로세스를 간소화하기 위해 CIA(기밀성, 무결성, 가용성) 삼각형이 사용되며, STRIDE가 가장 일반적인 방법 중 하나입니다. 그러나 선택한 방법론은 구체적인 맥락과 요구 사항에 따라 다를 수 있습니다.

### CIA 삼각형

CIA 삼각형은 정보 보안 분야에서 널리 인정받는 모델로, 기밀성, 무결성 및 가용성을 나타냅니다. 이 세 가지 요소는 많은 보안 조치 및 정책이 구축되는 기초를 형성하며, 위협 모델링 방법론을 포함합니다.

1. **기밀성**: 데이터나 시스템이 무단으로 액세스되지 않도록 보장합니다. 이는 적절한 액세스 제어, 암호화 및 기타 조치를 필요로 하며, 데이터 유출을 방지하기 위한 조치가 필요합니다.
2. **무결성**: 데이터의 정확성, 일관성 및 신뢰성을 보장합니다. 이 원칙은 데이터가 무단으로 변경되거나 조작되지 않도록 보장합니다. 이는 체크섬, 해싱 및 기타 데이터 확인 방법을 포함합니다.
3. **가용성**: 데이터와 서비스가 필요할 때 허가된 사용자에게 접근 가능하도록 보장합니다. 시스템이 중단되더라도 시스템이 계속 작동할 수 있도록 중복, 장애 허용 및 고가용성 구성이 필요합니다.

### 위협 모델링 방법론

1. **STRIDE**: Microsoft에서 개발된 STRIDE는 **위조, 변조, 부인, 정보 노출, 서비스 거부 및 권한 상승**을 나타내는 약어입니다. 각 범주는 위협 유형을 나타내며, 이 방법론은 잠재적 위협을 식별하기 위해 프로그램이나 시스템의 설계 단계에서 일반적으로 사용됩니다.
2. **DREAD**: Microsoft의 또 다른 방법론으로 식별된 위협의 위험 평가에 사용됩니다. DREAD는 **피해 가능성, 재현성, 이용 가능성, 영향을 받는 사용자 및 발견 가능성**을 나타냅니다. 각 요소는 점수가 매겨지며, 결과는 식별된 위협을 우선 순위로 정하는 데 사용됩니다.
3. **PASTA**(공격 시뮬레이션 및 위협 분석 프로세스): 이는 일곱 단계의 **위험 중심적** 방법론입니다. 보안 목표를 정의하고 식별, 기술 범위 생성, 응용 프로그램 분해, 위협 분석, 취약성 분석 및 위험/트리지 평가를 포함합니다.
4. **Trike**: 자산을 방어하는 데 초점을 맞춘 위험 중심적 방법론입니다. **위험 관리** 관점에서 시작하여 해당 맥락과 요구 사항에 따라 위협과 취약점을 살펴봅니다.
5. **VAST**(시각적, 민첩하고 간단한 위협 모델링): 이 방법론은 Agile 개발 환경에 통합되도록 설계되었습니다. 다른 방법론에서 요소를 결합하고 **위협의 시각적 표현**에 초점을 맞춥니다.
6. **OCTAVE**(운영 중요 위협, 자산 및 취약성 평가): CERT Coordination Center에서 개발된 이 프레임워크는 **특정 시스템이나 소프트웨어가 아닌 조직적 위험 평가**를 위해 고안되었습니다.

## 도구

위협 모델의 작성 및 관리에 도움이 되는 여러 도구와 소프트웨어 솔루션이 있습니다. 고려해볼 수 있는 몇 가지 도구는 다음과 같습니다.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

사이버 보안 전문가를 위한 고급 크로스 플랫폼 및 다기능 GUI 웹 스파이더/크롤러입니다. Spider Suite는 공격 표면 매핑 및 분석에 사용할 수 있습니다.

**사용법**

1. URL 선택 및 크롤링

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. 그래프 보기

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP의 오픈 소스 프로젝트인 Threat Dragon은 시스템 다이어그램 및 위협/완화를 자동으로 생성하는 규칙 엔진을 포함한 웹 및 데스크톱 애플리케이션입니다.

**사용법**

1. 새 프로젝트 생성

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

가끔 이렇게 보일 수 있습니다:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. 새 프로젝트 시작

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. 새 프로젝트 저장

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. 모델 생성

SpiderSuite Crawler와 같은 도구를 사용하여 영감을 받을 수 있으며, 기본 모델은 다음과 같이 보일 수 있습니다.

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

엔티티에 대한 간단한 설명:

* 프로세스(웹 서버 또는 웹 기능과 같은 엔티티 자체)
* 액터(웹사이트 방문자, 사용자 또는 관리자와 같은 사람)
* 데이터 흐름 라인(상호 작용 표시기)
* 신뢰 경계(다른 네트워크 세그먼트 또는 범위)
* 저장소(데이터가 저장되는 곳인 데이터베이스와 같은 것)

5. 위협 생성(단계 1)

먼저 위협을 추가할 레이어를 선택해야 합니다.

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

이제 위협을 생성할 수 있습니다.

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

액터 위협과 프로세스 위협 사이에는 차이가 있음을 염두에 두세요. 액터에 위협을 추가하면 "위조" 및 "부인"만 선택할 수 있습니다. 그러나 예시에서는 프로세스 엔티티에 위협을 추가하므로 위협 생성 상자에서 다음을 볼 수 있습니다:

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 완료

이제 완성된 모델은 다음과 같이 보일 것입니다. 이것이 OWASP Threat Dragon으로 간단한 위협 모델을 만드는 방법입니다.

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>
### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

이것은 Microsoft의 무료 도구로, 소프트웨어 프로젝트의 설계 단계에서 위협을 찾는 데 도움을 줍니다. 이 도구는 STRIDE 방법론을 사용하며 Microsoft 스택에서 개발하는 사람들에게 특히 적합합니다.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)는 **다크 웹**을 활용한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**되었는지 확인하는 **무료** 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난당한 악성 소프트웨어로 인한 계정 탈취와 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 **무료**로 엔진을 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}
