# Cheat Engine

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 트릭을 공유**하려면 [HackTricks](https://github.com/carlospolop/hacktricks) 및 [HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)은 실행 중인 게임의 메모리 내에서 중요한 값이 저장된 위치를 찾고 변경하는 데 유용한 프로그램입니다.\
다운로드하고 실행하면 도구 사용 방법에 대한 자습서가 제공됩니다. 도구 사용 방법을 배우고 싶다면 자습서를 완료하는 것이 매우 권장됩니다.

## 무엇을 찾고 있나요?

![](<../../.gitbook/assets/image (762).png>)

이 도구는 프로그램의 메모리에 어떤 값(보통 숫자)이 저장되어 있는지 찾는 데 매우 유용합니다.\
보통 숫자는 4바이트 형식으로 저장되지만, 더블 또는 플로트 형식으로 찾을 수도 있으며 숫자가 아닌 다른 것을 찾고 싶을 수도 있습니다. 그러므로 무엇을 찾을지 선택해야 합니다:

![](<../../.gitbook/assets/image (324).png>)

또한 **다양한 유형의 검색**을 지정할 수 있습니다:

![](<../../.gitbook/assets/image (311).png>)

또한 **메모리 스캔 중 게임을 일시 중지**할 수도 있습니다:

![](<../../.gitbook/assets/image (1052).png>)

### 단축키

_**편집 --> 설정 --> 단축키**_에서 **게임을 중지**하는 등 다양한 목적으로 다른 **단축키**를 설정할 수 있습니다. 다른 옵션도 사용할 수 있습니다:

![](<../../.gitbook/assets/image (864).png>)

## 값 수정

값을 **찾은 후** (다음 단계에서 자세히 설명함) **수정하려는 값이 어디에 있는지** 찾았다면 해당 값을 두 번 클릭하여 수정한 후 해당 값 두 번 클릭:

![](<../../.gitbook/assets/image (563).png>)

마지막으로 **체크 표시**를 하여 수정 사항을 메모리에 적용합니다:

![](<../../.gitbook/assets/image (385).png>)

메모리에 대한 변경 사항은 즉시 적용됩니다 (게임이 이 값을 다시 사용할 때까지 값이 게임에서 업데이트되지 않음에 유의).

## 값 검색

따라서 사용자의 생명과 같이 중요한 값을 향상시키고자 하며 해당 값을 메모리에서 찾고자 한다고 가정해 봅시다.

### 알려진 변경을 통해

값 100을 찾고자 한다고 가정하고 해당 값으로 검색하여 많은 일치 항목을 찾았다고 가정합니다:

![](<../../.gitbook/assets/image (108).png>)

그런 다음 **값을 변경**하고 게임을 **중지**한 후 **다음 스캔**을 수행합니다:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine은 **100에서 새 값으로 변경된 값**을 검색합니다. 축하합니다, 찾고자 했던 값의 주소를 찾았으므로 이제 수정할 수 있습니다.\
_여전히 여러 값이 있는 경우 해당 값을 다시 수정하고 "다음 스캔"을 수행하여 주소를 필터링할 수 있습니다._

### 알려지지 않은 값, 알려진 변경

값을 모르지만 **변경 방법**(및 변경 값)을 알고 있다면 해당 숫자를 찾을 수 있습니다.

따라서 "**알려지지 않은 초기 값**" 유형의 스캔을 수행합니다:

![](<../../.gitbook/assets/image (890).png>)

그런 다음 값이 변경되도록하고 **값이 변경된 방법**을 지정하고 **다음 스캔**을 수행합니다:

![](<../../.gitbook/assets/image (371).png>)

선택한 방식으로 **수정된 모든 값**이 표시됩니다:

![](<../../.gitbook/assets/image (569).png>)

값을 찾은 후 수정할 수 있습니다.

다양한 변경 사항이 있으며 결과를 필터링하려면 이러한 단계를 원하는만큼 반복할 수 있습니다:

![](<../../.gitbook/assets/image (574).png>)

### 무작위 메모리 주소 - 코드 찾기

값을 저장하는 주소를 찾는 방법을 배웠지만 **게임의 다른 실행에서는 해당 주소가 메모리의 다른 위치에 있을 가능성이 높습니다**. 따라서 항상 해당 주소를 찾는 방법을 알아보겠습니다.

언급된 트릭 중 일부를 사용하여 현재 게임이 중요한 값을 저장하는 주소를 찾습니다. 그런 다음 (원하는 경우 게임을 중지) 찾은 주소에서 **마우스 오른쪽 버튼을 클릭**하고 "**이 주소를 사용하는 것 찾기**" 또는 "**이 주소에 쓰는 것 찾기**"를 선택합니다:

![](<../../.gitbook/assets/image (1067).png>)

**첫 번째 옵션**은 이 **주소를 사용하는 코드 부분**을 알 수 있어서 게임 코드를 수정하는 데 유용합니다.\
**두 번째 옵션**은 **구체적**이며, **이 값이 어디서 쓰이는지**를 알기 위해 이 경우 더 유용합니다.

이러한 옵션 중 하나를 선택하면 **디버거**가 프로그램에 연결되고 새로운 **빈 창**이 나타납니다. 이제 **게임을 플레이**하고 **값을 수정**합니다 (게임을 다시 시작하지 않고). 창에는 **값을 수정하는 주소**가 채워집니다:

![](<../../.gitbook/assets/image (91).png>)

값을 수정하는 주소를 찾았으므로 Cheat Engine을 사용하여 빠르게 수정할 수 있습니다. 코드를 수정하여 숫자에 영향을 미치지 않도록하거나 항상 긍정적인 방향으로 영향을 미치도록 수정할 수 있습니다:

![](<../../.gitbook/assets/image (1057).png>)
### 랜덤 메모리 주소 - 포인터 찾기

이전 단계를 따라 관심 있는 값이 있는 위치를 찾습니다. 그런 다음 "**이 주소에 쓰는 것을 찾아보기**"를 사용하여 이 값을 쓰는 주소를 찾고 두 번 클릭하여 어셈블리 뷰를 얻습니다:

![](<../../.gitbook/assets/image (1039).png>)

그런 다음, 새로운 스캔을 수행하여 "\[]" 사이의 16진수 값을 검색합니다 (이 경우 $edx의 값):

![](<../../.gitbook/assets/image (994).png>)

(여러 개가 나타나면 일반적으로 가장 작은 주소를 필요로 합니다)\
이제, 우리는 **우리가 관심 있는 값이 수정될 포인터를 찾았습니다**.

"**주소 수동 추가**"를 클릭합니다:

![](<../../.gitbook/assets/image (990).png>)

이제 "포인터" 확인란을 클릭하고 텍스트 상자에 찾은 주소를 추가합니다 (이 시나리오에서 이전 이미지에서 찾은 주소는 "Tutorial-i386.exe"+2426B0였습니다):

![](<../../.gitbook/assets/image (392).png>)

(포인터 주소를 입력하면 첫 번째 "주소"가 자동으로 채워짐을 주목하세요)

확인을 클릭하면 새로운 포인터가 생성됩니다:

![](<../../.gitbook/assets/image (308).png>)

이제, 그 값을 수정할 때마다 **메모리 주소가 다르더라도 중요한 값을 수정하고 있습니다.**

### 코드 인젝션

코드 인젝션은 대상 프로세스에 코드 조각을 삽입하고 코드 실행을 자체 작성한 코드를 통해 재경로화하는 기술입니다 (포인트를 빼는 대신 포인트를 추가하는 등).

따라서, 플레이어의 생명을 1 감소시키는 주소를 찾은 것으로 상상해보세요:

![](<../../.gitbook/assets/image (203).png>)

**디스어셈블러 표시**를 클릭하여 어셈블리 코드를 얻습니다.\
그런 다음, **CTRL+a**를 클릭하여 자동 어셈블 창을 호출하고 _**템플릿 --> 코드 인젝션**_을 선택합니다

![](<../../.gitbook/assets/image (902).png>)

수정하려는 **명령어의 주소를 입력**합니다 (보통 자동으로 채워집니다):

![](<../../.gitbook/assets/image (744).png>)

템플릿이 생성됩니다:

![](<../../.gitbook/assets/image (944).png>)

그런 다음, 새 어셈블리 코드를 "**newmem**" 섹션에 삽입하고 "**originalcode**"에서 원래 코드를 제거하면 실행되지 않습니다. 이 예에서 삽입된 코드는 1을 빼는 대신 2 포인트를 추가합니다:

![](<../../.gitbook/assets/image (521).png>)

**실행을 클릭하고 계속 진행하면 프로그램에 코드가 인젝션되어 기능의 동작이 변경될 것입니다!**

## **참고 자료**

* **Cheat Engine 튜토리얼, Cheat Engine을 시작하는 방법을 배우려면 완료하세요**

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!**
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **HackTricks 및 HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
