<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>로부터 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 여러분의 해킹 기교를 공유하세요.

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php)는 실행 중인 게임의 메모리 내에서 중요한 값이 저장된 위치를 찾고 변경하는 유용한 프로그램입니다.\
다운로드하고 실행하면 도구 사용 방법에 대한 자습서가 제공됩니다. 도구 사용 방법을 배우려면 자습서를 완료하는 것이 매우 권장됩니다.

# 무엇을 찾고 있나요?

![](<../../.gitbook/assets/image (580).png>)

이 도구는 프로그램의 메모리에 어떤 값(일반적으로 숫자)이 저장되어 있는지 찾는 데 매우 유용합니다.\
일반적으로 숫자는 4바이트 형식으로 저장되지만, 더블 또는 플로트 형식으로 찾을 수도 있으며, 숫자가 아닌 다른 것을 찾을 수도 있습니다. 이를 위해 찾고자 하는 대상을 선택해야 합니다:

![](<../../.gitbook/assets/image (581).png>)

또한 다양한 유형의 검색을 지정할 수 있습니다:

![](<../../.gitbook/assets/image (582).png>)

메모리를 스캔하는 동안 게임을 중지하려면 상자를 선택할 수도 있습니다:

![](<../../.gitbook/assets/image (584).png>)

## 단축키

_**편집 --> 설정 --> 단축키**_에서 다른 목적에 대해 다른 **단축키**를 설정할 수 있습니다. 게임을 중지하는 것과 같은 다른 옵션도 사용할 수 있습니다:

![](<../../.gitbook/assets/image (583).png>)

# 값 수정하기

찾고자 하는 값의 위치를 찾았다면(다음 단계에서 자세히 설명합니다) 해당 값을 두 번 클릭하여 수정할 수 있습니다:

![](<../../.gitbook/assets/image (585).png>)

그리고 메모리에서 수정을 완료하기 위해 확인란을 선택합니다:

![](<../../.gitbook/assets/image (586).png>)

메모리의 변경 사항은 즉시 적용됩니다(게임이 이 값을 다시 사용하기 전까지는 값이 게임에서 업데이트되지 않음에 유의하세요).

# 값 검색하기

따라서 사용자의 생명과 같은 중요한 값(개선하려는 값)이 있고 이 값을 메모리에서 찾고자 한다고 가정합니다)

## 알려진 변경을 통해

값 100을 찾고자 한다고 가정하고 해당 값을 검색하여 많은 일치 항목을 찾았습니다:

![](<../../.gitbook/assets/image (587).png>)

그런 다음 값이 변경되도록 무언가를 수행하고 게임을 중지하고 다음 스캔을 수행합니다:

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine는 100에서 새 값으로 변경된 값들을 검색합니다. 축하합니다. 찾고자 하는 값의 주소를 찾았으므로 이제 값을 수정할 수 있습니다.\
_여전히 여러 값이 있는 경우 해당 값을 다시 수정하기 위해 무언가를 수행하고 다른 "다음 스캔"을 수행하세요._

## 알려지지 않은 값, 알려진 변경

값을 모르지만 값이 어떻게 변경되는지(변경 값도 알고 있는 경우) 알고 있다면 해당 숫자를 찾을 수 있습니다.

따라서 "**알려지지 않은 초기 값**" 유형의 스캔을 수행하세요:

![](<../../.gitbook/assets/image (589).png>)

그런 다음 값이 변경되도록 하고 값이 어떻게 변경되었는지(제 경우에는 1 감소)를 나타내고 **다음 스캔**을 수행하세요:

![](<../../.gitbook/assets/image (590).png>)

선택한 방식으로 수정된 모든 값이 표시됩니다:

![](<../../.gitbook/assets/image (591).png>)

값을 찾은 후에는 해당 값을 수정할 수 있습니다.

수정할 수 있는 가능한 변경 사항이 많이 있으며 결과를 필터링하기 위해 이러한 단계를 원하는 만큼 수행할 수 있습니다:

![](<../../.gitbook/assets/image (592).png>)

## 임의의 메모리 주소 - 코드 찾기

지금까지 값이 저장된 주소를 찾는 방법을 배웠지만, 게임의 다른 실행에서는 해당 주소가 메모리의 다른 위치에 있을 수 있습니다. 따라서 항상 해당 주소를 찾는 방법을 알아보겠습니다.

언급된 트릭 중 일부를 사용하여 현재 게임이 중요한 값을 저장하는 주소를 찾으세요. 그런 다음 (원하는 경우 게임을 중지하고) 찾은 주소에서 마우스 오른쪽 단추를 클릭하고 "**이 주소를 사용하는 부분 찾기**" 또는 "**이 주소에 쓰는 부분 찾기**"를 선택하세요:

![](<../../.gitbook/assets/image (593).png>)

**첫 번째 옵션**은 이 주소를 사용하는 **코드 부분**을 알려줍니다(게임의 코드를 수정하는 데 유용합니다).\
**두 번째 옵션**은 더 **구체적**이며, 이 경우에는 **이 값이 쓰여지는 위치**를 알아내는 데 더 도움이 됩니다.

이러한 옵션 중 하나를 선택한 후에는 **디버거**가 프로그램에 **연결**되고 새로운 **빈 창**이 나타납니다. 이제 **게임**을 **플레이**하고 **값**을 **수정**하세요(게임을 다시 시작하지 않고). **창**에는 **값을 수정하는 주소**가 **채워질** 것입니다:

![](<../../.gitbook/assets/image (594).png>)

값을 수정하는 주소를 찾았으므로 코드를 원하는 대로 수정할 수 있습니다(Cheat Engine를 사용하면 NOPs를 신속하게 수정할 수 있습니다):

![](<../../.gitbook/assets/image (595).png>)

따라서 코드를 수정하여 숫자에 영향을 주지 않거나 항상 긍정적인 방식으로 영향을 주도록 수정할 수 있습니다.
## 랜덤 메모리 주소 - 포인터 찾기

이전 단계를 따라 관심 있는 값이 있는 위치를 찾으세요. 그런 다음 "**이 주소에 쓰는 것을 찾아보세요**"를 사용하여 이 값을 쓰는 주소를 찾고, 이를 두 번 클릭하여 어셈블리 뷰를 얻으세요:

![](<../../.gitbook/assets/image (596).png>)

그런 다음, 새로운 스캔을 수행하여 "\[]" 사이의 16진수 값을 검색하세요 (이 경우 $edx의 값):

![](<../../.gitbook/assets/image (597).png>)

(여러 개가 나타나면 일반적으로 가장 작은 주소를 사용합니다)\
이제 우리는 **관심 있는 값을 수정할 포인터를 찾았습니다**.

"**주소 수동 추가**"를 클릭하세요:

![](<../../.gitbook/assets/image (598).png>)

이제 "Pointer" 확인란을 선택하고 이전 이미지에서 찾은 주소를 텍스트 상자에 추가하세요 (이 시나리오에서 이전 이미지에서 찾은 주소는 "Tutorial-i386.exe"+2426B0입니다):

![](<../../.gitbook/assets/image (599).png>)

(입력한 포인터 주소에서 첫 번째 "주소"가 자동으로 채워짐에 주목하세요)

확인을 클릭하면 새로운 포인터가 생성됩니다:

![](<../../.gitbook/assets/image (600).png>)

이제 해당 값을 수정할 때마다 메모리 주소가 다르더라도 **중요한 값을 수정하고 있습니다**.

## 코드 주입

코드 주입은 대상 프로세스에 코드 조각을 주입한 다음 코드 실행을 자체 작성한 코드를 통해 재경로 설정하는 기술입니다 (예: 점수를 얻는 대신 점수를 뺏는 것).

따라서 플레이어의 생명을 1 감소시키는 주소를 찾았다고 가정해 보겠습니다:

![](<../../.gitbook/assets/image (601).png>)

디스어셈블러 표시를 클릭하여 **디스어셈블 코드**를 얻으세요.\
그런 다음, **CTRL+a**를 눌러 자동 어셈블 창을 호출하고 _**템플릿 --> 코드 주입**_을 선택하세요.

![](<../../.gitbook/assets/image (602).png>)

**수정하려는 명령문의 주소**를 입력하세요 (일반적으로 자동으로 채워집니다):

![](<../../.gitbook/assets/image (603).png>)

템플릿이 생성됩니다:

![](<../../.gitbook/assets/image (604).png>)

그런 다음, 새 어셈블리 코드를 "**newmem**" 섹션에 삽입하고 원래 코드를 "**originalcode**"에서 제거하세요. 이 예제에서 주입된 코드는 1을 빼는 대신 2 포인트를 추가합니다:

![](<../../.gitbook/assets/image (605).png>)

**실행을 클릭하고 계속 진행하면 코드가 프로그램에 주입되어 기능의 동작이 변경됩니다!**

# **참고 자료**

* **Cheat Engine 튜토리얼, Cheat Engine을 시작하는 방법을 배우려면 완료하세요**



<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>로 AWS 해킹을 처음부터 전문가까지 배워보세요</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
