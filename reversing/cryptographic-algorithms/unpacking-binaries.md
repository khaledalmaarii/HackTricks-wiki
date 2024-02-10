<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**을 팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 해킹 트릭을 공유하세요.

</details>


# 패킹된 이진 파일 식별하기

* **문자열 부재**: 패킹된 이진 파일에서는 거의 어떤 문자열도 찾을 수 없는 것이 일반적입니다.
* 많은 **사용되지 않는 문자열**: 악성 코드가 상업용 패커를 사용하는 경우, 교차 참조 없이 많은 문자열을 찾는 것이 일반적입니다. 이러한 문자열이 존재한다고 해도 이진 파일이 패킹되지 않았다는 의미는 아닙니다.
* 일부 도구를 사용하여 이진 파일을 패킹한 패커를 찾을 수도 있습니다:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# 기본 권장 사항

* 패킹된 이진 파일을 분석할 때는 **IDA에서 아래에서 위로** 분석을 시작하세요. 언패커는 언패킹된 코드가 종료되면 종료되므로 시작 시 언패킹된 코드로 실행을 전달하는 경우는 드뭅니다.
* **레지스터** 또는 **메모리 영역**으로의 **JMP** 또는 **CALL** 또는 **인수를 푸시하고 주소 방향을 호출한 다음 `retn`을 호출하는 함수**를 검색하세요. 이 경우 함수의 반환은 호출하기 전에 스택에 푸시된 주소를 호출할 수 있으므로 해당 주소를 따라가야 합니다.
* `VirtualAlloc`에 **중단점**을 설정하세요. 이는 프로그램이 언패킹된 코드를 작성할 수 있는 메모리 공간을 할당하기 때문입니다. 함수를 실행한 후 EAX 내부의 값을 얻으려면 "run to user code" 또는 F8을 사용하여 "**덤프에서 해당 주소를 따라가세요**". 언패킹된 코드가 저장될 영역인지 확실하지 않기 때문에 이를 알 수 없습니다.
* **`VirtualAlloc`**의 인수로 "**40**"이라는 값을 사용하면 Read+Write+Execute(실행이 필요한 일부 코드가 여기에 복사됨)를 의미합니다.
* 코드를 언패킹하는 동안 **산술 연산** 및 **`memcopy`** 또는 **`Virtual`**`Alloc`과 같은 함수를 **여러 번 호출**하는 것이 일반적입니다. 산술 연산만 수행하는 함수에 도달하면 (아마도 JMP 또는 레지스터로의 호출) **함수의 끝**을 찾거나 적어도 **마지막 함수를 호출**하여 코드가 흥미로운지 확인하세요.
* 코드를 언패킹하는 동안 **메모리 영역을 변경**할 때마다 **메모리 영역 변경**이 언패킹 코드의 시작을 나타낼 수 있습니다. Process Hacker(프로세스 --> 속성 --> 메모리)를 사용하여 메모리 영역을 쉽게 덤프할 수 있습니다.
* 코드를 언패킹하려고 할 때 이미 **언패킹된 코드로 작업 중인지 확인하는 좋은 방법**은 이진 파일의 문자열을 **확인**하는 것입니다. 어느 시점에서 점프(메모리 영역 변경)를 수행하고 **더 많은 문자열이 추가**된 것을 알 수 있다면, **언패킹된 코드로 작업 중**임을 알 수 있습니다.\
그러나 패커에 이미 많은 문자열이 포함되어 있는 경우 "http"라는 단어를 포함하는 문자열의 수를 확인하고 이 수가 증가하는지 확인할 수 있습니다.
* 메모리 영역에서 실행 파일을 덤프할 때 [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases)를 사용하여 일부 헤더를 수정할 수 있습니다.


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**을 팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 해킹 트릭을 공유하세요.

</details>
