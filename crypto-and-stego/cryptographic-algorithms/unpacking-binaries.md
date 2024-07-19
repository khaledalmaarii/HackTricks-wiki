{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}


# 패킹된 바이너리 식별하기

* **문자열 부족**: 패킹된 바이너리에서 거의 문자열이 없는 경우가 흔합니다.
* 많은 **사용되지 않는 문자열**: 또한, 악성 코드가 상업용 패커를 사용하는 경우, 교차 참조가 없는 많은 문자열을 찾는 것이 일반적입니다. 이러한 문자열이 존재한다고 해서 바이너리가 패킹되지 않았다는 의미는 아닙니다.
* 바이너리를 패킹하는 데 사용된 패커를 찾기 위해 몇 가지 도구를 사용할 수 있습니다:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# 기본 권장 사항

* **IDA에서 패킹된 바이너리를 아래에서 위로 분석하기 시작하세요**. 언패커는 언패킹된 코드가 종료되면 종료되므로 언패커가 시작할 때 언패킹된 코드로 실행을 전달할 가능성은 낮습니다.
* **레지스터** 또는 **메모리**의 **영역**에 대한 **JMP** 또는 **CALL**을 검색하세요. 또한 **인수를 푸시하고 주소 방향을 호출한 후 `retn`을 호출하는 함수**를 검색하세요. 이 경우 함수의 반환은 호출하기 전에 스택에 푸시된 주소를 호출할 수 있습니다.
* `VirtualAlloc`에 **중단점을 설정하세요**. 이는 프로그램이 언패킹된 코드를 쓸 수 있는 메모리 공간을 할당합니다. "사용자 코드로 실행"하거나 F8을 사용하여 **함수를 실행한 후 EAX 내부의 값을 가져오세요**. 그리고 "**덤프에서 해당 주소를 따르세요**". 언패킹된 코드가 저장될 지역인지 알 수 없습니다.
* **`VirtualAlloc`**에 "**40**"이라는 값을 인수로 사용하면 읽기+쓰기+실행을 의미합니다(여기에 실행이 필요한 코드가 복사될 것입니다).
* **코드를 언패킹하는 동안** **여러 호출**을 **산술 연산** 및 **`memcopy`** 또는 **`Virtual`**`Alloc`과 같은 함수에서 찾는 것이 일반적입니다. 만약 당신이 산술 연산만 수행하는 함수에 있다면, **함수의 끝을 찾으려고 시도하세요**(아마도 레지스터에 대한 JMP 또는 호출) **또는** 최소한 **마지막 함수에 대한 호출**을 찾고 그곳으로 실행하세요. 코드가 흥미롭지 않기 때문입니다.
* 코드를 언패킹하는 동안 **메모리 영역이 변경될 때마다 주의하세요**. 메모리 영역의 변경은 **언패킹 코드의 시작**을 나타낼 수 있습니다. Process Hacker를 사용하여 메모리 영역을 쉽게 덤프할 수 있습니다(프로세스 --> 속성 --> 메모리).
* 코드를 언패킹하려고 할 때 **이미 언패킹된 코드로 작업하고 있는지 아는 좋은 방법**은 **바이너리의 문자열을 확인하는 것입니다**. 만약 어느 시점에서 점프를 수행하고(아마도 메모리 영역을 변경하면서) **더 많은 문자열이 추가된 것을 발견하면**, **당신이 언패킹된 코드로 작업하고 있다는 것을 알 수 있습니다**.\
그러나 패커에 이미 많은 문자열이 포함되어 있다면 "http"라는 단어가 포함된 문자열의 수를 확인하고 이 숫자가 증가하는지 확인하세요.
* 메모리 영역에서 실행 파일을 덤프할 때 [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases)를 사용하여 일부 헤더를 수정할 수 있습니다.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
