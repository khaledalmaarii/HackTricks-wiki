{% hint style="success" %}
**AWS 해킹 학습 및 실습:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**GCP 해킹 학습 및 실습:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요**.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}


# 기본 Payloads

* **간단한 목록:** 각 줄에 항목이 포함된 목록
* **런타임 파일:** 런타임에서 읽히는 목록(메모리에 로드되지 않음). 큰 목록을 지원합니다.
* **대소문자 변경:** 문자열 목록에 일부 변경 적용(변경 없음, 소문자로, 대문자로, Proper 이름으로 - 첫 글자 대문자로, 나머지는 소문자로-, Proper 이름으로 -첫 글자 대문자로, 나머지는 그대로-.
* **숫자:** X부터 Y까지 Z 간격 또는 무작위로 숫자 생성.
* **브루트 포서:** 문자 집합, 최소 및 최대 길이.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : 명령 실행 및 출력을 burpcollab로 DNS 요청을 통해 가져오는 페이로드.

{% embed url="https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e" %}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
