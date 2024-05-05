# macOS xpc\_connection\_get\_audit\_token 공격

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 되는 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks를 광고하길 원하거나** **HackTricks를 PDF로 다운로드**하길 원한다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를** 팔로우하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소로 **PR을 제출**하여 **해킹 트릭을 공유**하세요.

</details>

**자세한 정보는 원본 게시물을 확인하세요:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). 이것은 요약입니다:

## Mach Messages 기본 정보

Mach Messages가 무엇인지 모르는 경우 이 페이지를 확인하세요:

{% content-ref url="../../" %}
[..](../../)
{% endcontent-ref %}

일단 ([여기에서 정의](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

Mach 메시지는 **맥 포트**를 통해 전송되며, 이는 **단일 수신자, 다중 송신자 통신** 채널로 맥 커널에 내장된 것입니다. **여러 프로세스가 맥 포트로 메시지를 보낼 수 있지만** 언제든지 **단일 프로세스만이** 그것을 읽을 수 있습니다. 파일 디스크립터 및 소켓과 마찬가지로 맥 포트는 커널에 의해 할당되고 관리되며 프로세스는 정수만 보고 이를 사용하여 사용할 맥 포트를 커널에 지시할 수 있습니다.

## XPC 연결

XPC 연결이 어떻게 설정되는지 모르는 경우 확인하세요:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## 취약점 요약

알아두어야 할 중요한 점은 **XPC의 추상화는 일대일 연결**이지만 **다중 송신자가 있는 기술**을 기반으로 하고 있다는 것입니다:

* 맥 포트는 단일 수신자, **다중 송신자**입니다.
* XPC 연결의 감사 토큰은 **가장 최근에 수신된 메시지에서 복사**됩니다.
* XPC 연결의 **감사 토큰을 획득**하는 것은 많은 **보안 검사에 중요**합니다.

이전 상황이 유망하게 들리지만 이로 인해 문제가 발생하지 않는 몇 가지 시나리오가 있습니다 ([여기에서](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* 감사 토큰은 연결을 수락할지 결정하기 위한 권한 확인에 자주 사용됩니다. 이는 서비스 포트로 메시지를 사용하여 발생하며 **아직 연결이 설정되지 않은** 상태입니다. 이 포트에서의 추가 메시지는 추가 연결 요청으로 처리됩니다. 따라서 **연결을 수락하기 전의 모든 확인 사항은 취약하지 않습니다** (이는 `-listener:shouldAcceptNewConnection:` 내에서 감사 토큰이 안전하다는 것을 의미합니다). 따라서 **특정 작업을 확인하는 XPC 연결을 찾고 있습니다**.
* XPC 이벤트 핸들러는 동기적으로 처리됩니다. 이는 한 메시지의 이벤트 핸들러가 다음 메시지를 호출하기 전에 완료되어야 함을 의미하며, 동시 디스패치 큐에서도 마찬가지입니다. 따라서 **XPC 이벤트 핸들러 내에서 감사 토큰은 다른 일반 (응답이 아닌!) 메시지에 의해 덮어쓰일 수 없습니다**.

이것이 악용될 수 있는 두 가지 다른 방법:

1. Variant1:
* **악용**은 서비스 **A** 및 서비스 **B**에 **연결**합니다.
* 서비스 **B**는 사용자가 할 수 없는 **특권 기능**을 서비스 **A**에서 호출할 수 있습니다.
* 서비스 **A**는 **이벤트 핸들러 내에서 아닌** **`dispatch_async`**에서 **`xpc_connection_get_audit_token`**을 호출합니다.
* 따라서 **다른** 메시지가 **감사 토큰을 덮어쓸 수 있습니다**. 왜냐하면 이것은 이벤트 핸들러 외부에서 비동기적으로 디스패치되기 때문입니다.
* 악용은 **서비스 A에게 서비스 A로의 SEND 권한을 전달**합니다.
* 따라서 svc **B**는 실제로 **메시지를 서비스 A로 보냅니다**.
* 악용은 **특권 작업을 호출**하려고 시도합니다. RC svc **A**는 **이 작업의 권한을 확인**하면서 **svc B가 감사 토큰을 덮어썼습니다** (악용이 특권 작업을 호출할 수 있도록 함).
2. Variant 2:
* 서비스 **B**는 사용자가 할 수 없는 **특권 기능**을 서비스 **A**에서 호출할 수 있습니다.
* 악용은 **서비스 A**에 연결하여 **특정 응답을 기대하는 메시지를 보내는** 서비스와 **두 번째 연결**을 형성합니다.
* 악용은 **서비스 B**에게 **그 응답 포트를 전달하는** 메시지를 보냅니다.
* 서비스 **B가 응답**할 때, **악용**은 **서비스 A로 다른 메시지를 보내어 특권 기능에 도달**하려고 시도하며, 서비스 B의 응답이 완벽한 순간에 감사 토큰을 덮어쓸 것을 기대합니다 (경쟁 조건).

## Variant 1: 이벤트 핸들러 외부에서 xpc\_connection\_get\_audit\_token 호출 <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

시나리오:

* 두 맥 서비스 **`A`** 및 **`B`**에 연결할 수 있는데 (샌드박스 프로필 및 연결 수락 전 권한 확인에 기반함).
* _**A**_는 **`B`**가 전달할 수 있는 특정 작업에 대한 **권한 확인**이 있어야 합니다 (하지만 우리 앱은 할 수 없음).
* 예를 들어, B에게 **특권**이 있거나 **루트로 실행** 중인 경우 A에게 특권 작업을 수행하도록 요청할 수 있습니다.
* 이 권한 확인을 위해 **`A`**는 비동기적으로 감사 토큰을 획득하며, 예를 들어 **`dispatch_async`**에서 `xpc_connection_get_audit_token`을 호출합니다.

{% hint style="danger" %}
이 경우 공격자는 **악용**을 트리거하여 **A에게 작업을 수행하도록 요청**하는 **악용**을 만들 수 있으며 **B가 `A`로 메시지를 보내도록** 만듭니다. RC가 **성공**하면 **B의 감사 토큰이 메모리에 복사**되고 **악용**의 요청이 **A에 의해 처리**되는 동안 특권 작업에 **액세스**할 수 있게 됩니다. 이 작업은 **B**로서 `diagnosticd` 및 **A**로서 `smd`로 발생했습니다. smb의 함수 [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc)를 통해 새로운 특권 도우미 도구를 설치하는 데 사용할 수 있습니다 (**루트**로 실행 중인 프로세스가 **smd**에 연락하면 다른 확인이 수행되지 않습니다). 따라서 서비스 **B**는 **루트로 실행**되므로 `diagnosticd`로 설정되어 **프로세스를 모니터링**할 수 있으며, 모니터링이 시작되면 **초당 여러 메시지를 보냅니다.**

공격을 수행하려면:

1. 표준 XPC 프로토콜을 사용하여 `smd`라는 서비스에 **연결**을 시작합니다.
2. `diagnosticd`에 대한 보조 **연결**을 형성합니다. 일반 절차와는 달리 두 개의 새로운 맥 포트를 생성하고 보내는 대신, 클라이언트 포트 송신 권한을 `smd` 연결과 연관된 **송신 권한**의 복제본으로 대체합니다.
3. 결과적으로 XPC 메시지를 `diagnosticd`로 보낼 수 있지만 `diagnosticd`로부터의 응답은 `smd`로 재경로됩니다. `smd`에게는 사용자 및 `diagnosticd`로부터의 메시지가 동일한 연결에서 발신된 것으로 보입니다.

![악용 프로세스를 묘사하는 이미지](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. 다음 단계는 `diagnosticd`에게 선택한 프로세스 (아마도 사용자의 프로세스)의 모니터링을 시작하도록 지시하는 것입니다. 동시에 `smd`로 루틴 1004 메시지의 홍수를 보냅니다. 여기서 의도는 특권이 있는 도구를 설치하는 것입니다.
5. 이 작업은 `handle_bless` 함수 내에서 race condition을 트리거합니다. 타이밍이 중요합니다: `xpc_connection_get_pid` 함수 호출은 사용자 프로세스의 PID를 반환해야 합니다(특권 도구는 사용자 앱 번들에 상주합니다). 그러나 `xpc_connection_get_audit_token` 함수는 특히 `connection_is_authorized` 서브루틴 내에서 `diagnosticd`에 속한 감사 토큰을 참조해야 합니다.

## 변형 2: 응답 전달

XPC(크로스 프로세스 통신) 환경에서 이벤트 핸들러는 동시에 실행되지 않지만 응답 메시지 처리에는 고유한 동작이 있습니다. 구체적으로 응답을 기대하는 메시지를 보내는 두 가지 다른 방법이 있습니다:

1. **`xpc_connection_send_message_with_reply`**: 여기서 XPC 메시지는 지정된 큐에서 수신되고 처리됩니다.
2. **`xpc_connection_send_message_with_reply_sync`**: 반면에 이 방법에서는 XPC 메시지가 현재 디스패치 큐에서 수신되고 처리됩니다.

이 차이는 **응답 패킷이 XPC 이벤트 핸들러의 실행과 동시에 구문 분석될 수 있는 가능성**을 허용합니다. 특히 `_xpc_connection_set_creds`는 감사 토큰의 부분적 덮어쓰기를 방지하기 위해 잠금을 구현하지만 전체 연결 객체에 이 보호를 확장하지는 않습니다. 결과적으로 이는 패킷의 구문 분석과 해당 이벤트 핸들러의 실행 사이의 간격 동안 감사 토큰이 교체될 수 있는 취약점을 만듭니다.

이 취약점을 악용하기 위해 다음 설정이 필요합니다:

* 두 개의 mach 서비스, **`A`**와 **`B`**, 둘 다 연결을 설정할 수 있어야 합니다.
* 서비스 **`A`**는 **`B`**만 수행할 수 있는 특정 작업에 대한 권한 확인을 포함해야 합니다(사용자 애플리케이션은 수행할 수 없음).
* 서비스 **`A`**는 응답을 기대하는 메시지를 보내야 합니다.
* 사용자는 **`B`**에게 응답할 메시지를 보낼 수 있어야 합니다.

악용 프로세스는 다음 단계를 포함합니다:

1. 서비스 **`A`**가 응답을 기대하는 메시지를 보내기를 기다립니다.
2. **`A`**에 직접 응답하는 대신 응답 포트가 탈취되어 서비스 **`B`**에게 메시지를 보내는 데 사용됩니다.
3. 이후 금지된 작업을 포함하는 메시지가 전송되며, **`B`**의 응답과 동시에 처리될 것으로 예상됩니다.

아래는 설명된 공격 시나리오의 시각적 표현입니다:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## 발견 문제

* **인스턴스 찾기의 어려움**: `xpc_connection_get_audit_token` 사용 사례를 정적으로나 동적으로 찾는 것이 어려웠습니다.
* **방법론**: Frida를 사용하여 `xpc_connection_get_audit_token` 함수를 후킹하여 이벤트 핸들러에서 비롯된 호출을 필터링했습니다. 그러나 이 방법은 후킹된 프로세스에 한정되었으며 적극적인 사용이 필요했습니다.
* **분석 도구**: IDA/Ghidra와 같은 도구를 사용하여 도달 가능한 mach 서비스를 조사했지만, dyld 공유 캐시를 포함하는 호출로 인해 시간이 많이 소요되었습니다.
* **스크립팅 제한**: `dispatch_async` 블록에서 `xpc_connection_get_audit_token` 호출을 분석하기 위한 시도는 블록 구문 분석과 dyld 공유 캐시와의 상호작용으로 인해 복잡성에 방해를 받았습니다.

## 수정 <a href="#the-fix" id="the-fix"></a>

* **보고된 문제**: `smd` 내에서 발견된 일반 및 구체적인 문제에 대해 Apple에 보고서가 제출되었습니다.
* **Apple의 응답**: Apple은 `smd`에서 `xpc_connection_get_audit_token`을 `xpc_dictionary_get_audit_token`으로 대체하여 문제를 해결했습니다.
* **수정의 성격**: `xpc_dictionary_get_audit_token` 함수는 XPC 메시지에 연결된 mach 메시지에서 직접 감사 토큰을 검색하기 때문에 안전하다고 간주됩니다. 그러나 이는 `xpc_connection_get_audit_token`과 마찬가지로 공개 API의 일부가 아닙니다.
* **보다 포괄적인 수정의 부재**: Apple이 연결의 저장된 감사 토큰과 일치하지 않는 메시지를 폐기하는 등 더 포괄적인 수정을 구현하지 않은 이유는 명확하지 않습니다. 특정 시나리오(예: `setuid` 사용)에서 합법적인 감사 토큰 변경 가능성이 요인일 수 있습니다.
* **현재 상태**: 문제는 iOS 17 및 macOS 14에서 지속되며, 이를 식별하고 이해하려는 사람들에게 도전을 제공합니다.
