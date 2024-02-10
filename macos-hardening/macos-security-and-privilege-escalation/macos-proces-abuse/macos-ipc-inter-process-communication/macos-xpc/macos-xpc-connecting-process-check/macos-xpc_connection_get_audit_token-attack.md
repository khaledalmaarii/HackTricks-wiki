# macOS xpc\_connection\_get\_audit\_token 공격

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 여러분의 해킹 기교를 공유하세요.

</details>

**자세한 정보는 원본 게시물을 확인하세요: [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)**. 이것은 요약입니다:


## Mach Messages 기본 정보

Mach Messages가 무엇인지 모르는 경우 이 페이지를 확인하세요:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

당분간은 ([여기에서 정의](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

Mach 메시지는 mach 커널에 내장된 **단일 수신자, 다중 발신자 통신** 채널인 **mach 포트**를 통해 전송됩니다. **여러 프로세스가 mach 포트로 메시지를 보낼 수 있지만** 어느 시점에서는 **단일 프로세스만 읽을 수 있습니다**. 파일 디스크립터와 소켓과 마찬가지로 mach 포트는 커널에 의해 할당되고 관리되며 프로세스는 정수만 보고 이를 사용하여 커널에 사용할 mach 포트를 지정할 수 있습니다.

## XPC 연결

XPC 연결이 어떻게 설정되는지 모르는 경우 확인하세요:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## 취약점 요약

알아두면 좋은 점은 **XPC의 추상화는 일대일 연결**이지만 **다중 발신자를 가질 수 있는 기술을 기반**으로 한다는 것입니다:

* Mach 포트는 단일 수신자, **다중 발신자**입니다.
* XPC 연결의 감사 토큰은 **가장 최근에 수신한 메시지에서 복사**됩니다.
* XPC 연결의 **감사 토큰을 얻는 것은 많은 보안 검사에 중요**합니다.

이전 상황은 유망해 보이지만 일부 시나리오에서는 문제가 발생하지 않을 수 있습니다 ([여기에서](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* 감사 토큰은 연결을 수락할지 여부를 결정하기 위한 권한 확인에 자주 사용됩니다. 이는 서비스 포트로 메시지를 사용하여 발생하므로 **아직 연결이 설정되지 않았습니다**. 이 포트의 추가 메시지는 추가 연결 요청으로 처리됩니다. 따라서 **연결을 수락하기 전의 확인은 취약하지 않습니다** (이는 `-listener:shouldAcceptNewConnection:` 내에서 감사 토큰이 안전하다는 것을 의미합니다). 따라서 **특정 작업을 확인하는 XPC 연결을 찾고 있습니다**.
* XPC 이벤트 핸들러는 동기적으로 처리됩니다. 이는 한 메시지의 이벤트 핸들러가 다음 메시지를 호출하기 전에 완료되어야 함을 의미합니다. 따라서 XPC 이벤트 핸들러 내에서는 다른 일반 (응답이 아닌!) 메시지에 의해 감사 토큰이 덮어쓰일 수 없습니다.

이를 악용할 수 있는 두 가지 다른 방법이 있습니다:

1. Variant1:
* **Exploit**은 서비스 **A**와 서비스 **B**에 **연결**합니다.
* 서비스 **B**는 사용자가 할 수 없는 **특권 기능**을 서비스 **A**에서 호출할 수 있습니다.
* 서비스 **A**는 **`xpc_connection_get_audit_token`**을 호출하는 동안 **이벤트 핸들러** 내부가 아닌 **`dispatch_async`**에서 실행됩니다.
* 따라서 **다른** 메시지가 **이벤트 핸들러 외부에서 비동기적으로 디스패치**되므로 **감사 토큰이 덮어쓰일 수 있습니다**.
* Exploit은 **서비스 A에 대한 SEND 권한을 서비스 B에 전달**합니다.
* 따라서 svc **B**는 실제로 서비스 **A**에 **메시지를 보냅니다**.
* Exploit은 **특권 작업을 호출**하려고 시도합니다. RC svc **A**에서는 **이 작업의 권한을 확인**하고 **svc B가 감사 토큰을 덮어썼으므로** (Exploit이 특권 작업을 호출할 수 있는 액세스를 제공) 악용이 가능합니다.
2. Variant 2:
* 서비스 **B**는 사용자가 할 수 없는 **특권 기능**을 서비스 **A**에서 호출할 수 있습니다.
* Exploit은 **서비스 A**에 연결하고 특정 **응답**을 기대하는 **메시지를 보내**는데 사용되는 **리플레이 포트**가 있는 메시지를 받습니다.
* Exploit은 **서비스 B**에게 **그 리플레이 포트**를 전달하는 메시지를 보냅니다.
* 서비스 **B가 응답**을 보낼 때, **메시지를 서비스 A에 보내고** **Exploit**은 특권 기능에 도달하려는 **다른 메시지를 서비스 A에 보냅니다**. 그리고 그 때 완벽한 타이밍에 서비스 B의 응답이 감사 토큰을 덮어쓰도
4. 다음 단계는 `diagnosticd`에게 선택한 프로세스 (사용자의 프로세스일 수도 있음)의 모니터링을 지시하는 것입니다. 동시에, `smd`로 일련의 루틴 1004 메시지가 보내집니다. 이렇게 함으로써 권한이 상승된 도구를 설치하는 것이 목적입니다.
5. 이 작업은 `handle_bless` 함수 내에서 경합 조건을 발생시킵니다. 타이밍이 매우 중요합니다: `xpc_connection_get_pid` 함수 호출은 사용자의 프로세스의 PID를 반환해야 합니다 (권한이 상승된 도구는 사용자의 앱 번들에 있음). 그러나 `xpc_connection_get_audit_token` 함수는 특히 `connection_is_authorized` 하위 루틴 내에서 `diagnosticd`에 속한 감사 토큰을 참조해야 합니다.

## 변형 2: 응답 전달

XPC (크로스 프로세스 통신) 환경에서 이벤트 핸들러는 동시에 실행되지 않지만, 응답 메시지 처리에는 고유한 동작이 있습니다. 구체적으로, 응답을 기대하는 메시지를 보내는 두 가지 다른 방법이 있습니다:

1. **`xpc_connection_send_message_with_reply`**: 여기서 XPC 메시지는 지정된 큐에서 수신되고 처리됩니다.
2. **`xpc_connection_send_message_with_reply_sync`**: 반대로, 이 방법에서는 XPC 메시지가 현재 디스패치 큐에서 수신되고 처리됩니다.

이 차이점은 **응답 패킷이 XPC 이벤트 핸들러의 실행과 동시에 구문 분석될 수 있는 가능성**을 제공합니다. 특히, `_xpc_connection_set_creds`는 감사 토큰의 부분적 덮어쓰기를 방지하기 위해 잠금을 구현하지만, 전체 연결 객체에 대해서는 이 보호를 확장하지 않습니다. 결과적으로, 패킷의 구문 분석과 이벤트 핸들러의 실행 사이의 간격 동안 감사 토큰이 교체될 수 있는 취약점이 생성됩니다.

이 취약점을 악용하기 위해서는 다음 설정이 필요합니다:

- 두 개의 맥 서비스, **`A`**와 **`B`**, 둘 다 연결을 설정할 수 있는 서비스입니다.
- 서비스 **`A`**는 **`B`**만 수행할 수 있는 특정 작업에 대한 권한 확인을 포함해야 합니다 (사용자의 애플리케이션은 수행할 수 없음).
- 서비스 **`A`**는 응답을 기대하는 메시지를 보내야 합니다.
- 사용자는 **`B`**에게 응답할 메시지를 보낼 수 있습니다.

악용 과정은 다음 단계를 포함합니다:

1. 서비스 **`A`**가 응답을 기대하는 메시지를 보내기를 기다립니다.
2. **`A`**에 직접 응답하는 대신, 응답 포트를 탈취하여 **`B`**에게 메시지를 보냅니다.
3. 이후, 금지된 작업을 포함하는 메시지가 전송되며, 이 메시지가 **`B`**의 응답과 동시에 처리될 것으로 예상됩니다.

아래는 설명된 공격 시나리오의 시각적 표현입니다:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)


<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## 발견 문제

- **인스턴스 찾기의 어려움**: `xpc_connection_get_audit_token` 사용 인스턴스를 정적으로나 동적으로 찾는 것은 어려웠습니다.
- **방법론**: `xpc_connection_get_audit_token` 함수를 후킹하기 위해 Frida를 사용했으며, 이벤트 핸들러에서 비롯된 호출을 필터링했습니다. 그러나 이 방법은 후킹된 프로세스에 한정되며, 활성 사용이 필요했습니다.
- **분석 도구**: IDA/Ghidra와 같은 도구를 사용하여 도달 가능한 맥 서비스를 조사했지만, dyld 공유 캐시를 포함한 호출로 인해 시간이 많이 소요되는 작업이었습니다.
- **스크립팅 제한**: `dispatch_async` 블록에서 `xpc_connection_get_audit_token` 호출을 분석하기 위한 스크립팅 시도는 블록 구문 분석과 dyld 공유 캐시와의 상호작용의 복잡성으로 인해 제한되었습니다.

## 수정 사항 <a href="#the-fix" id="the-fix"></a>

- **보고된 문제**: `smd`에서 발견된 일반적인 및 구체적인 문제에 대해 Apple에 보고서가 제출되었습니다.
- **Apple의 응답**: Apple은 `smd`에서 `xpc_connection_get_audit_token`을 `xpc_dictionary_get_audit_token`으로 대체하여 이 문제를 해결했습니다.
- **수정 사항의 성격**: `xpc_dictionary_get_audit_token` 함수는 XPC 메시지에 연결된 맥 메시지에서 직접 감사 토큰을 검색하기 때문에 안전하다고 간주됩니다. 그러나 이 함수는 `xpc_connection_get_audit_token`과 마찬가지로 공개 API의 일부가 아닙니다.
- **보다 포괄적인 수정의 부재**: Apple이 연결의 저장된 감사 토큰과 일치하지 않는 메시지를 폐기하는 등 더 포괄적인 수정을 구현하지 않은 이유는 여전히 불분명합니다. 특정 시나리오에서 합법적인 감사 토큰 변경 가능성 (예: `setuid` 사용)이 요인일 수 있습니다.
- **현재 상태**: 이 문제는 iOS 17과 macOS 14에서 여전히 존재하여 식별하고 이해하는 데 어려움을 겪는 사람들에게 도전이 됩니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요!</summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**구독 플랜**](https://github.com/sponsors/carlospolop)을 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터**에서 **팔로우**하세요 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **HackTricks**와 **HackTricks Cloud** 깃허브 저장소에 **PR을 제출**하여 여러분의 해킹 기법을 공유하세요.

</details>
