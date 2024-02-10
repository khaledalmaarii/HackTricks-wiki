# macOS XPC 연결 프로세스 확인

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

## XPC 연결 프로세스 확인

XPC 서비스에 연결이 설정되면 서버는 연결이 허용되는지 확인합니다. 일반적으로 수행하는 확인 사항은 다음과 같습니다:

1. 연결하는 **프로세스가 Apple에서 제공한 Apple 서명** 인증서로 서명되었는지 확인합니다.
* 이를 **검증하지 않으면**, 공격자는 다른 확인 사항과 일치하는 가짜 인증서를 생성하여 사용할 수 있습니다.
2. 연결하는 프로세스가 **조직의 인증서**로 서명되었는지 확인합니다 (팀 ID 확인).
* 이를 **검증하지 않으면**, Apple의 **어떤 개발자 인증서**든 서명에 사용할 수 있고 서비스에 연결할 수 있습니다.
3. 연결하는 프로세스에 **적절한 번들 ID**가 있는지 확인합니다.
* 이를 **검증하지 않으면**, 동일한 조직에 의해 서명된 **어떤 도구**든 XPC 서비스와 상호 작용하는 데 사용될 수 있습니다.
4. (4 또는 5) 연결하는 프로세스에 **적절한 소프트웨어 버전 번호**가 있는지 확인합니다.
* 이를 **검증하지 않으면**, 다른 확인 사항이 적용되더라도 과거의 보안 취약한 클라이언트가 프로세스 인젝션에 취약한 상태로 XPC 서비스에 연결할 수 있습니다.
5. (4 또는 5) 연결하는 프로세스에 위험한 권한을 가지지 않은 강화된 런타임이 있는지 확인합니다 (임의의 라이브러리를 로드하거나 DYLD 환경 변수를 사용하는 권한).
* 이를 **검증하지 않으면**, 클라이언트는 **코드 인젝션에 취약**할 수 있습니다.
6. 연결하는 프로세스가 서비스에 연결할 수 있도록 허용하는 **권한**을 가지고 있는지 확인합니다. 이는 Apple 바이너리에 적용됩니다.
7. **검증**은 연결하는 **클라이언트의 감사 토큰**에 **기반**해야 하며 프로세스 ID (PID)가 아니어야 합니다. 왜냐하면 전자는 **PID 재사용 공격**을 방지하기 때문입니다.
* 개발자들은 감사 토큰 API 호출을 **거의 사용하지 않습니다**. Apple은 언제든지 변경할 수 있습니다. 또한, Mac App Store 앱에서는 비공개 API 사용이 허용되지 않습니다.
* **`processIdentifier`** 메서드를 사용하는 경우 취약할 수 있습니다.
* **`xpc_dictionary_get_audit_token`**은 **`xpc_connection_get_audit_token`** 대신 사용해야 합니다. 후자는 특정 상황에서도 [취약할 수 있습니다](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### 통신 공격

PID 재사용 공격에 대한 자세한 정보는 다음을 확인하세요:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

**`xpc_connection_get_audit_token`** 공격에 대한 자세한 정보는 다음을 확인하세요:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - 다운그레이드 공격 방지

Trustcache는 Apple Silicon 기기에 도입된 방어적인 방법으로, Apple 바이너리의 CDHSAH 데이터베이스를 저장하여 수정되지 않은 바이너리만 실행할 수 있도록 합니다. 이는 다운그레이드 버전의 실행을 방지합니다.

### 코드 예제

서버는 이 **검증**을 **`shouldAcceptNewConnection`** 함수에서 구현할 것입니다.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

NSXPCConnection 객체에는 **`auditToken`**이라는 **비공개** 속성(사용해야하지만 변경될 수 있는 속성)과 **`processIdentifier`**라는 **공개** 속성(사용해서는 안되는 속성)이 있습니다.

연결 프로세스는 다음과 같이 확인할 수 있습니다:

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
{% endcode %}

개발자가 클라이언트의 버전을 확인하지 않으려면, 적어도 클라이언트가 프로세스 인젝션에 취약하지 않은지 확인할 수 있습니다:

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
{% endcode %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
