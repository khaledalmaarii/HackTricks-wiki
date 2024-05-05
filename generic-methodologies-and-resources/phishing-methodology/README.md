# 피싱 방법론

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로**부터 **히어로**로 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 방법론

1. 피해자 식별
1. **피해자 도메인** 선택
2. 피해자가 사용하는 **로그인 포털을 찾아** 몇 가지 기본 웹 열거를 수행하고 **가장할 포털을 결정**합니다.
3. **OSINT**를 사용하여 **이메일을 찾습니다**.
2. 환경 준비
1. 피싱 평가에 사용할 도메인을 **구입**합니다.
2. 관련 레코드 (SPF, DMARC, DKIM, rDNS)를 **구성**하여 **이메일 서비스를 구성**합니다.
3. **gophish**로 VPS를 구성합니다.
3. 캠페인 준비
1. **이메일 템플릿**을 준비합니다.
2. 자격 증명을 훔치기 위한 **웹 페이지**를 준비합니다.
4. 캠페인 시작!

## 유사 도메인 이름 생성 또는 신뢰할 수 있는 도메인 구매

### 도메인 이름 변형 기술

* **키워드**: 도메인 이름에 원본 도메인의 중요한 **키워드가 포함**됩니다 (예: zelster.com-management.com).
* **하이픈 서브도메인**: 서브도메인의 **점을 하이픈으로 변경**합니다 (예: www-zelster.com).
* **새 TLD**: **새 TLD**를 사용하여 동일한 도메인 (예: zelster.org)
* **동형 문자**: 도메인 이름의 문자를 **비슷한 문자로 대체**합니다 (예: zelfser.com).
* **교체**: 도메인 이름 내에서 **두 문자를 교환**합니다 (예: zelsetr.com).
* **단수화/복수화**: 도메인 이름 끝에 "s"를 추가하거나 제거합니다 (예: zeltsers.com).
* **생략**: 도메인 이름에서 **한 문자를 제거**합니다 (예: zelser.com).
* **반복**: 도메인 이름에서 **한 문자를 반복**합니다 (예: zeltsser.com).
* **교체**: 동형 문자와 유사하지만 덜 은밀합니다. 도메인 이름의 문자 중 하나를 교체하여 원래 문자와 키보드 상의 근접한 문자로 대체합니다 (예: zektser.com).
* **서브도메인**: 도메인 이름에 **점을** 추가합니다 (예: ze.lster.com).
* **삽입**: 도메인 이름에 **문자를 삽입**합니다 (예: zerltser.com).
* **마침표 누락**: 도메인 이름에 TLD를 추가합니다. (예: zelstercom.com)

**자동 도구**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**웹사이트**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### 비트 플리핑

**일부 비트가 자동으로 뒤집힐 수 있는** 여러 요인(태양 플레어, 우주선, 하드웨어 오류 등)으로 인해 **저장 또는 통신 중인 일부 비트가 자동으로 뒤집힐 수 있습니다**.

이 개념을 **DNS 요청에 적용**할 때 DNS 서버가 수신한 도메인이 초기 요청한 도메인과 다를 수 있습니다.

예를 들어, 도메인 "windows.com"의 단일 비트 수정으로 "windnws.com"으로 변경될 수 있습니다.

공격자는 피해자의 도메인과 유사한 여러 비트 플리핑 도메인을 등록하여 **합법적인 사용자를 자신의 인프라로 리디렉션**시킬 수 있습니다.

자세한 내용은 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)에서 확인하세요.

### 신뢰할 수 있는 도메인 구매

[https://www.expireddomains.net/](https://www.expireddomains.net)에서 사용할 만료된 도메인을 검색할 수 있습니다.\
사용할 만료된 도메인이 **이미 좋은 SEO를 가지고 있는지 확인**하려면 다음에서 카테고리화되어 있는지 확인할 수 있습니다:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 이메일 발견

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 무료)
* [https://phonebook.cz/](https://phonebook.cz) (100% 무료)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

더 많은 유효한 이메일 주소를 **발견**하거나 이미 발견한 이메일 주소를 **확인**하려면 피해자의 smtp 서버를 브루트 포스할 수 있는지 확인하세요. [여기에서 이메일 주소를 확인/발견하는 방법을 배우세요](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
또한 사용자가 **메일에 액세스하기 위해 웹 포털을 사용하는 경우**, 해당 포털이 **사용자 이름 브루트 포스**에 취약한지 확인하고 가능한 경우 취약점을 악용할 수 있습니다.

## GoPhish 구성

### 설치

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)에서 다운로드할 수 있습니다.

다운로드하여 `/opt/gophish` 내부에 압축을 푼 후 `/opt/gophish/gophish`를 실행하세요.\
출력에서 관리자 사용자의 암호가 제공됩니다. 따라서 해당 포트에 액세스하여 해당 자격 증명을 사용하여 관리자 암호를 변경하세요. 해당 포트를 로컬로 터널링해야 할 수도 있습니다.
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 구성

**TLS 인증서 구성**

이 단계 이전에는 이미 사용할 도메인을 **구입**하고 있어야 하며, 해당 도메인은 **gophish**를 구성하는 **VPS의 IP**를 **가리키고 있어야** 합니다.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**메일 구성**

시작 설치: `apt-get install postfix`

다음 파일에 도메인을 추가하십시오:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**또한 /etc/postfix/main.cf 내의 다음 변수 값을 변경하십시오**

`myhostname = <도메인>`\
`mydestination = $myhostname, <도메인>, localhost.com, localhost`

마지막으로 **`/etc/hostname`** 및 **`/etc/mailname`** 파일을 도메인 이름으로 수정하고 **VPS를 다시 시작하십시오.**

이제, `mail.<도메인>`을 VPS의 **IP 주소**로 가리키는 **DNS A 레코드**를 만들고, `mail.<도메인>`을 가리키는 **DNS MX** 레코드를 만듭니다.

이제 이메일을 보내는 테스트를 해봅시다:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 구성**

gophish의 실행을 중지하고 구성합니다.\
`/opt/gophish/config.json`을 다음과 같이 수정하십시오 (https 사용에 유의):
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**gophish 서비스 구성**

gophish 서비스를 생성하여 자동으로 시작되고 서비스로 관리할 수 있도록 하려면 다음 내용으로 `/etc/init.d/gophish` 파일을 생성할 수 있습니다:
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
서비스 구성을 완료하고 다음을 수행하여 확인하십시오:
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## 메일 서버 및 도메인 구성

### 기다리고 정품처럼 보이기

도메인이 오래될수록 스팸으로 감지될 가능성이 적어집니다. 따라서 피싱 평가를 진행하기 전에 최대한 많은 시간(적어도 1주일)을 기다려야 합니다. 게다가, 평판이 좋은 섹터에 관한 페이지를 넣으면 얻는 평판도 더 좋아집니다.

1주일을 기다려야 하지만 지금 모든 것을 구성할 수 있습니다.

### 역방향 DNS (rDNS) 레코드 구성

VPS의 IP 주소를 도메인 이름으로 해석하는 rDNS (PTR) 레코드를 설정합니다.

### 발신자 정책 프레임워크 (SPF) 레코드

**새 도메인에 SPF 레코드를 구성**해야 합니다. SPF 레코드가 무엇인지 모르는 경우 [**이 페이지**](../../network-services-pentesting/pentesting-smtp/#spf)를 읽어보세요.

[https://www.spfwizard.net/](https://www.spfwizard.net)을 사용하여 SPF 정책을 생성할 수 있습니다 (VPS 머신의 IP를 사용).

![](<../../.gitbook/assets/image (1037).png>)

도메인 내의 TXT 레코드에 설정해야 하는 내용입니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 도메인 기반 메시지 인증, 보고 및 준수(Domain-based Message Authentication, Reporting & Conformance, DMARC) 레코드

**새 도메인에 대한 DMARC 레코드를 구성해야**합니다. DMARC 레코드가 무엇인지 모르는 경우 [**이 페이지를 읽으십시오**](../../network-services-pentesting/pentesting-smtp/#dmarc).

다음 내용을 포함하는 새 DNS TXT 레코드를 생성해야 합니다. 호스트 이름을 `_dmarc.<도메인>`으로 지정하십시오.
```bash
v=DMARC1; p=none
```
### 도메인키 식별 메일 (DKIM)

**새 도메인에 대한 DKIM을 구성해야**합니다. DMARC 레코드가 무엇인지 모르는 경우 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/#dkim).

이 튜토리얼은 다음을 기반으로 합니다: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
DKIM 키가 생성하는 두 B64 값을 연결해야합니다:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### 이메일 구성 점수 테스트

[https://www.mail-tester.com/](https://www.mail-tester.com)를 사용하여 이를 수행할 수 있습니다.\
페이지에 액세스하여 제공된 주소로 이메일을 보내보세요:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
당신은 또한 이메일 구성을 확인할 수 있습니다. `check-auth@verifier.port25.com` 로 이메일을 보내고 응답을 읽어보세요 (이를 위해 포트 25를 열어야 하며, root로 이메일을 보내면 파일 _/var/mail/root_ 에 응답을 확인할 수 있습니다).\
모든 테스트를 통과했는지 확인하세요:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
당신은 **자신이 제어하는 Gmail로 메시지를 보내고**, Gmail 받은 편지함에서 **이메일 헤더**를 확인할 수 있습니다. `Authentication-Results` 헤더 필드에 `dkim=pass`가 포함되어 있어야 합니다.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### 스팸하우스 블랙리스트에서 제거

페이지 [www.mail-tester.com](https://www.mail-tester.com)에서 도메인이 스팸하우스에 의해 차단되었는지 확인할 수 있습니다. 도메인/IP를 제거하려면 다음 주소에서 요청할 수 있습니다: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### 마이크로소프트 블랙리스트에서 제거

도메인/IP를 제거하려면 [https://sender.office.com/](https://sender.office.com)에서 요청할 수 있습니다.

## GoPhish 캠페인 생성 및 실행

### 발신 프로필

* **발신자 프로필을 식별할 이름**을 설정합니다.
* 어떤 계정에서 피싱 이메일을 보낼지 결정합니다. 제안: _noreply, support, servicedesk, salesforce..._
* 사용자 이름과 비밀번호를 비워 둘 수 있지만 **인증서 오류 무시**를 확인해야 합니다.

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

{% hint style="info" %}
**테스트 이메일 보내기** 기능을 사용하여 모든 것이 작동하는지 테스트하는 것이 좋습니다.\
테스트를 수행하여 블랙리스트에 올라가지 않도록 **10분 메일 주소로 테스트 이메일을 보내는 것이 좋습니다**.
{% endhint %}

### 이메일 템플릿

* **템플릿을 식별할 이름**을 설정합니다.
* 그런 다음 **제목**을 작성합니다(이상한 내용이 아닌 일반적인 이메일에서 읽을 수 있는 내용).
* **추적 이미지 추가**를 확인했는지 확인합니다.
* **이메일 템플릿**을 작성합니다(다음 예제처럼 변수를 사용할 수 있습니다):
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
**이메일의 신뢰성을 높이기 위해**, 클라이언트 이메일에서 서명을 사용하는 것이 권장됩니다. 제안:

* **존재하지 않는 주소**로 이메일을 보내 응답에 서명이 있는지 확인합니다.
* info@ex.com 또는 press@ex.com 또는 public@ex.com과 같은 **공개 이메일**을 검색하고 이메일을 보내 응답을 기다립니다.
* **일부 유효한 발견된** 이메일에 연락해 응답을 기다립니다.

![](<../../.gitbook/assets/image (80).png>)

{% hint style="info" %}
이메일 템플릿은 **파일을 첨부하여 전송**할 수도 있습니다. 특별히 제작된 파일/문서를 사용하여 NTLM 도전을 도용하고 싶다면 [이 페이지](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)를 참조하세요.
{% endhint %}

### 랜딩 페이지

* **이름 작성**
* 웹 페이지의 **HTML 코드 작성**. 웹 페이지를 **가져올 수 있음**을 참고하세요.
* **제출된 데이터 캡처** 및 **비밀번호 캡처** 표시
* **리다이렉션 설정**

![](<../../.gitbook/assets/image (826).png>)

{% hint style="info" %}
보통 페이지의 HTML 코드를 수정하고 로컬에서 테스트를 수행한 후 (아파치 서버를 사용하여) **원하는 결과를 얻을 때까지** 수정해야 합니다. 그런 다음 해당 HTML 코드를 상자에 작성하세요.\
HTML에 **일부 정적 리소스를 사용해야 하는 경우** (CSS 및 JS 페이지 등) _**/opt/gophish/static/endpoint**_에 저장한 다음 _**/static/\<filename>**_에서 액세스할 수 있습니다.
{% endhint %}

{% hint style="info" %}
리다이렉션으로 사용자를 피해자의 **정품 메인 웹 페이지로 리다이렉트**하거나 예를 들어 _/static/migration.html_로 리다이렉트하여 5초 동안 **회전하는 바퀴**([**https://loading.io/**](https://loading.io))를 표시한 후 프로세스가 성공적이었음을 나타낼 수 있습니다.
{% endhint %}

### 사용자 및 그룹

* 이름 설정
* 데이터 **가져오기** (예제에 사용할 템플릿을 사용하려면 각 사용자의 이름, 성 및 이메일 주소가 필요합니다)

![](<../../.gitbook/assets/image (163).png>)

### 캠페인

마지막으로, 캠페인을 생성하여 이름, 이메일 템플릿, 랜딩 페이지, URL, 전송 프로필 및 그룹을 선택합니다. URL은 피해자에게 보낼 링크가 될 것임을 유의하세요.

**전송 프로필을 사용하여 최종 피싱 이메일이 어떻게 보일지 확인할 수 있습니다**:

![](<../../.gitbook/assets/image (192).png>)

{% hint style="info" %}
테스트 이메일을 10분 메일 주소로 보내 테스트를 수행하여 블랙리스트에 올라가지 않도록 하는 것이 좋습니다.
{% endhint %}

모든 것이 준비되면 캠페인을 시작하세요!

## 웹사이트 복제

어떤 이유로든 웹사이트를 복제하고 싶다면 다음 페이지를 확인하세요:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## 백도어 문서 및 파일

일부 피싱 평가(주로 Red Team을 위한 것)에서는 **백도어가 포함된 파일을 전송**하고 싶을 수도 있습니다(C2일 수도 있고 인증을 트리거할 수도 있습니다).\
일부 예제를 보려면 다음 페이지를 확인하세요:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## MFA 피싱

### 프록시 MitM을 통한

이전 공격은 사용자가 설정한 정보를 수집하고 실제 웹사이트의 로그인 폼을 위장하는 것이므로 꽤 교묘합니다. 그러나 사용자가 올바른 비밀번호를 입력하지 않았거나 사용자가 설정한 애플리케이션이 2단계 인증(2FA)으로 구성된 경우, **이 정보만으로 속은 사용자를 흉내낼 수 없습니다**.

이때 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) 및 [**muraena**](https://github.com/muraenateam/muraena)와 같은 도구가 유용합니다. 이 도구를 사용하면 MitM과 같은 공격을 생성할 수 있습니다. 기본적으로 공격은 다음과 같이 작동합니다:

1. 실제 웹페이지의 **로그인 폼을 위장**합니다.
2. 사용자가 자신의 자격 증명을 가짜 페이지로 보내고 도구는 이를 실제 웹페이지로 보내어 **자격 증명이 작동하는지 확인**합니다.
3. 계정이 **2FA로 구성**된 경우 MitM 페이지는 이를 요청하고 사용자가 입력하면 도구가 실제 웹페이지로 보냅니다.
4. 사용자가 인증되면(공격자로서) 도구가 MitM을 수행하는 동안 상호 작용하는 모든 정보의 **자격 증명, 2FA, 쿠키 및 기타 정보를 캡처**할 수 있습니다.

### VNC를 통한

원래 웹페이지와 동일한 외관의 악성 페이지로 피해자를 보내는 대신, 실제 웹페이지에 연결된 브라우저가 있는 VNC 세션으로 피해자를 보낼 수 있다면 어떨까요? 그러면 피해자가 하는 일을 볼 수 있고 비밀번호, 사용된 MFA, 쿠키를 도용할 수 있습니다...\
이를 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)로 수행할 수 있습니다.

## 탐지 방지

당연히 걸렸는지 여부를 알 수 있는 가장 좋은 방법 중 하나는 **블랙리스트에서 도메인을 검색**하는 것입니다. 도메인이 의심스러운 것으로 감지된 경우 어떤 식으로든 도메인이 나열됩니다.\
도메인이 어떤 블랙리스트에 나열되어 있는지 확인하는 간단한 방법은 [https://malwareworld.com/](https://malwareworld.com)을 사용하는 것입니다.

그러나 피해자가 야생에서 **의심스러운 피싱 활동을 찾고 있는지** 알 수 있는 다른 방법은 다음에서 설명한 대로입니다:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

피해자의 도메인과 매우 유사한 이름의 도메인을 **구입**하거나 피해자의 도메인의 **키워드를 포함**하는 **자체 제어 도메인의 하위 도메인**에 대한 **인증서를 생성**할 수 있습니다. 피해자가 이러한 도메인과 상호 작용하는 경우, 의심스러운 도메인을 찾고 있음을 알 수 있으며 매우 은밀해야 합니다.

### 피싱 평가

[**Phishious** ](https://github.com/Rices/Phishious)를 사용하여 이메일이 스팸 폴더에 들어갈지 또는 차단될지 여부를 평가하세요.

## 참고 자료

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
