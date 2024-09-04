# Linux 환경 변수

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

## 전역 변수

전역 변수는 **자식 프로세스**에 의해 **상속됩니다**.

현재 세션을 위해 전역 변수를 생성하려면:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
이 변수는 현재 세션과 그 자식 프로세스에서 접근할 수 있습니다.

변수를 **제거**하려면 다음을 수행하십시오:
```bash
unset MYGLOBAL
```
## Local variables

**로컬 변수**는 **현재 셸/스크립트**에서만 **접근**할 수 있습니다.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 현재 변수 목록
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – **X**에서 사용하는 디스플레이. 이 변수는 일반적으로 **:0.0**으로 설정되며, 이는 현재 컴퓨터의 첫 번째 디스플레이를 의미합니다.
* **EDITOR** – 사용자가 선호하는 텍스트 편집기.
* **HISTFILESIZE** – 히스토리 파일에 포함된 최대 라인 수.
* **HISTSIZE** – 사용자가 세션을 종료할 때 히스토리 파일에 추가되는 라인 수.
* **HOME** – 홈 디렉토리.
* **HOSTNAME** – 컴퓨터의 호스트 이름.
* **LANG** – 현재 언어.
* **MAIL** – 사용자의 메일 스풀 위치. 일반적으로 **/var/spool/mail/USER**.
* **MANPATH** – 매뉴얼 페이지를 검색할 디렉토리 목록.
* **OSTYPE** – 운영 체제의 유형.
* **PS1** – bash의 기본 프롬프트.
* **PATH** – 파일 이름만 지정하여 실행하고자 하는 바이너리 파일이 있는 모든 디렉토리의 경로를 저장합니다.
* **PWD** – 현재 작업 디렉토리.
* **SHELL** – 현재 명령 셸의 경로 (예: **/bin/bash**).
* **TERM** – 현재 터미널 유형 (예: **xterm**).
* **TZ** – 시간대.
* **USER** – 현재 사용자 이름.

## Interesting variables for hacking

### **HISTFILESIZE**

이 변수의 **값을 0으로 변경**하면, **세션을 종료할 때** **히스토리 파일** (\~/.bash\_history) **이 삭제됩니다**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

이 **변수의 값을 0으로 변경**하세요. 그러면 **세션을 종료할 때** 어떤 명령도 **히스토리 파일**(\~/.bash\_history)에 추가되지 않습니다.
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

프로세스는 **http 또는 https**를 통해 인터넷에 연결하기 위해 여기에서 선언된 **프록시**를 사용합니다.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

프로세스는 **이 환경 변수**에 표시된 인증서를 신뢰합니다.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

프롬프트의 모양을 변경합니다.

[**이것은 예시입니다**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

루트:

![](<../.gitbook/assets/image (897).png>)

일반 사용자:

![](<../.gitbook/assets/image (740).png>)

하나, 둘, 셋의 백그라운드 작업:

![](<../.gitbook/assets/image (145).png>)

하나의 백그라운드 작업, 하나의 정지된 작업, 마지막 명령이 올바르게 완료되지 않음:

![](<../.gitbook/assets/image (715).png>)


{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
