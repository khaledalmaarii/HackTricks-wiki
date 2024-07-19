# macOS AppleFS

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Apple 독점 파일 시스템 (APFS)

**Apple 파일 시스템 (APFS)**는 계층 파일 시스템 플러스 (HFS+)를 대체하기 위해 설계된 현대적인 파일 시스템입니다. 그 개발은 **향상된 성능, 보안 및 효율성**의 필요성에 의해 추진되었습니다.

APFS의 몇 가지 주목할 만한 기능은 다음과 같습니다:

1. **공간 공유**: APFS는 여러 볼륨이 **단일 물리적 장치에서 동일한 기본 무료 저장소를 공유**할 수 있도록 합니다. 이를 통해 볼륨이 수동 크기 조정이나 재분할 없이 동적으로 성장하고 축소될 수 있어 공간 활용이 더 효율적입니다.
1. 이는 전통적인 파일 디스크의 파티션과 비교할 때, **APFS에서 서로 다른 파티션(볼륨)이 모든 디스크 공간을 공유**한다는 것을 의미하며, 일반적인 파티션은 보통 고정 크기를 가집니다.
2. **스냅샷**: APFS는 **읽기 전용**인 파일 시스템의 시점 인스턴스인 **스냅샷 생성**을 지원합니다. 스냅샷은 추가 저장소를 최소한으로 소모하면서 효율적인 백업과 쉬운 시스템 롤백을 가능하게 하며, 빠르게 생성하거나 되돌릴 수 있습니다.
3. **클론**: APFS는 **원본과 동일한 저장소를 공유하는 파일 또는 디렉토리 클론을 생성**할 수 있습니다. 클론이나 원본 파일이 수정될 때까지 이 기능은 저장소 공간을 중복하지 않고 파일이나 디렉토리의 복사본을 효율적으로 생성하는 방법을 제공합니다.
4. **암호화**: APFS는 **전체 디스크 암호화**와 파일별 및 디렉토리별 암호화를 **본래적으로 지원**하여 다양한 사용 사례에서 데이터 보안을 강화합니다.
5. **충돌 보호**: APFS는 **파일 시스템 일관성을 보장하는 복사-쓰기 메타데이터 방식을 사용**하여 갑작스러운 전원 손실이나 시스템 충돌의 경우에도 데이터 손상 위험을 줄입니다.

전반적으로 APFS는 Apple 장치에 대해 더 현대적이고 유연하며 효율적인 파일 시스템을 제공하며, 향상된 성능, 신뢰성 및 보안에 중점을 두고 있습니다.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` 볼륨은 **`/System/Volumes/Data`**에 마운트됩니다 (이것은 `diskutil apfs list`로 확인할 수 있습니다).

firmlinks 목록은 **`/usr/share/firmlinks`** 파일에서 찾을 수 있습니다.
```bash
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
