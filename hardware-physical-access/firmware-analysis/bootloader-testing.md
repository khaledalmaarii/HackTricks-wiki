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

다음 단계는 U-boot와 같은 장치 시작 구성 및 부트로더를 수정하는 데 권장됩니다:

1. **부트로더의 인터프리터 셸에 접근**:
- 부팅 중 "0", 스페이스 또는 다른 식별된 "매직 코드"를 눌러 부트로더의 인터프리터 셸에 접근합니다.

2. **부트 인수 수정**:
- 다음 명령을 실행하여 '`init=/bin/sh`'를 부트 인수에 추가하여 셸 명령을 실행할 수 있도록 합니다:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTP 서버 설정**:
- 로컬 네트워크를 통해 이미지를 로드하기 위해 TFTP 서버를 구성합니다:
%%%
#setenv ipaddr 192.168.2.2 #장치의 로컬 IP
#setenv serverip 192.168.2.1 #TFTP 서버 IP
#saveenv
#reset
#ping 192.168.2.1 #네트워크 접근 확인
#tftp ${loadaddr} uImage-3.6.35 #loadaddr는 파일을 로드할 주소와 TFTP 서버의 이미지 파일 이름을 가져옵니다
%%%

4. **`ubootwrite.py` 사용**:
- `ubootwrite.py`를 사용하여 U-boot 이미지를 작성하고 수정된 펌웨어를 푸시하여 루트 접근을 얻습니다.

5. **디버그 기능 확인**:
- 자세한 로깅, 임의 커널 로드 또는 신뢰할 수 없는 소스에서 부팅과 같은 디버그 기능이 활성화되어 있는지 확인합니다.

6. **주의할 하드웨어 간섭**:
- 장치 부팅 시퀀스 중 하나의 핀을 접지에 연결하고 SPI 또는 NAND 플래시 칩과 상호작용할 때 주의하십시오. 특히 커널이 압축 해제되기 전에 핀을 단락시키기 전에 NAND 플래시 칩의 데이터 시트를 참조하십시오.

7. **악성 DHCP 서버 구성**:
- PXE 부팅 중 장치가 수신할 악성 매개변수를 가진 악성 DHCP 서버를 설정합니다. Metasploit의 (MSF) DHCP 보조 서버와 같은 도구를 사용하십시오. 'FILENAME' 매개변수를 `'a";/bin/sh;#'`와 같은 명령 주입 명령으로 수정하여 장치 시작 절차에 대한 입력 유효성 검사를 테스트합니다.

**참고**: 장치 핀과의 물리적 상호작용을 포함하는 단계(*별표로 표시된)는 장치 손상을 피하기 위해 극도로 주의하여 접근해야 합니다.


## References
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

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
