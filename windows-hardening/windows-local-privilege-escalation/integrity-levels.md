# Níveis de Integridade

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

## Níveis de Integridade

No Windows Vista e versões posteriores, todos os itens protegidos vêm com uma etiqueta de **nível de integridade**. Essa configuração atribui principalmente um nível de integridade "médio" a arquivos e chaves de registro, exceto por certas pastas e arquivos que o Internet Explorer 7 pode gravar em um nível de integridade baixo. O comportamento padrão é que processos iniciados por usuários padrão tenham um nível de integridade médio, enquanto serviços normalmente operam em um nível de integridade do sistema. Um rótulo de alta integridade protege o diretório raiz.

Uma regra chave é que objetos não podem ser modificados por processos com um nível de integridade inferior ao nível do objeto. Os níveis de integridade são:

* **Não confiável**: Este nível é para processos com logins anônimos. %%%Exemplo: Chrome%%%
* **Baixo**: Principalmente para interações na internet, especialmente no Modo Protegido do Internet Explorer, afetando arquivos e processos associados, e certas pastas como a **Pasta Temporária da Internet**. Processos de baixa integridade enfrentam restrições significativas, incluindo sem acesso de gravação no registro e acesso limitado de gravação no perfil do usuário.
* **Médio**: O nível padrão para a maioria das atividades, atribuído a usuários padrão e objetos sem níveis de integridade específicos. Mesmo membros do grupo de Administradores operam neste nível por padrão.
* **Alto**: Reservado para administradores, permitindo que eles modifiquem objetos em níveis de integridade inferiores, incluindo aqueles no próprio nível alto.
* **Sistema**: O nível operacional mais alto para o kernel do Windows e serviços essenciais, fora do alcance mesmo para administradores, garantindo a proteção de funções vitais do sistema.
* **Instalador**: Um nível único que se destaca acima de todos os outros, permitindo que objetos neste nível desinstalem qualquer outro objeto.

Você pode obter o nível de integridade de um processo usando o **Process Explorer** da **Sysinternals**, acessando as **propriedades** do processo e visualizando a aba "**Segurança**":

![](<../../.gitbook/assets/image (824).png>)

Você também pode obter seu **nível de integridade atual** usando `whoami /groups`

![](<../../.gitbook/assets/image (325).png>)

### Níveis de Integridade no Sistema de Arquivos

Um objeto dentro do sistema de arquivos pode precisar de um **requisito mínimo de nível de integridade** e se um processo não tiver esse nível de integridade, não poderá interagir com ele.\
Por exemplo, vamos **criar um arquivo regular a partir de um console de usuário regular e verificar as permissões**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Agora, vamos atribuir um nível de integridade mínimo de **Alto** ao arquivo. Isso **deve ser feito a partir de um console** executando como **administrador**, pois um **console regular** estará executando em nível de integridade Médio e **não será permitido** atribuir nível de integridade Alto a um objeto:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Isso é onde as coisas ficam interessantes. Você pode ver que o usuário `DESKTOP-IDJHTKP\user` tem **plenos privilégios** sobre o arquivo (de fato, este foi o usuário que criou o arquivo), no entanto, devido ao nível mínimo de integridade implementado, ele não poderá mais modificar o arquivo, a menos que esteja executando dentro de um Nível de Integridade Alto (note que ele poderá lê-lo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Portanto, quando um arquivo tem um nível mínimo de integridade, para modificá-lo você precisa estar executando pelo menos nesse nível de integridade.**
{% endhint %}

### Níveis de Integridade em Binários

Eu fiz uma cópia de `cmd.exe` em `C:\Windows\System32\cmd-low.exe` e defini um **nível de integridade baixo a partir de um console de administrador:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Agora, quando eu executo `cmd-low.exe`, ele **será executado sob um nível de integridade baixo** em vez de um nível médio:

![](<../../.gitbook/assets/image (313).png>)

Para pessoas curiosas, se você atribuir um nível de integridade alto a um binário (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), ele não será executado automaticamente com nível de integridade alto (se você invocá-lo de um nível de integridade médio --por padrão-- ele será executado sob um nível de integridade médio).

### Níveis de Integridade em Processos

Nem todos os arquivos e pastas têm um nível mínimo de integridade, **mas todos os processos estão sendo executados sob um nível de integridade**. E semelhante ao que aconteceu com o sistema de arquivos, **se um processo quiser escrever dentro de outro processo, ele deve ter pelo menos o mesmo nível de integridade**. Isso significa que um processo com nível de integridade baixo não pode abrir um manipulador com acesso total a um processo com nível de integridade médio.

Devido às restrições comentadas nesta e na seção anterior, do ponto de vista de segurança, é sempre **recomendado executar um processo no nível de integridade mais baixo possível**.


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
