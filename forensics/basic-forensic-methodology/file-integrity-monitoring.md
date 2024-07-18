{% hint style="success" %}
Aprenda e pratique AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> [**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte) <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> \
Aprenda e pratique GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line"> [**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

# Baseline

Um baseline consiste em tirar uma snapshot de certas partes de um sistema para **compará-lo com um estado futuro e destacar mudanças**.

Por exemplo, você pode calcular e armazenar o hash de cada arquivo do sistema de arquivos para poder descobrir quais arquivos foram modificados.\
Isso também pode ser feito com as contas de usuário criadas, processos em execução, serviços em execução e qualquer outra coisa que não deveria mudar muito, ou nada.

## Monitoramento de Integridade de Arquivos

O Monitoramento de Integridade de Arquivos (FIM) é uma técnica de segurança crítica que protege ambientes de TI e dados rastreando mudanças em arquivos. Envolve duas etapas-chave:

1. **Comparação de Baseline:** Estabeleça um baseline usando atributos de arquivo ou checksums criptográficos (como MD5 ou SHA-2) para comparações futuras e detectar modificações.
2. **Notificação de Mudança em Tempo Real:** Receba alertas instantâneos quando arquivos são acessados ou alterados, geralmente por meio de extensões de kernel do sistema operacional.

## Ferramentas

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Referências

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


{% hint style="success" %}
Aprenda e pratique AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> [**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte) <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> \
Aprenda e pratique GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line"> [**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
