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

# Guia de Decompilação de Wasm e Compilação de Wat

No âmbito do **WebAssembly**, ferramentas para **decompilar** e **compilar** são essenciais para desenvolvedores. Este guia apresenta alguns recursos online e software para lidar com arquivos **Wasm (WebAssembly binary)** e **Wat (WebAssembly text)**.

## Ferramentas Online

- Para **decompilar** Wasm para Wat, a ferramenta disponível na [demonstração wasm2wat do Wabt](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) é útil.
- Para **compilar** Wat de volta para Wasm, a [demonstração wat2wasm do Wabt](https://webassembly.github.io/wabt/demo/wat2wasm/) serve ao propósito.
- Outra opção de decompilação pode ser encontrada em [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Soluções de Software

- Para uma solução mais robusta, [JEB da PNF Software](https://www.pnfsoftware.com/jeb/demo) oferece recursos extensivos.
- O projeto de código aberto [wasmdec](https://github.com/wwwg/wasmdec) também está disponível para tarefas de decompilação.

# Recursos de Decompilação .Net

Decompilar assemblies .Net pode ser realizado com ferramentas como:

- [ILSpy](https://github.com/icsharpcode/ILSpy), que também oferece um [plugin para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), permitindo uso multiplataforma.
- Para tarefas envolvendo **decompilação**, **modificação** e **recompilação**, [dnSpy](https://github.com/0xd4d/dnSpy/releases) é altamente recomendado. **Clicando com o botão direito** em um método e escolhendo **Modificar Método** permite alterações no código.
- [dotPeek da JetBrains](https://www.jetbrains.com/es-es/decompiler/) é outra alternativa para decompilar assemblies .Net.

## Melhorando Depuração e Registro com DNSpy

### Registro DNSpy
Para registrar informações em um arquivo usando DNSpy, incorpore o seguinte trecho de código .Net:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Senha: " + password + "\n");
%%%

### Depuração DNSpy
Para uma depuração eficaz com DNSpy, uma sequência de etapas é recomendada para ajustar **atributos de Assembly** para depuração, garantindo que otimizações que poderiam dificultar a depuração estejam desativadas. Este processo inclui alterar as configurações de `DebuggableAttribute`, recompilar o assembly e salvar as alterações.

Além disso, para depurar uma aplicação .Net executada pelo **IIS**, executar `iisreset /noforce` reinicia o IIS. Para anexar o DNSpy ao processo do IIS para depuração, o guia instrui a selecionar o processo **w3wp.exe** dentro do DNSpy e iniciar a sessão de depuração.

Para uma visão abrangente dos módulos carregados durante a depuração, acessar a janela **Módulos** no DNSpy é aconselhável, seguido pela abertura de todos os módulos e ordenação dos assemblies para facilitar a navegação e depuração.

Este guia encapsula a essência da decompilação de WebAssembly e .Net, oferecendo um caminho para os desenvolvedores navegarem nessas tarefas com facilidade.

## **Decompilador Java**
Para decompilar bytecode Java, estas ferramentas podem ser muito úteis:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Depuração de DLLs**
### Usando IDA
- **Rundll32** é carregado de caminhos específicos para versões de 64 bits e 32 bits.
- **Windbg** é selecionado como o depurador com a opção de suspender no carregamento/descarregamento da biblioteca habilitada.
- Os parâmetros de execução incluem o caminho da DLL e o nome da função. Esta configuração interrompe a execução ao carregar cada DLL.

### Usando x64dbg/x32dbg
- Semelhante ao IDA, **rundll32** é carregado com modificações na linha de comando para especificar a DLL e a função.
- As configurações são ajustadas para interromper na entrada da DLL, permitindo definir um ponto de interrupção no ponto de entrada desejado da DLL.

### Imagens
- Os pontos de parada de execução e configurações são ilustrados por meio de capturas de tela.

## **ARM & MIPS**
- Para emulação, [arm_now](https://github.com/nongiach/arm_now) é um recurso útil.

## **Shellcodes**
### Técnicas de Depuração
- **Blobrunner** e **jmp2it** são ferramentas para alocar shellcodes na memória e depurá-los com Ida ou x64dbg.
- Blobrunner [lançamentos](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [versão compilada](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** oferece emulação e inspeção de shellcode baseada em GUI, destacando diferenças no manuseio de shellcode como um arquivo versus shellcode direto.

### Deobfuscação e Análise
- **scdbg** fornece insights sobre funções de shellcode e capacidades de deobfuscação.
%%%bash
scdbg.exe -f shellcode # Informações básicas
scdbg.exe -f shellcode -r # Relatório de análise
scdbg.exe -f shellcode -i -r # Hooks interativos
scdbg.exe -f shellcode -d # Dump de shellcode decodificado
scdbg.exe -f shellcode /findsc # Encontrar deslocamento inicial
scdbg.exe -f shellcode /foff 0x0000004D # Executar a partir do deslocamento
%%%

- **CyberChef** para desassemblar shellcode: [Receita CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Um ofuscador que substitui todas as instruções por `mov`.
- Recursos úteis incluem uma [explicação no YouTube](https://www.youtube.com/watch?v=2VF_wPkiBJY) e [slides em PDF](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** pode reverter a ofuscação do movfuscator, exigindo dependências como `libcapstone-dev` e `libz3-dev`, e instalando [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**
- Para binários Delphi, [IDR](https://github.com/crypto2011/IDR) é recomendado.


# Cursos

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Deobfuscação binária\)



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
