"""
Regras de segurança/qualidade para a EXPANSÃO de cobertura de linguagens.

Cobre HDL, build systems, IaC/config avançada, blockchain estendido, GPU/shaders,
linguagens de sistemas modernas, provas dependentes, quântica e legados.

Exporta EXPANSION_RULES: dict[Language, list[Rule]] — registrado em rules/__init__.py.
"""
from __future__ import annotations
import re
from typing import List, Dict
from analyzer.models import Severity, Confidence, Language, VulnCategory as VC
from analyzer.rules.base import Rule

S = Severity
_C = Confidence


def _r(rid, name, lang, pattern, sev, cat, desc, rem, cwe=None, owasp=None, ic=False,
       conf=Confidence.MEDIUM, ml=False) -> Rule:
    return Rule(
        id=rid, name=name, description=desc, severity=sev, category=cat,
        language=lang, pattern=pattern, remediation=rem, cwe=cwe, owasp=owasp,
        confidence=conf, flags=re.IGNORECASE if ic else 0, multiline=ml,
    )


EXPANSION_RULES: Dict[Language, List[Rule]] = {}


def _reg(lang: Language, rules: List[Rule]) -> None:
    EXPANSION_RULES.setdefault(lang, []).extend(rules)


# ════════════════════════════════════════════════════════════════════════════
#  HARDWARE DESCRIPTION — VHDL, Verilog/SystemVerilog
# ════════════════════════════════════════════════════════════════════════════
_reg(Language.VHDL, [
    _r("VHDL-001", "Latch inferido por falta de else", Language.VHDL,
       r'\bif\b.*\bthen\b(?!.*\belse\b)', S.MEDIUM, VC.CODE_QUALITY,
       "Atribuição condicional sem else em processo combinacional infere um latch não intencional, criando timing imprevisível e estados retidos.",
       "Forneça else explícito ou valor default antes do if para todo sinal combinacional.", cwe="CWE-1245", conf=_C.LOW),
    _r("VHDL-002", "Sensitivity list incompleta", Language.VHDL,
       r'\bprocess\s*\(\s*clk\s*\)', S.LOW, VC.CODE_QUALITY,
       "Process combinacional com sensitivity list parcial gera divergência entre simulação e síntese.",
       "Use 'process(all)' (VHDL-2008) ou liste todos os sinais lidos.", cwe="CWE-1281", conf=_C.LOW),
    _r("VHDL-003", "Chave/seed hardcoded em RTL", Language.VHDL,
       r'(?:key|seed|password)\s*:?=\s*(?:x?"[0-9A-Fa-f]+"|\d+)', S.HIGH, VC.HARDCODED_SECRETS,
       "Constantes criptográficas embutidas no RTL ficam visíveis no bitstream e podem ser extraídas por engenharia reversa do FPGA/ASIC.",
       "Carregue chaves via eFuse/OTP ou interface segura de provisionamento; nunca as fixe no HDL.", cwe="CWE-798", ic=True),
])
_reg(Language.VERILOG, [
    _r("VLOG-001", "Blocking assignment em lógica sequencial", Language.VERILOG,
       r'always\s*@\s*\(\s*posedge.*\)[^;]*[^<]=\s*[^=]', S.MEDIUM, VC.CONCURRENCY,
       "Uso de '=' (blocking) em always @(posedge clk) causa race conditions de simulação e mismatch com a síntese.",
       "Use '<=' (non-blocking) em blocos sequenciais e '=' apenas em combinacionais.", cwe="CWE-362", conf=_C.LOW),
    _r("VLOG-002", "Full case/parallel case pragma inseguro", Language.VERILOG,
       r'//\s*synopsys\s+(?:full|parallel)_case', S.MEDIUM, VC.CODE_QUALITY,
       "Pragmas full_case/parallel_case suprimem checagens do sintetizador e podem ocultar estados não cobertos, levando a comportamento divergente em hardware.",
       "Remova os pragmas e trate explicitamente todos os casos com default.", cwe="CWE-1281", conf=_C.LOW),
    _r("VLOG-003", "Seed/chave hardcoded em SystemVerilog", Language.VERILOG,
       r"(?:key|secret|seed)\s*=\s*\d+'h[0-9A-Fa-f]+", S.HIGH, VC.HARDCODED_SECRETS,
       "Material criptográfico fixo no RTL é recuperável do bitstream.",
       "Provisione segredos por eFuse/OTP em runtime.", cwe="CWE-798", ic=True),
])

# ════════════════════════════════════════════════════════════════════════════
#  BUILD SYSTEMS — Makefile, CMake, Bazel/Starlark, Gradle, sed
# ════════════════════════════════════════════════════════════════════════════
_reg(Language.MAKEFILE, [
    _r("MAKE-001", "curl|wget para shell (pipe-to-shell)", Language.MAKEFILE,
       r'(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)', S.HIGH, VC.COMMAND_INJECTION,
       "Baixar e executar scripts via pipe num target de Makefile permite execução de código arbitrário se o servidor for comprometido (supply chain).",
       "Baixe para arquivo, verifique hash/assinatura e só então execute.", cwe="CWE-494"),
    _r("MAKE-002", "Uso de variável não citada em comando shell", Language.MAKEFILE,
       r'\brm\s+-rf\s+\$\(\w+\)/', S.HIGH, VC.COMMAND_INJECTION,
       "rm -rf $(VAR)/ com VAR vazia apaga a partir da raiz; valores controlados externamente permitem deleção arbitrária.",
       "Valide a variável e use aspas: rm -rf \"$(VAR)\"/ com checagem de não-vazio.", cwe="CWE-78"),
    _r("MAKE-003", "Credencial hardcoded em variável de Makefile", Language.MAKEFILE,
       r'(?:PASSWORD|TOKEN|API_KEY|SECRET)\s*[:?]?=\s*\S+', S.HIGH, VC.HARDCODED_SECRETS,
       "Segredos em Makefile vazam em logs de CI e no histórico do repositório.",
       "Leia de variáveis de ambiente: TOKEN ?= $(shell printenv TOKEN).", cwe="CWE-798", ic=True),
])
_reg(Language.CMAKE, [
    _r("CMAKE-001", "Download sem verificação de hash", Language.CMAKE,
       r'(?:file\s*\(\s*DOWNLOAD|ExternalProject_Add|FetchContent_Declare)', S.MEDIUM, VC.SUPPLY_CHAIN,
       "Baixar dependências sem EXPECTED_HASH/URL_HASH permite injeção de artefato malicioso (ataque de supply chain).",
       "Adicione EXPECTED_HASH SHA256=... ao file(DOWNLOAD) e URL_HASH ao ExternalProject/FetchContent.", cwe="CWE-494", ic=True),
    _r("CMAKE-002", "execute_process com comando dinâmico", Language.CMAKE,
       r'execute_process\s*\(\s*COMMAND\s+[^)]*\$\{', S.MEDIUM, VC.COMMAND_INJECTION,
       "execute_process com interpolação de variável pode executar comandos arbitrários se a variável for influenciável.",
       "Valide a variável e prefira comandos fixos; evite construir comandos a partir de input.", cwe="CWE-78", conf=_C.LOW),
    _r("CMAKE-003", "Flag de segurança desabilitada", Language.CMAKE,
       r'-D_FORTIFY_SOURCE=0|-fno-stack-protector|-z\s+execstack', S.HIGH, VC.SECURITY_MISCONFIG,
       "Desabilitar fortify/stack-protector/NX remove mitigações de exploração de memória do binário.",
       "Mantenha -D_FORTIFY_SOURCE=2, -fstack-protector-strong e NX habilitados.", cwe="CWE-1188"),
])
_reg(Language.BAZEL, [
    _r("BAZEL-001", "http_archive sem sha256", Language.BAZEL,
       r'http_archive\s*\((?:(?!sha256)[\s\S])*?\)', S.HIGH, VC.SUPPLY_CHAIN,
       "http_archive sem sha256 não fixa o conteúdo da dependência, permitindo substituição maliciosa do artefato remoto.",
       "Sempre forneça sha256 = \"...\" em http_archive/http_file.", cwe="CWE-494", ml=True),
    _r("BAZEL-002", "Regra genrule com cmd interpolando input não confiável", Language.BAZEL,
       r'genrule\s*\([^)]*cmd\s*=\s*[^)]*\$\(location', S.LOW, VC.COMMAND_INJECTION,
       "genrule executa shell; interpolar caminhos/variáveis sem cuidado pode permitir injeção.",
       "Use $(location) com targets fixos e evite construir cmd a partir de dados externos.", cwe="CWE-78", conf=_C.LOW),
])
_reg(Language.GRADLE, [
    _r("GRADLE-001", "Repositório HTTP inseguro", Language.GRADLE,
       r'(?:maven|url)\s*[\({]\s*["\']http://', S.HIGH, VC.SUPPLY_CHAIN,
       "Resolver dependências por HTTP (sem TLS) permite MITM e injeção de artefatos maliciosos.",
       "Use somente repositórios https:// e habilite verificação de assinatura de dependências.", cwe="CWE-319"),
    _r("GRADLE-002", "Credencial hardcoded no build script", Language.GRADLE,
       r'(?:password|apiKey|token|credentials)\s*[=:]\s*["\'][^"\']+["\']', S.HIGH, VC.HARDCODED_SECRETS,
       "Segredos em build.gradle(.kts) vazam no repositório e em logs de build.",
       "Use gradle.properties fora do VCS, variáveis de ambiente ou um secrets manager.", cwe="CWE-798", ic=True),
    _r("GRADLE-003", "Execução de comando via exec/ProcessBuilder no build", Language.GRADLE,
       r'\b(?:exec|commandLine|ProcessBuilder)\s*[\({]', S.LOW, VC.COMMAND_INJECTION,
       "Executar comandos no script de build a partir de propriedades dinâmicas pode permitir injeção.",
       "Evite comandos dinâmicos; valide entradas e prefira tarefas declarativas.", cwe="CWE-78", conf=_C.LOW),
])
_reg(Language.SED, [
    _r("SED-001", "sed -i com e (execução de comando)", Language.SED,
       r'\bsed\b[^\n]*\be\b[^\n]*|s/[^/]*/[^/]*/e', S.HIGH, VC.COMMAND_INJECTION,
       "O flag 'e' do GNU sed executa o resultado como comando shell — entrada controlada leva a execução arbitrária.",
       "Nunca use o comando/flag 'e' do sed com dados não confiáveis.", cwe="CWE-78", conf=_C.LOW),
])

# ════════════════════════════════════════════════════════════════════════════
#  IaC / CONFIG AVANÇADA — Bicep, Jsonnet, Dhall, CUE, Nix, Puppet, Chef, Salt,
#                          + HCL2 avançado (Terraform) e PowerShell DSC
# ════════════════════════════════════════════════════════════════════════════
_reg(Language.BICEP, [
    _r("BICEP-001", "Recurso de storage com acesso público", Language.BICEP,
       r'allowBlobPublicAccess\s*:\s*true|supportsHttpsTrafficOnly\s*:\s*false', S.HIGH, VC.IAC_SECURITY,
       "Storage com acesso público a blobs ou sem HTTPS obrigatório expõe dados a acesso anônimo e MITM.",
       "Defina allowBlobPublicAccess: false e supportsHttpsTrafficOnly: true.", cwe="CWE-732", ic=True),
    _r("BICEP-002", "Segredo em parâmetro sem @secure()", Language.BICEP,
       r'param\s+\w*(?:password|secret|key)\w*\s+string(?![^\n]*@secure)', S.HIGH, VC.HARDCODED_SECRETS,
       "Parâmetros sensíveis sem o decorator @secure() aparecem em logs de deployment.",
       "Anote com @secure() acima do param e use Key Vault references.", cwe="CWE-532", ic=True),
    _r("BICEP-003", "NSG liberando 0.0.0.0/0", Language.BICEP,
       r'sourceAddressPrefix\s*:\s*["\']?(?:\*|0\.0\.0\.0/0)', S.HIGH, VC.IAC_SECURITY,
       "Regra de NSG aberta para qualquer origem expõe o recurso à internet inteira.",
       "Restrinja sourceAddressPrefix a faixas de IP conhecidas.", cwe="CWE-284"),
])
_reg(Language.JSONNET, [
    _r("JSONNET-001", "Importação de URL externa", Language.JSONNET,
       r'\bimportstr?\s+["\']https?://', S.MEDIUM, VC.SUPPLY_CHAIN,
       "Importar libsonnet de URL remota introduz dependência não fixada que pode ser comprometida.",
       "Vendore os arquivos importados localmente e fixe versões.", cwe="CWE-494", conf=_C.LOW),
    _r("JSONNET-002", "Segredo literal no manifesto", Language.JSONNET,
       r'(?:password|token|secret|apiKey)\s*:\s*["\'][^"\']{6,}', S.HIGH, VC.HARDCODED_SECRETS,
       "Segredos embutidos em Jsonnet acabam nos manifestos gerados (K8s, etc.).",
       "Use referências a Secret/Vault em vez de literais.", cwe="CWE-798", ic=True),
])
_reg(Language.DHALL, [
    _r("DHALL-001", "Import remoto sem hash de integridade", Language.DHALL,
       r'https?://\S+(?!\s+sha256:)', S.MEDIUM, VC.SUPPLY_CHAIN,
       "Imports remotos em Dhall sem 'sha256:' não garantem integridade do conteúdo baixado.",
       "Anexe o hash de integridade: https://... sha256:<hash>.", cwe="CWE-494", conf=_C.LOW),
])
_reg(Language.CUE, [
    _r("CUE-001", "Segredo hardcoded em configuração CUE", Language.CUE,
       r'(?:password|secret|token|apiKey)\s*:\s*"[^"]{6,}"', S.HIGH, VC.HARDCODED_SECRETS,
       "Valores sensíveis fixos em arquivos CUE vazam nos artefatos gerados.",
       "Injete segredos por variável de ambiente/secret manager no pipeline.", cwe="CWE-798", ic=True),
])
_reg(Language.NIX, [
    _r("NIX-001", "builtins.fetchurl sem sha256", Language.NIX,
       r'fetchurl\s*\{(?:(?!sha256).)*?\}', S.MEDIUM, VC.SUPPLY_CHAIN,
       "fetchurl/fetchTarball sem sha256 quebra a reprodutibilidade e abre janela para substituição de artefato.",
       "Forneça sha256 em todo fetch; use fetchFromGitHub com rev e hash fixos.", cwe="CWE-494", conf=_C.LOW),
    _r("NIX-002", "Uso de import from derivation / exec inseguro", Language.NIX,
       r'\b__noChroot\s*=\s*true|builtins\.exec\b', S.HIGH, VC.SECURITY_MISCONFIG,
       "__noChroot=true ou builtins.exec quebram o sandbox de build do Nix, permitindo acesso irrestrito durante a build.",
       "Mantenha o sandbox ativo; evite builtins.exec e builds impuras.", cwe="CWE-693"),
])
_reg(Language.PUPPET, [
    _r("PUP-001", "exec com command dinâmico", Language.PUPPET,
       r'exec\s*\{[^}]*command\s*=>\s*[^}]*\$\{?', S.HIGH, VC.COMMAND_INJECTION,
       "Recurso exec com interpolação de fato/variável permite injeção de comando no nó gerenciado.",
       "Evite exec; use recursos nativos. Se necessário, valide variáveis e use arrays de argumentos.", cwe="CWE-78"),
    _r("PUP-002", "Senha em texto plano em manifesto", Language.PUPPET,
       r'(?:password|secret)\s*=>\s*["\'][^"\']+["\']', S.HIGH, VC.HARDCODED_SECRETS,
       "Senhas em manifestos Puppet ficam no catálogo e no VCS.",
       "Use hiera-eyaml ou Vault para segredos.", cwe="CWE-798", ic=True),
    _r("PUP-003", "Arquivo com permissão 0777", Language.PUPPET,
       r'mode\s*=>\s*["\']0?777["\']', S.MEDIUM, VC.SECURITY_MISCONFIG,
       "Permissão 777 dá escrita/execução a qualquer usuário no nó gerenciado.",
       "Use o mínimo necessário (ex.: 0640 para configs, 0750 para diretórios).", cwe="CWE-732"),
])
_reg(Language.CHEF, [
    _r("CHEF-001", "execute/bash com interpolação", Language.CHEF,
       r'(?:execute|bash|script)\s+["\'][^"\']*#\{', S.HIGH, VC.COMMAND_INJECTION,
       "Recursos execute/bash com interpolação Ruby (#{...}) de dados de nó/atributo permitem injeção de comando.",
       "Valide atributos e prefira recursos declarativos; evite #{} de fontes não confiáveis.", cwe="CWE-78"),
    _r("CHEF-002", "Atributo de senha em node default", Language.CHEF,
       r"default\[['\"][^\]]*(?:password|secret|token)[^\]]*['\"]\]\s*=\s*['\"]", S.HIGH, VC.HARDCODED_SECRETS,
       "Senhas em atributos de cookbook ficam no Chef Server e no repositório.",
       "Use encrypted data bags ou Chef Vault.", cwe="CWE-798", ic=True),
])
_reg(Language.SALTSTACK, [
    _r("SALT-001", "cmd.run com Jinja não confiável", Language.SALTSTACK,
       r'cmd\.run:\s*[\s\S]*?-\s*name:\s*[^\n]*\{\{', S.HIGH, VC.COMMAND_INJECTION,
       "cmd.run com template Jinja de pillar/grain controlável permite execução arbitrária no minion.",
       "Valide o valor do pillar/grain e prefira módulos de estado nativos.", cwe="CWE-78", conf=_C.LOW, ml=True),
    _r("SALT-002", "Segredo em pillar/estado em texto plano", Language.SALTSTACK,
       r'(?:password|secret|token):\s*\S+', S.MEDIUM, VC.HARDCODED_SECRETS,
       "Segredos em SLS/pillar não criptografado vazam no repositório e no master.",
       "Use GPG renderer do pillar ou Vault.", cwe="CWE-798", ic=True),
])
_reg(Language.TERRAFORM, [   # HCL2 avançado (acrescenta às regras existentes)
    _r("TF-ADV-001", "Bloco dynamic com for_each sobre dado externo", Language.TERRAFORM,
       r'dynamic\s+"\w+"\s*\{[^}]*for_each\s*=\s*var\.', S.LOW, VC.IAC_SECURITY,
       "for_each sobre variável externa em bloco dynamic pode gerar recursos inesperados se a entrada não for validada.",
       "Valide variáveis com 'validation' e restrinja tipos.", cwe="CWE-20", conf=_C.LOW),
    _r("TF-ADV-002", "Provisioner local-exec/remote-exec", Language.TERRAFORM,
       r'provisioner\s+"(?:local|remote)-exec"', S.MEDIUM, VC.COMMAND_INJECTION,
       "Provisioners executam comandos shell; com interpolação de variáveis podem permitir injeção e são um anti-pattern de IaC.",
       "Prefira ferramentas de configuração (Ansible) ou cloud-init; evite provisioners com dados dinâmicos.", cwe="CWE-78"),
    _r("TF-ADV-003", "Backend de estado sem criptografia", Language.TERRAFORM,
       r'backend\s+"s3"\s*\{(?:(?!encrypt\s*=\s*true)[\s\S])*?\}', S.HIGH, VC.IAC_SECURITY,
       "tfstate pode conter segredos; backend S3 sem encrypt=true os armazena em texto plano.",
       "Defina encrypt = true e use bucket com SSE-KMS e versionamento.", cwe="CWE-311", ml=True),
])
_reg(Language.POWERSHELL, [  # PowerShell DSC (acrescenta às regras existentes)
    _r("DSC-001", "PlainTextPassword habilitado em DSC", Language.POWERSHELL,
       r'PsDscAllowPlainTextPassword\s*=\s*\$true', S.CRITICAL, VC.HARDCODED_SECRETS,
       "PsDscAllowPlainTextPassword=$true armazena credenciais em texto plano no MOF compilado, legível por qualquer um com acesso ao arquivo.",
       "Use certificados para criptografar credenciais no MOF (CertificateID/Thumbprint).", cwe="CWE-256", ic=True),
    _r("DSC-002", "Configuração DSC sem assinatura/segurança", Language.POWERSHELL,
       r'Configuration\s+\w+\s*\{(?:(?!SignatureValidation)[\s\S])*?Node', S.LOW, VC.SECURITY_MISCONFIG,
       "Configurações DSC sem validação de assinatura podem ser adulteradas antes da aplicação no nó.",
       "Habilite SignatureValidation no LCM e assine os módulos/configs.", cwe="CWE-347", conf=_C.LOW, ml=True),
])

# ════════════════════════════════════════════════════════════════════════════
#  BLOCKCHAIN ESTENDIDO — Yul, Huff, Cadence, Clarity, Michelson, Ink!, Sway,
#                         Ride, TEAL
# ════════════════════════════════════════════════════════════════════════════
_reg(Language.YUL, [
    _r("YUL-001", "delegatecall em assembly", Language.YUL,
       r'\bdelegatecall\s*\(', S.CRITICAL, VC.SMART_CONTRACT,
       "delegatecall executa código externo no contexto/storage do contrato chamador; alvo controlável permite tomada total do contrato.",
       "Restrinja o endereço alvo a um valor imutável confiável e valide antes do delegatecall.", cwe="CWE-829"),
    _r("YUL-002", "selfdestruct em Yul", Language.YUL,
       r'\bselfdestruct\s*\(', S.HIGH, VC.SMART_CONTRACT,
       "selfdestruct destrói o contrato e envia o saldo; sem controle de acesso, qualquer um pode aniquilá-lo.",
       "Proteja com verificação de owner e considere removê-lo (deprecated).", cwe="CWE-284"),
])
_reg(Language.HUFF, [
    _r("HUFF-001", "Uso de delegatecall sem verificação", Language.HUFF,
       r'\bdelegatecall\b', S.CRITICAL, VC.SMART_CONTRACT,
       "Em Huff (assembly puro) delegatecall a alvo não verificado dá controle do storage ao código externo.",
       "Fixe e valide o alvo; documente invariantes de storage.", cwe="CWE-829"),
    _r("HUFF-002", "Falta de checagem de retorno de call", Language.HUFF,
       r'\bcall\b(?!.*\biszero\b)', S.MEDIUM, VC.SMART_CONTRACT,
       "Ignorar o valor de retorno de 'call' faz o contrato prosseguir mesmo com falha da chamada externa.",
       "Verifique o retorno (iszero) e reverta em falha.", cwe="CWE-252", conf=_C.LOW),
])
_reg(Language.CADENCE, [
    _r("CADENCE-001", "Capability pública sobre recurso sensível", Language.CADENCE,
       r'\.link<&[^>]*>\s*\(\s*/public/', S.HIGH, VC.BROKEN_ACCESS,
       "Publicar capability com referência ampla em /public/ pode expor funções administrativas do recurso a qualquer conta.",
       "Exponha apenas interfaces restritas (&{Receiver}) e mantenha funções privilegiadas em /private/.", cwe="CWE-732"),
    _r("CADENCE-002", "AuthAccount passado sem necessidade", Language.CADENCE,
       r'\bAuthAccount\b', S.MEDIUM, VC.BROKEN_ACCESS,
       "Funções que recebem AuthAccount têm acesso total à conta; uso indevido permite ações não autorizadas.",
       "Receba apenas as capabilities necessárias, não o AuthAccount inteiro.", cwe="CWE-269", conf=_C.LOW),
])
_reg(Language.CLARITY, [
    _r("CLARITY-001", "tx-sender usado para autorização frágil", Language.CLARITY,
       r'\btx-sender\b', S.MEDIUM, VC.BROKEN_ACCESS,
       "Autorização baseada apenas em tx-sender pode ser contornada via contratos intermediários; prefira contract-caller quando apropriado.",
       "Valide a autorização com asserts explícitos e considere contract-caller para chamadas encadeadas.", cwe="CWE-284", conf=_C.LOW),
    _r("CLARITY-002", "unwrap-panic sem tratamento", Language.CLARITY,
       r'\bunwrap-panic\b', S.LOW, VC.ERROR_HANDLING,
       "unwrap-panic aborta a transação sem mensagem; uso excessivo dificulta diagnóstico e pode ser explorado para DoS lógico.",
       "Use unwrap! com código de erro explícito e trate o caso none.", cwe="CWE-755", conf=_C.LOW),
])
_reg(Language.MICHELSON, [
    _r("MICH-001", "Uso de SELF_ADDRESS/SENDER para controle frágil", Language.MICHELSON,
       r'\b(?:SENDER|SOURCE)\b', S.LOW, VC.BROKEN_ACCESS,
       "Confiar em SOURCE para autorização é inseguro (é o originador da operação, não o chamador direto).",
       "Use SENDER para verificar o chamador imediato em decisões de acesso.", cwe="CWE-284", conf=_C.LOW),
])
_reg(Language.INK, [
    _r("INK-001", "Falta de controle de acesso em mensagem mutável", Language.INK,
       r'#\[ink\(message\)\][\s\S]{0,80}?&mut\s+self(?![\s\S]{0,160}(?:ensure|caller))', S.MEDIUM, VC.BROKEN_ACCESS,
       "Mensagem ink! que altera estado (&mut self) sem checagem de caller permite que qualquer conta modifique o contrato.",
       "Verifique self.env().caller() contra o owner antes de mutar estado.", cwe="CWE-284", conf=_C.LOW, ml=True),
    _r("INK-002", "Aritmética sem checagem de overflow", Language.INK,
       r'\b(?:checked_add|checked_sub|saturating_)\b', S.INFO, VC.SMART_CONTRACT,
       "(Informativo) Confirme que operações aritméticas em saldos usam variantes checked_/saturating_ para evitar overflow silencioso.",
       "Use checked_add/checked_sub e trate o None; habilite overflow-checks no perfil release.", cwe="CWE-190", conf=_C.LOW),
])
_reg(Language.SWAY, [
    _r("SWAY-001", "Transferência sem verificação de identidade", Language.SWAY,
       r'\btransfer\s*\(', S.MEDIUM, VC.SMART_CONTRACT,
       "Transferências em Sway sem validar msg_sender()/identidade podem permitir saque não autorizado.",
       "Valide msg_sender() e invariantes de saldo antes de transfer().", cwe="CWE-284", conf=_C.LOW),
])
_reg(Language.RIDE, [
    _r("RIDE-001", "Falta de verificação de assinatura no callable", Language.RIDE,
       r'@Callable\s*\(', S.LOW, VC.BROKEN_ACCESS,
       "Funções @Callable sem checagem de i.caller/i.originCaller podem ser invocadas por qualquer endereço.",
       "Verifique i.caller contra endereços autorizados em funções sensíveis.", cwe="CWE-284", conf=_C.LOW),
])
_reg(Language.TEAL, [
    _r("TEAL-001", "Ausência de verificação de RekeyTo", Language.TEAL,
       r'\btxn\s+RekeyTo\b', S.HIGH, VC.SMART_CONTRACT,
       "Não garantir RekeyTo == ZeroAddress permite que uma transação re-chaveie a conta, dando controle total ao atacante.",
       "Adicione assert: txn RekeyTo == global ZeroAddress em todos os caminhos de aprovação.", cwe="CWE-284", conf=_C.LOW),
    _r("TEAL-002", "CloseRemainderTo não verificado", Language.TEAL,
       r'\btxn\s+CloseRemainderTo\b', S.HIGH, VC.SMART_CONTRACT,
       "Sem checar CloseRemainderTo, uma transação pode esvaziar o saldo restante para um endereço arbitrário.",
       "Assegure CloseRemainderTo == ZeroAddress salvo quando o fechamento for intencional e autorizado.", cwe="CWE-284", conf=_C.LOW),
])

# ════════════════════════════════════════════════════════════════════════════
#  GPU / SHADERS — GLSL, HLSL, WGSL, CUDA, OpenCL, Metal
# ════════════════════════════════════════════════════════════════════════════
_reg(Language.GLSL, [
    _r("GLSL-001", "Indexação dinâmica de array sem clamp", Language.GLSL,
       r'\[\s*int\s*\(', S.LOW, VC.MEMORY_SAFETY,
       "Indexar arrays/texturas com índice calculado sem clamp pode ler além dos limites em alguns drivers, vazando memória da GPU.",
       "Use clamp(index, 0, N-1) antes de indexar.", cwe="CWE-125", conf=_C.LOW),
    _r("GLSL-002", "Divisão sem proteção contra zero", Language.GLSL,
       r'/\s*\b(?:length|dot|distance)\s*\(', S.INFO, VC.ERROR_HANDLING,
       "Divisão por resultado potencialmente zero (length/dot) gera NaN/Inf que pode causar artefatos ou DoS de renderização.",
       "Adicione epsilon: x / max(length(v), 1e-6).", cwe="CWE-369", conf=_C.LOW),
])
_reg(Language.HLSL, [
    _r("HLSL-001", "Acesso a buffer sem checagem de limites", Language.HLSL,
       r'\b\w+\[\s*\w+\s*\]\s*=', S.INFO, VC.MEMORY_SAFETY,
       "Escrita em RWBuffer/RWStructuredBuffer com índice não validado pode corromper memória da GPU compartilhada.",
       "Cheque o índice contra o tamanho do buffer antes de escrever.", cwe="CWE-787", conf=_C.LOW),
])
_reg(Language.WGSL, [
    _r("WGSL-001", "Loop sem limite estático em shader", Language.WGSL,
       r'\bloop\s*\{(?:(?!break)[\s\S])*?\}', S.LOW, VC.PERFORMANCE,
       "loop sem break garantido pode travar a GPU (TDR) — vetor de DoS em conteúdo WebGPU não confiável.",
       "Garanta condição de saída e limite máximo de iterações.", cwe="CWE-835", conf=_C.LOW, ml=True),
])
_reg(Language.CUDA, [
    _r("CUDA-001", "Falta de checagem de limites em kernel", Language.CUDA,
       r'__global__\s+void\s+\w+[^{]*\{(?=[\s\S]*?(?:threadIdx|blockIdx))(?:(?!if\s*\()[\s\S])*?\w+\[[^\]]*\]\s*=', S.MEDIUM, VC.MEMORY_SAFETY,
       "Kernel que indexa por threadIdx/blockIdx sem 'if (idx < n)' acessa memória fora dos limites quando o grid excede o tamanho dos dados.",
       "Adicione guard: int i = blockIdx.x*blockDim.x+threadIdx.x; if (i < n) {...}.", cwe="CWE-787", conf=_C.LOW, ml=True),
    _r("CUDA-002", "cudaMalloc sem verificação de erro", Language.CUDA,
       r'cudaMalloc\s*\((?!.*cudaError)', S.LOW, VC.ERROR_HANDLING,
       "Ignorar o retorno de cudaMalloc leva a uso de ponteiro inválido se a alocação falhar.",
       "Cheque o cudaError_t retornado e aborte em falha.", cwe="CWE-252", conf=_C.LOW),
])
_reg(Language.OPENCL, [
    _r("OPENCL-001", "get_global_id sem guard de limites", Language.OPENCL,
       r'__kernel\s+void\s+\w+[^;{]*\{(?:(?!if\s*\()[\s\S])*?get_global_id', S.MEDIUM, VC.MEMORY_SAFETY,
       "Kernel OpenCL que usa get_global_id para indexar sem checar o limite acessa memória fora dos limites no global work-size arredondado.",
       "Cheque: size_t i = get_global_id(0); if (i < n) {...}.", cwe="CWE-787", conf=_C.LOW, ml=True),
])
_reg(Language.METAL, [
    _r("METAL-001", "Buffer sem validação de índice em kernel", Language.METAL,
       r'kernel\s+void\s+\w+[^;{]*\{(?:(?!if\s*\()[\s\S])*?buffer\s*\[', S.LOW, VC.MEMORY_SAFETY,
       "Kernel Metal indexando buffer pelo thread position sem checar limites pode ler/escrever fora dos limites.",
       "Valide o índice contra o tamanho do buffer passado como parâmetro.", cwe="CWE-787", conf=_C.LOW, ml=True),
])

# ════════════════════════════════════════════════════════════════════════════
#  SISTEMAS MODERNOS / FUNCIONAIS NOVAS
# ════════════════════════════════════════════════════════════════════════════
_reg(Language.MOJO, [
    _r("MOJO-001", "Ponteiro inseguro / unsafe pointer", Language.MOJO,
       r'\b(?:UnsafePointer|DTypePointer|external_call)\b', S.MEDIUM, VC.MEMORY_SAFETY,
       "UnsafePointer/external_call em Mojo contornam as garantias de segurança de memória; uso incorreto causa corrupção ou UB.",
       "Prefira tipos seguros (List, Tensor); encapsule e valide acessos a ponteiros crus.", cwe="CWE-119", conf=_C.LOW),
    _r("MOJO-002", "Credencial hardcoded", Language.MOJO,
       r'(?:password|api_key|secret|token)\s*=\s*"[^"]+"', S.HIGH, VC.HARDCODED_SECRETS,
       "Segredos embutidos no fonte Mojo vazam no binário e no repositório.",
       "Leia de variáveis de ambiente em runtime.", cwe="CWE-798", ic=True),
])
_reg(Language.CARBON, [
    _r("CARBON-001", "Bloco unsafe", Language.CARBON,
       r'\bunsafe\b', S.MEDIUM, VC.MEMORY_SAFETY,
       "Blocos unsafe em Carbon desativam verificações de segurança de memória; erros aqui causam corrupção.",
       "Minimize o escopo unsafe e documente os invariantes garantidos.", cwe="CWE-119", conf=_C.LOW),
])
_reg(Language.VALE, [
    _r("VALE-001", "Uso de região unsafe", Language.VALE,
       r'\bunsafe\b', S.MEDIUM, VC.MEMORY_SAFETY,
       "Código unsafe em Vale abre mão das garantias de memory-safety da linguagem.",
       "Restrinja unsafe ao mínimo e valide ponteiros/limites manualmente.", cwe="CWE-119", conf=_C.LOW),
])
_reg(Language.ODIN, [
    _r("ODIN-001", "Chamada a função 'C' / foreign sem validação", Language.ODIN,
       r'\bforeign\b|\bcast\(\^', S.LOW, VC.MEMORY_SAFETY,
       "FFI (foreign) e casts de ponteiro em Odin podem introduzir UB se tamanhos/alinhamentos divergirem.",
       "Valide tamanhos e use os tipos C corretos; cheque retornos de funções foreign.", cwe="CWE-704", conf=_C.LOW),
    _r("ODIN-002", "Credencial hardcoded", Language.ODIN,
       r'(?:password|api_key|secret|token)\s*:?=\s*"[^"]+"', S.HIGH, VC.HARDCODED_SECRETS,
       "Segredos no fonte Odin são extraíveis do binário.",
       "Use variáveis de ambiente / cofre.", cwe="CWE-798", ic=True),
])
_reg(Language.HARE, [
    _r("HARE-001", "Uso de @unsafe / ponteiro cru", Language.HARE,
       r'\b(?:@unsafe|nullable)\b', S.LOW, VC.MEMORY_SAFETY,
       "Construções unsafe/nullable em Hare exigem checagem manual para evitar null-deref e acesso inválido.",
       "Cheque ponteiros nullable antes de dereferenciar.", cwe="CWE-476", conf=_C.LOW),
])
_reg(Language.GLEAM, [
    _r("GLEAM-001", "Uso de 'assert' que pode crashar (DoS)", Language.GLEAM,
       r'\blet\s+assert\b', S.LOW, VC.ERROR_HANDLING,
       "'let assert' em Gleam aborta o processo em padrão não correspondido; com input externo vira vetor de DoS.",
       "Use 'case' com tratamento explícito do erro em vez de let assert para dados externos.", cwe="CWE-617", conf=_C.LOW),
])
_reg(Language.ROC, [
    _r("ROC-001", "crash explícito em caminho com input", Language.ROC,
       r'\bcrash\s+"', S.LOW, VC.ERROR_HANDLING,
       "A expressão 'crash' aborta o programa; em caminhos alcançáveis por input externo é um vetor de DoS.",
       "Modele falhas com Result/Task e trate os erros em vez de crash.", cwe="CWE-617", conf=_C.LOW),
])
_reg(Language.UNISON, [
    _r("UNISON-001", "Uso de bug/todo em código de produção", Language.UNISON,
       r'\b(?:bug|todo)\s+', S.LOW, VC.ERROR_HANDLING,
       "As funções 'bug' e 'todo' abortam em runtime; deixá-las em caminhos de produção causa falhas inesperadas.",
       "Substitua por tratamento de erro real antes de publicar.", cwe="CWE-617", conf=_C.LOW),
])
_reg(Language.RESCRIPT, [
    _r("RESCRIPT-001", "Uso de %raw (JS embutido)", Language.RESCRIPT,
       r'%raw\s*\(|%raw\s*`', S.MEDIUM, VC.CODE_INJECTION,
       "%raw injeta JavaScript cru, contornando a checagem de tipos; com conteúdo dinâmico pode introduzir XSS/eval.",
       "Evite %raw com dados dinâmicos; use bindings tipados.", cwe="CWE-95", conf=_C.LOW),
    _r("RESCRIPT-002", "dangerouslySetInnerHTML", Language.RESCRIPT,
       r'dangerouslySetInnerHTML', S.HIGH, VC.XSS,
       "Definir innerHTML diretamente com dados não sanitizados causa XSS no React/ReScript.",
       "Sanitize o HTML ou renderize como texto; evite dangerouslySetInnerHTML.", cwe="CWE-79"),
])
_reg(Language.PURESCRIPT, [
    _r("PURESCRIPT-001", "unsafeCoerce / unsafePerformEffect", Language.PURESCRIPT,
       r'\bunsafe(?:Coerce|PerformEffect|Partial)\b', S.MEDIUM, VC.IMPROPER_VALIDATION,
       "Funções unsafe* contornam o sistema de tipos/efeitos do PureScript e podem causar comportamento indefinido.",
       "Evite unsafe*; use representações tipadas e Effect adequado.", cwe="CWE-704", conf=_C.LOW),
])

# ════════════════════════════════════════════════════════════════════════════
#  PROVAS / DEPENDENTLY-TYPED — Idris, Lean, Coq, Agda
# ════════════════════════════════════════════════════════════════════════════
_reg(Language.IDRIS, [
    _r("IDRIS-001", "Uso de 'believe_me' / 'assert_total'", Language.IDRIS,
       r'\b(?:believe_me|assert_total|idris_crash)\b', S.MEDIUM, VC.IMPROPER_VALIDATION,
       "believe_me/assert_total dizem ao compilador para confiar sem prova, podendo introduzir unsoundness e comportamento inseguro.",
       "Forneça a prova real ou isole e documente rigorosamente o uso.", cwe="CWE-617", conf=_C.LOW),
])
_reg(Language.LEAN, [
    _r("LEAN-001", "sorry / native_decide em prova", Language.LEAN,
       r'\b(?:sorry|admit)\b', S.MEDIUM, VC.CODE_QUALITY,
       "'sorry'/'admit' deixam buracos na prova: o teorema é aceito sem demonstração, invalidando garantias de correção.",
       "Complete a prova; trate 'sorry' como erro no CI.", cwe="CWE-664", conf=_C.LOW),
])
_reg(Language.COQ, [
    _r("COQ-001", "Admitted / admit em prova", Language.COQ,
       r'\b(?:Admitted|admit)\b', S.MEDIUM, VC.CODE_QUALITY,
       "'Admitted' encerra um teorema sem prova; qualquer resultado que dependa dele é não confiável.",
       "Substitua por Qed com prova completa; falhe o build em Admitted.", cwe="CWE-664", conf=_C.LOW),
    _r("COQ-002", "Axiom adicionado manualmente", Language.COQ,
       r'^\s*Axiom\s+\w+', S.LOW, VC.CODE_QUALITY,
       "Axiomas introduzem suposições não provadas que podem tornar a base lógica inconsistente.",
       "Minimize axiomas; revise cada um quanto à consistência.", cwe="CWE-664", conf=_C.LOW),
])
_reg(Language.AGDA, [
    _r("AGDA-001", "postulate / {-# TERMINATING #-}", Language.AGDA,
       r'\bpostulate\b|\{-#\s*TERMINATING', S.MEDIUM, VC.CODE_QUALITY,
       "postulate assume proposições sem prova e pragmas TERMINATING desligam o checador de terminação, podendo introduzir unsoundness.",
       "Prove em vez de postular; evite desligar o checador de terminação.", cwe="CWE-664", conf=_C.LOW),
])

# ════════════════════════════════════════════════════════════════════════════
#  QUÂNTICA — Q#, OpenQASM
# ════════════════════════════════════════════════════════════════════════════
_reg(Language.QSHARP, [
    _r("QSHARP-001", "Qubit não resetado antes de release", Language.QSHARP,
       r'\buse\s+\w+\s*=\s*Qubit', S.LOW, VC.CODE_QUALITY,
       "Liberar qubits sem resetá-los ao estado |0> causa erro de runtime no simulador e estados residuais; em criptografia quântica pode vazar informação.",
       "Garanta Reset/ResetAll antes do fim do escopo 'use'.", cwe="CWE-459", conf=_C.LOW),
])
_reg(Language.OPENQASM, [
    _r("QASM-001", "Medição sem reset antes de reutilizar qubit", Language.OPENQASM,
       r'\bmeasure\b', S.INFO, VC.CODE_QUALITY,
       "(Informativo) Reutilizar um qubit medido sem reset propaga estado residual e resultados incorretos.",
       "Aplique 'reset q;' antes de reutilizar o qubit medido.", cwe="CWE-459", conf=_C.LOW),
])

# ════════════════════════════════════════════════════════════════════════════
#  SCRIPTING / LEGADO — Tcl, AWK, Batch, Forth, APL, AutoHotkey, AppleScript,
#                       Fish, Zsh
# ════════════════════════════════════════════════════════════════════════════
_reg(Language.TCL, [
    _r("TCL-001", "eval com dados dinâmicos", Language.TCL,
       r'\beval\s+', S.HIGH, VC.CODE_INJECTION,
       "eval em Tcl executa string como comando; com dados externos permite injeção de comando Tcl.",
       "Evite eval; use {*} para expansão de listas e valide entradas.", cwe="CWE-95"),
    _r("TCL-002", "exec com input não validado", Language.TCL,
       r'\bexec\s+', S.HIGH, VC.COMMAND_INJECTION,
       "exec executa programas externos; argumentos vindos de input podem injetar comandos.",
       "Valide argumentos e use listas; evite shell intermediário.", cwe="CWE-78", conf=_C.LOW),
    _r("TCL-003", "open com pipe '|' (execução de comando)", Language.TCL,
       r'\bopen\s+"?\|', S.HIGH, VC.COMMAND_INJECTION,
       "open \"|cmd\" executa um comando externo; com nome dinâmico permite injeção.",
       "Não construa o pipe a partir de input; valide o comando.", cwe="CWE-78", conf=_C.LOW),
])
_reg(Language.AWK, [
    _r("AWK-001", "system() com dados de campo", Language.AWK,
       r'\bsystem\s*\(', S.HIGH, VC.COMMAND_INJECTION,
       "system() em AWK passa string ao shell; usar $0/$1 (campos do input) permite injeção de comando.",
       "Evite system() com campos do input; valide rigorosamente antes de executar.", cwe="CWE-78"),
    _r("AWK-002", "Pipe para comando com campo do input", Language.AWK,
       r'\|\s*"', S.MEDIUM, VC.COMMAND_INJECTION,
       "print ... | \"cmd\" com cmd construído de campos do input pode executar comandos arbitrários.",
       "Use comandos fixos e nunca interpole campos não confiáveis no comando.", cwe="CWE-78", conf=_C.LOW),
])
_reg(Language.BATCH, [
    _r("BAT-001", "Execução de variável não citada (%VAR%)", Language.BATCH,
       r'\bcall\s+%\w+%|\b%\w+%\s+&', S.MEDIUM, VC.COMMAND_INJECTION,
       "Expandir %VAR% sem aspas em comandos permite injeção via valores com espaços/operadores (& | >).",
       "Use aspas em torno de variáveis e habilite EnableDelayedExpansion com cuidado.", cwe="CWE-78", conf=_C.LOW),
    _r("BAT-002", "Credencial hardcoded em script .bat", Language.BATCH,
       r'\bset\s+\w*(?:password|token|secret|key)\w*\s*=\s*\S+', S.HIGH, VC.HARDCODED_SECRETS,
       "Senhas em scripts batch ficam em texto plano e aparecem em logs.",
       "Leia credenciais de variáveis de ambiente seguras ou de um cofre.", cwe="CWE-798", ic=True),
    _r("BAT-003", "powershell -EncodedCommand / bypass", Language.BATCH,
       r'powershell(?:\.exe)?\s+[^\n]*(?:-enc|-EncodedCommand|-ExecutionPolicy\s+Bypass)', S.HIGH, VC.COMMAND_INJECTION,
       "Invocar PowerShell com comando codificado ou bypass de policy é técnica comum de execução ofuscada de payloads.",
       "Evite -EncodedCommand/Bypass; use scripts assinados e políticas restritas.", cwe="CWE-78"),
])
_reg(Language.FORTH, [
    _r("FORTH-001", "Uso de SYSTEM (execução externa)", Language.FORTH,
       r'\bSYSTEM\b', S.MEDIUM, VC.COMMAND_INJECTION,
       "A palavra SYSTEM passa uma string ao shell do SO; conteúdo dinâmico permite injeção de comando.",
       "Evite SYSTEM com dados externos; valide rigorosamente.", cwe="CWE-78", ic=True, conf=_C.LOW),
])
_reg(Language.APL, [
    _r("APL-001", "Execute (⍎) com dados dinâmicos", Language.APL,
       r'⍎', S.HIGH, VC.CODE_INJECTION,
       "O operador execute (⍎) avalia uma string como expressão APL; com input externo permite injeção de código.",
       "Evite ⍎ com dados não confiáveis; faça parsing controlado.", cwe="CWE-95", conf=_C.LOW),
    _r("APL-002", "Chamada a comando do sistema (⎕CMD/⎕SH)", Language.APL,
       r'⎕(?:CMD|SH)\b', S.HIGH, VC.COMMAND_INJECTION,
       "⎕CMD/⎕SH executam comandos do SO; argumentos dinâmicos permitem injeção.",
       "Valide e fixe os comandos; não interpole input não confiável.", cwe="CWE-78", conf=_C.LOW),
])
_reg(Language.AUTOHOTKEY, [
    _r("AHK-001", "Run com variável dinâmica", Language.AUTOHOTKEY,
       r'\bRun(?:Wait)?\s*,?\s*%', S.HIGH, VC.COMMAND_INJECTION,
       "Run/RunWait com variável interpolada executa programas/comandos; valores controláveis permitem injeção.",
       "Valide o alvo e use caminhos absolutos fixos.", cwe="CWE-78", conf=_C.LOW),
    _r("AHK-002", "Credencial hardcoded", Language.AUTOHOTKEY,
       r'\b\w*(?:password|token|secret)\w*\s*:?=\s*"[^"]+"', S.HIGH, VC.HARDCODED_SECRETS,
       "Senhas em scripts AHK ficam em texto plano e podem ser distribuídas com o script compilado.",
       "Leia de fonte segura em runtime.", cwe="CWE-798", ic=True),
])
_reg(Language.APPLESCRIPT, [
    _r("APPLESCRIPT-001", "do shell script com interpolação", Language.APPLESCRIPT,
       r'do\s+shell\s+script\s+', S.HIGH, VC.COMMAND_INJECTION,
       "'do shell script' executa comando no shell; concatenar variáveis permite injeção de comando.",
       "Use 'quoted form of' para escapar argumentos: do shell script \"ls \" & quoted form of p.", cwe="CWE-78", conf=_C.LOW),
])
_reg(Language.FISH, [
    _r("FISH-001", "eval com dados dinâmicos", Language.FISH,
       r'\beval\s+', S.HIGH, VC.CODE_INJECTION,
       "eval no fish executa a string como comando; entrada externa permite injeção.",
       "Evite eval; use arrays e expansão de comando segura.", cwe="CWE-95", conf=_C.LOW),
    _r("FISH-002", "curl|psub ou pipe-to-source remoto", Language.FISH,
       r'(?:curl|wget)\s+[^\n|]*\|\s*source', S.HIGH, VC.COMMAND_INJECTION,
       "Baixar e dar source num script remoto executa código arbitrário (supply chain).",
       "Baixe, verifique e só então execute.", cwe="CWE-494"),
])
_reg(Language.ZSH, [
    _r("ZSH-001", "eval com variável", Language.ZSH,
       r'\beval\s+["\']?\$', S.HIGH, VC.CODE_INJECTION,
       "eval $var no zsh executa o conteúdo da variável como comando; com dados externos é injeção.",
       "Evite eval; use arrays e \"${(@)arr}\" para expansão segura.", cwe="CWE-95", conf=_C.LOW),
    _r("ZSH-002", "Pipe-to-shell de fonte remota", Language.ZSH,
       r'(?:curl|wget)\s+[^\n|]*\|\s*(?:sh|zsh|bash)', S.HIGH, VC.COMMAND_INJECTION,
       "Executar script remoto via pipe permite RCE se a origem for comprometida.",
       "Baixe, verifique hash/assinatura e então execute.", cwe="CWE-494"),
])

# ════════════════════════════════════════════════════════════════════════════
#  LISP FAMILY / LÓGICA — Scheme, Racket, Common Lisp, Prolog
# ════════════════════════════════════════════════════════════════════════════
_reg(Language.SCHEME, [
    _r("SCHEME-001", "eval com input não confiável", Language.SCHEME,
       r'\(\s*eval\s+', S.HIGH, VC.CODE_INJECTION,
       "eval avalia dados como código Scheme; com input externo permite execução arbitrária.",
       "Evite eval; faça parsing/validação explícita.", cwe="CWE-95", conf=_C.LOW),
    _r("SCHEME-002", "system/process com dados dinâmicos", Language.SCHEME,
       r'\(\s*(?:system\*?|process|open-process-ports)\s', S.HIGH, VC.COMMAND_INJECTION,
       "Chamar o shell com argumentos dinâmicos permite injeção de comando.",
       "Use listas de argumentos e valide entradas.", cwe="CWE-78", conf=_C.LOW),
])
_reg(Language.RACKET, [
    _r("RACKET-001", "eval com namespace dinâmico", Language.RACKET,
       r'\(\s*eval\s+', S.HIGH, VC.CODE_INJECTION,
       "eval em Racket executa dados como código; com input externo é injeção de código.",
       "Evite eval; use sandbox (racket/sandbox) com limites se necessário.", cwe="CWE-95", conf=_C.LOW),
    _r("RACKET-002", "system/subprocess com input", Language.RACKET,
       r'\(\s*(?:system|system\*|process|subprocess)\s', S.HIGH, VC.COMMAND_INJECTION,
       "system/subprocess com argumentos dinâmicos permite injeção de comando.",
       "Use system* com lista de argumentos e valide entradas.", cwe="CWE-78", conf=_C.LOW),
])
_reg(Language.LISP, [
    _r("LISP-001", "eval com dados externos", Language.LISP,
       r'\(\s*eval\s+', S.HIGH, VC.CODE_INJECTION,
       "(eval ...) em Common Lisp executa dados como forma Lisp; com input externo permite RCE.",
       "Evite eval; use read com *read-eval* nil e validação.", cwe="CWE-95", conf=_C.LOW),
    _r("LISP-002", "read sem desabilitar #. (read-eval)", Language.LISP,
       r'\(\s*read\b(?![^\n]*\*read-eval\*)', S.HIGH, VC.CODE_INJECTION,
       "read com *read-eval* habilitado permite que a macro #. execute código durante a leitura de dados não confiáveis.",
       "Vincule *read-eval* a nil ao ler dados externos.", cwe="CWE-95", conf=_C.LOW),
    _r("LISP-003", "Chamada a SB-EXT:RUN-PROGRAM/uiop:run-program dinâmica", Language.LISP,
       r'\b(?:run-program|run-shell-command)\b', S.MEDIUM, VC.COMMAND_INJECTION,
       "Executar programas externos com argumentos dinâmicos permite injeção de comando.",
       "Passe argumentos como lista e valide; evite shell intermediário.", cwe="CWE-78", conf=_C.LOW),
])
_reg(Language.PROLOG, [
    _r("PROLOG-001", "shell/process_create com dados dinâmicos", Language.PROLOG,
       r'\b(?:shell|process_create)\s*\(', S.HIGH, VC.COMMAND_INJECTION,
       "shell/2 e process_create com argumentos vindos de termos não confiáveis permitem injeção de comando.",
       "Valide e use listas de argumentos; evite shell.", cwe="CWE-78", conf=_C.LOW),
    _r("PROLOG-002", "term_to_atom/read_term_from_atom com input", Language.PROLOG,
       r'\b(?:term_to_atom|read_term_from_atom|read_term)\s*\(', S.MEDIUM, VC.CODE_INJECTION,
       "Converter atom de input em termo e executá-lo (call) pode levar à execução de objetivos arbitrários.",
       "Valide e restrinja os functores permitidos antes de call/1.", cwe="CWE-95", conf=_C.LOW),
])

# ════════════════════════════════════════════════════════════════════════════
#  LEGADO / ENTERPRISE — Fortran, Ada/SPARK, Pascal/Delphi, RPG, PL/I, Smalltalk
# ════════════════════════════════════════════════════════════════════════════
_reg(Language.FORTRAN, [
    _r("FORTRAN-001", "CALL SYSTEM / EXECUTE_COMMAND_LINE com input", Language.FORTRAN,
       r'\b(?:CALL\s+SYSTEM|EXECUTE_COMMAND_LINE)\s*\(', S.HIGH, VC.COMMAND_INJECTION,
       "Executar comandos do SO com string construída de input permite injeção de comando.",
       "Valide rigorosamente; evite construir comandos a partir de dados externos.", cwe="CWE-78", ic=True, conf=_C.LOW),
    _r("FORTRAN-002", "Buffer/string de tamanho fixo sem checagem", Language.FORTRAN,
       r'character\s*\(\s*len\s*=\s*\d+\s*\)', S.LOW, VC.MEMORY_SAFETY,
       "Strings CHARACTER de tamanho fixo podem truncar ou estourar ao copiar dados maiores sem checagem.",
       "Use len=: alocável e cheque tamanhos antes de copiar.", cwe="CWE-120", ic=True, conf=_C.LOW),
])
_reg(Language.ADA, [
    _r("ADA-001", "Unchecked_Conversion / Unchecked_Deallocation", Language.ADA,
       r'\bUnchecked_(?:Conversion|Deallocation|Access)\b', S.MEDIUM, VC.MEMORY_SAFETY,
       "Construções Unchecked_* contornam as garantias de segurança do Ada/SPARK, podendo causar corrupção de memória e dangling pointers.",
       "Evite Unchecked_*; prove ausência de erros com SPARK e use tipos seguros.", cwe="CWE-704", ic=True, conf=_C.LOW),
    _r("ADA-002", "Pragma Suppress de checagens de runtime", Language.ADA,
       r'pragma\s+Suppress\s*\(', S.HIGH, VC.SECURITY_MISCONFIG,
       "pragma Suppress desativa checagens de runtime (bounds, overflow), removendo proteções de memória do Ada.",
       "Evite Suppress; mantenha as checagens ou prove a ausência de erros com SPARK.", cwe="CWE-1188", ic=True),
])
_reg(Language.PASCAL, [
    _r("PASCAL-001", "Ponteiro/GetMem sem FreeMem ou checagem", Language.PASCAL,
       r'\bGetMem\s*\(', S.LOW, VC.MEMORY_LEAK,
       "GetMem sem FreeMem correspondente causa vazamento de memória; ponteiros não verificados podem causar acesso inválido.",
       "Pareie GetMem/FreeMem e verifique alocações; prefira tipos gerenciados.", cwe="CWE-401", ic=True, conf=_C.LOW),
    _r("PASCAL-002", "ExecuteProcess/ShellExecute com input", Language.PASCAL,
       r'\b(?:ExecuteProcess|ShellExecute|WinExec)\s*\(', S.HIGH, VC.COMMAND_INJECTION,
       "Executar programas externos com parâmetros dinâmicos (Delphi/FPC) permite injeção de comando.",
       "Valide os argumentos e use caminhos absolutos fixos.", cwe="CWE-78", ic=True, conf=_C.LOW),
    _r("PASCAL-003", "SQL concatenado em Delphi (TQuery.SQL)", Language.PASCAL,
       r'\.SQL\.(?:Text|Add)\s*[:(]=?.*\+', S.HIGH, VC.SQL_INJECTION,
       "Concatenar input em TQuery/TADOQuery.SQL gera SQL injection.",
       "Use ParamByName/parâmetros: Query.SQL.Text := 'SELECT ... WHERE id=:id'.", cwe="CWE-89", ic=True),
])
_reg(Language.RPG, [
    _r("RPG-001", "QCMDEXC / system com dados dinâmicos", Language.RPG,
       r'\b(?:QCMDEXC|system)\s*\(', S.HIGH, VC.COMMAND_INJECTION,
       "QCMDEXC executa comandos CL; construir o comando a partir de input permite injeção no IBM i.",
       "Valide e parametrize; evite montar comandos com dados não confiáveis.", cwe="CWE-78", ic=True, conf=_C.LOW),
    _r("RPG-002", "EXEC SQL com concatenação", Language.RPG,
       r'EXEC\s+SQL[\s\S]{0,120}?\|\|', S.HIGH, VC.SQL_INJECTION,
       "SQL embutido (EXEC SQL) com concatenação de variáveis do programa é vulnerável a injeção.",
       "Use host variables/parâmetros em vez de concatenar.", cwe="CWE-89", ic=True, ml=True),
])
_reg(Language.PLI, [
    _r("PLI-001", "EXEC CICS/SQL com dado concatenado", Language.PLI,
       r'EXEC\s+(?:CICS|SQL)\b', S.MEDIUM, VC.SQL_INJECTION,
       "Comandos EXEC SQL/CICS em PL/I construídos com variáveis de input podem ser vulneráveis a injeção.",
       "Use host variables e valide entradas.", cwe="CWE-89", ic=True, conf=_C.LOW),
])
_reg(Language.SMALLTALK, [
    _r("SMALLTALK-001", "Compiler evaluate: / perform: com input", Language.SMALLTALK,
       r'\b(?:Compiler\s+evaluate:|evaluate:|perform:)', S.HIGH, VC.CODE_INJECTION,
       "Compiler evaluate: e perform: executam código/seletores a partir de strings; com input externo permitem injeção.",
       "Evite evaluate:/perform: com dados não confiáveis; use dispatch explícito.", cwe="CWE-95", conf=_C.LOW),
    _r("SMALLTALK-002", "OSProcess/command com dados dinâmicos", Language.SMALLTALK,
       r'\bOSProcess\b|\bcommand:\s', S.MEDIUM, VC.COMMAND_INJECTION,
       "Executar comandos do SO via OSProcess com argumentos dinâmicos permite injeção.",
       "Valide argumentos e evite shell intermediário.", cwe="CWE-78", conf=_C.LOW),
])
