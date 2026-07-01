"""Regras específicas para VBA/VB6 e macros Office, roteadas como VB.NET legado."""
import re
from analyzer.models import Severity,Confidence,Language,VulnCategory
from analyzer.rules.base import Rule
VBA_RULES=[
 Rule("VBA-001","Autoexec de macro Office", "Macros AutoOpen/Document_Open executam ao abrir o documento.",Severity.HIGH,VulnCategory.CODE_INJECTION,Language.VBNET,r'\b(?:Auto_Open|AutoOpen|Document_Open|Workbook_Open)\s*\(',"Desabilite autoexec e assine macros aprovadas.",cwe="CWE-284",confidence=Confidence.HIGH),
 Rule("VBA-002","Execução por WScript.Shell/Shell", "Macro cria shell ou executa comando.",Severity.CRITICAL,VulnCategory.COMMAND_INJECTION,Language.VBNET,r'(?:CreateObject\s*\(\s*"WScript\.Shell"|WScript\.Shell|Shell)\s*(?:\.Run|\()', "Remova execução de comandos e use APIs allowlisted.",cwe="CWE-78",confidence=Confidence.HIGH),
 Rule("VBA-003","Download de payload em macro", "Macro usa XMLHTTP/WinHttp para baixar conteúdo.",Severity.CRITICAL,VulnCategory.SUPPLY_CHAIN,Language.VBNET,r'(?:MSXML2?\.XMLHTTP|WinHttp\.WinHttpRequest|URLDownloadToFile)',"Bloqueie acesso de rede por macros e valide artefatos.",cwe="CWE-494",confidence=Confidence.HIGH),
 Rule("VBA-004","PowerShell invocado por macro", "Macro invoca PowerShell, técnica comum de execução evasiva.",Severity.CRITICAL,VulnCategory.COMMAND_INJECTION,Language.VBNET,r'(?:powershell(?:\.exe)?|pwsh)(?:\s|")', "Remova a invocação e restrinja child processes do Office.",cwe="CWE-78",flags=re.IGNORECASE,confidence=Confidence.HIGH),
 Rule("VBA-005","Acesso ao VBA project object model", "VBProject/VBComponents permite modificar macros dinamicamente.",Severity.HIGH,VulnCategory.CODE_INJECTION,Language.VBNET,r'\b(?:VBProject|VBComponents|CodeModule)\b',"Desabilite Trust access to the VBA project object model.",cwe="CWE-94",confidence=Confidence.HIGH),
 Rule("VBA-006","Ofuscação Chr/StrReverse", "Construção repetida de strings sugere ofuscação de macro.",Severity.MEDIUM,VulnCategory.CODE_QUALITY,Language.VBNET,r'(?:ChrW?\s*\(\s*\d+\s*\)\s*&\s*){3,}|StrReverse\s*\(',"Substitua por código legível e revise o payload.",cwe="CWE-506",confidence=Confidence.MEDIUM),
]
