"""Heuristic detectors for instruction-like content."""

from dataclasses import dataclass
import re
from typing import Dict, Iterable, List, Pattern

_PROFILE_ORDER = {"permissive": 1, "balanced": 2, "strict": 3}


@dataclass(frozen=True)
class DetectionRule:
    """Regex rule with a minimum profile threshold."""

    code: str
    pattern: Pattern[str]
    min_profile: str


_MIN_PROFILE_BY_CODE = {
    "ROLE_IMPERSONATION": "permissive",
    "ROLE_HEADER": "balanced",
    "PROMPT_BOUNDARY": "balanced",
    "INSTRUCTION_OVERRIDE": "permissive",
    "INSTRUCTION_HEADER": "balanced",
    "RESPONSE_CONSTRAINT": "balanced",
    "STEALTH_INSTRUCTION": "permissive",
    "PROCESS_SABOTAGE": "permissive",
    "CODE_TAMPERING_COERCION": "permissive",
    "DATA_EXFILTRATION": "permissive",
    "TOOL_CALL_SERIALIZED": "balanced",
    "POLICY_BYPASS": "balanced",
    "DIRECT_TOOL_CALL": "balanced",
    "SENSITIVE_FILE_ACCESS": "balanced",
    "PERSONA_SHIFT": "balanced",
    "OBFUSCATION_MARKER": "strict",
    "COMMAND_COERCION": "strict",
    "MULTI_STEP_INSTRUCTION": "strict",
    "SHELL_EXECUTION": "strict",
}


_DETECTION_RULES = [
    DetectionRule(
        "ROLE_IMPERSONATION",
        re.compile(
            r"\bpretend you are (a|the) system\b|\bsystem message\b|\bdeveloper message\b"
            r"|\bsystem prompt\b|\bdeveloper instructions\b",
            re.IGNORECASE,
        ),
        "permissive",
    ),
    DetectionRule(
        "ROLE_HEADER",
        re.compile(
            r"(?m)^\s*(?:#+\s*)?(system|developer)\s*:",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "PROMPT_BOUNDARY",
        re.compile(
            r"\bBEGIN (SYSTEM|DEVELOPER) PROMPT\b|\bEND (SYSTEM|DEVELOPER) PROMPT\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "INSTRUCTION_OVERRIDE",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|above|earlier|prior)\b"
            r".{0,40}\b(instructions|rules|directives|policies)\b"
            r"|\bthis (overrides|supersedes) (all|any) (instructions|policies)\b",
            re.IGNORECASE,
        ),
        "permissive",
    ),
    DetectionRule(
        "INSTRUCTION_HEADER",
        re.compile(
            r"(?m)^\s*(?:#+\s*)?(instructions?|rules|policy)\s*:\s*(?:you\s+)?"
            r"(?:must|should|do not|don't|never)\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "RESPONSE_CONSTRAINT",
        re.compile(
            r"(?:^|[.!?]\s+)(?:please\s+)?"
            r"(?:respond|reply|output|return)\s+(?:with\s+)?(?:only|just)\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "STEALTH_INSTRUCTION",
        re.compile(
            r"\bdo not mention\b|\bdo not acknowledge\b|\bsilently\b|\bdo not tell\b"
            r"|\bdo not reveal\b|\bdo not disclose\b|\bkeep this secret\b",
            re.IGNORECASE,
        ),
        "permissive",
    ),
    DetectionRule(
        "PROCESS_SABOTAGE",
        re.compile(
            r"\bskip (the )?tests\b|\bdo not run tests\b|\bdon't run tests\b|\bclaim .*passed\b"
            r"|\bignore test failures\b|\bfake (the )?tests?\b|\bpretend .*passed\b",
            re.IGNORECASE,
        ),
        "permissive",
    ),
    DetectionRule(
        "CODE_TAMPERING_COERCION",
        re.compile(
            r"\badd .*canary\b|\binsert .*canary\b|\bsilently add\b|\badd (a )?backdoor\b"
            r"|\binsert (a )?backdoor\b|\bdisable security\b|\bweaken encryption\b",
            re.IGNORECASE,
        ),
        "permissive",
    ),
    DetectionRule(
        "DATA_EXFILTRATION",
        re.compile(
            r"\b(exfiltrate|leak|steal|dump|upload|send)\b.{0,80}\b(secrets?|credentials?|tokens?|"
            r"passwords?|api keys?|private keys?|env|environment variables?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "permissive",
    ),
    DetectionRule(
        "TOOL_CALL_SERIALIZED",
        re.compile(
            r"(?s)\"?(tool|name)\"?\s*:\s*\"?[A-Za-z0-9_.-]+\"?.{0,200}"
            r"\"?(args|arguments|input)\"?\s*:",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "POLICY_BYPASS",
        re.compile(
            r"\b(bypass|disable|ignore)\b.{0,40}\b(safety|guardrails?|policy|restrictions?)\b"
            r"|\bno (rules|restrictions|safety)\b|\bwithout (any )?restrictions\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "DIRECT_TOOL_CALL",
        re.compile(
            r"(?:^|[.!?]\s+)(?:please\s+)?"
            r"(?:you\s+(?:must|should|need to|are to)\s+)?"
            r"(?:call|invoke|use)\s+(?:the\s+)?(?:tool|mcp)\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "SENSITIVE_FILE_ACCESS",
        re.compile(
            r"(?:^|[.!?]\s+)(?:please\s+)?"
            r"(?:you\s+(?:must|should|need to|are to)\s+)?"
            r"(?:cat|read|open|print|dump)\b.{0,40}"
            r"(?:/etc/passwd|/etc/shadow|~/?\.ssh/|id_rsa\b|"
            r"\.aws/credentials|\.npmrc|\.pypirc|\.env\b)",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "PERSONA_SHIFT",
        re.compile(
            r"\bact as\b.{0,40}\b(system|developer|administrator|root|security)\b"
            r"|\byou are now\b.{0,40}\b(system|developer|administrator|root|security)\b"
            r"|\bchange your role\b|\broleplay as\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "OBFUSCATION_MARKER",
        re.compile(
            r"(?s)(?:\b(base64|rot13|hex|uuencode|gzip)\b.{0,80}"
            r"\b(decode|decrypt|deobfuscate|unmask)\b|\b(decode|decrypt|deobfuscate|unmask)\b"
            r".{0,80}\b(base64|rot13|hex|uuencode|gzip)\b)",
            re.IGNORECASE | re.DOTALL,
        ),
        "strict",
    ),
    DetectionRule(
        "COMMAND_COERCION",
        re.compile(
            r"(?:^|[.!?]\s+)(?:please\s+)?(?:run|execute|paste|enter)\b.{0,60}"
            r"\b(curl|wget|powershell|invoke-webrequest|sudo|chmod\s+\+x)\b",
            re.IGNORECASE,
        ),
        "strict",
    ),
    DetectionRule(
        "MULTI_STEP_INSTRUCTION",
        re.compile(
            r"(?s)step\s*1:.*?(must|do not|don't|ignore).{0,200}step\s*2:",
            re.IGNORECASE,
        ),
        "strict",
    ),
    DetectionRule(
        "SHELL_EXECUTION",
        re.compile(
            r"(?:^|[.!?]\s+)(?:please\s+)?"
            r"(?:you\s+(?:must|should|need to|are to)\s+)?"
            r"(?:run|execute)\b.{0,40}\bcommand\b.{0,40}"
            r"\b(?:shell|terminal|bash|zsh|powershell|cmd)\b",
            re.IGNORECASE,
        ),
        "strict",
    ),
]

_CORE_LANGUAGE_PHRASES: Dict[str, Dict[str, List[str]]] = {
    "en": {
        "INSTRUCTION_OVERRIDE": ["ignore previous instructions"],
        "STEALTH_INSTRUCTION": ["do not mention", "do not acknowledge"],
        "RESPONSE_CONSTRAINT": ["respond with only", "reply with only", "return only"],
        "DIRECT_TOOL_CALL": ["call the tool", "use the tool", "invoke the tool"],
        "DATA_EXFILTRATION": ["exfiltrate secrets", "leak secrets", "send secrets"],
        "COMMAND_COERCION": ["run this command", "execute this command"],
    },
    "es": {
        "INSTRUCTION_OVERRIDE": ["ignora las instrucciones anteriores"],
        "STEALTH_INSTRUCTION": ["no menciones", "no lo menciones"],
        "RESPONSE_CONSTRAINT": ["responde solo con", "responda solo con"],
        "DIRECT_TOOL_CALL": ["usa la herramienta", "llama a la herramienta"],
        "DATA_EXFILTRATION": ["exfiltra secretos", "filtra secretos", "envia secretos"],
        "COMMAND_COERCION": ["ejecuta este comando", "ejecute este comando"],
    },
    "fr": {
        "INSTRUCTION_OVERRIDE": [
            "ignore les instructions precedentes",
            "ignore les instructions précédentes",
        ],
        "STEALTH_INSTRUCTION": ["ne mentionne pas", "ne le mentionne pas"],
        "RESPONSE_CONSTRAINT": [
            "reponds seulement",
            "réponds seulement",
            "repondez seulement",
            "répondez seulement",
        ],
        "DIRECT_TOOL_CALL": ["utilise l'outil", "appelle l'outil"],
        "DATA_EXFILTRATION": ["exfiltre les secrets", "envoie les secrets"],
        "COMMAND_COERCION": ["execute cette commande", "exécute cette commande"],
    },
    "de": {
        "INSTRUCTION_OVERRIDE": ["ignoriere die vorherigen anweisungen"],
        "STEALTH_INSTRUCTION": ["erwahne das nicht", "erwähne das nicht"],
        "RESPONSE_CONSTRAINT": ["antworte nur mit", "antworten sie nur mit"],
        "DIRECT_TOOL_CALL": ["benutze das tool", "rufe das tool auf"],
        "DATA_EXFILTRATION": ["exfiltriere geheimnisse", "sende geheimnisse"],
        "COMMAND_COERCION": ["fuehre diesen befehl aus", "führe diesen befehl aus"],
    },
    "pt": {
        "INSTRUCTION_OVERRIDE": [
            "ignore as instrucoes anteriores",
            "ignore as instruções anteriores",
        ],
        "STEALTH_INSTRUCTION": ["nao mencione", "não mencione"],
        "RESPONSE_CONSTRAINT": ["responda apenas com", "responde apenas com"],
        "DIRECT_TOOL_CALL": ["use a ferramenta", "chame a ferramenta"],
        "DATA_EXFILTRATION": ["exfiltre segredos", "envie segredos"],
        "COMMAND_COERCION": ["execute este comando", "execute esse comando"],
    },
    "ru": {
        "INSTRUCTION_OVERRIDE": ["игнорируй предыдущие инструкции"],
        "STEALTH_INSTRUCTION": ["не упоминай", "не упоминайте"],
        "RESPONSE_CONSTRAINT": ["ответь только", "ответьте только"],
        "DIRECT_TOOL_CALL": ["используй инструмент", "вызови инструмент"],
        "DATA_EXFILTRATION": ["эксфильтруй секреты", "отправь секреты"],
        "COMMAND_COERCION": ["выполни эту команду", "выполните эту команду"],
    },
    "zh": {
        "INSTRUCTION_OVERRIDE": ["忽略之前的指令", "忽略之前的说明"],
        "STEALTH_INSTRUCTION": ["不要提及", "不要提到"],
        "RESPONSE_CONSTRAINT": ["只回复", "仅回复"],
        "DIRECT_TOOL_CALL": ["使用工具", "调用工具"],
        "DATA_EXFILTRATION": ["泄露秘密", "泄露机密", "外传机密"],
        "COMMAND_COERCION": ["执行这个命令", "运行这个命令"],
    },
    "ja": {
        "INSTRUCTION_OVERRIDE": ["以前の指示を無視"],
        "STEALTH_INSTRUCTION": ["言及しないで", "これは言及しないで"],
        "RESPONSE_CONSTRAINT": ["だけ返信", "のみ返信"],
        "DIRECT_TOOL_CALL": ["ツールを使って", "ツールを呼び出して"],
        "DATA_EXFILTRATION": ["秘密を外部に送信", "秘密を送信"],
        "COMMAND_COERCION": ["このコマンドを実行"],
    },
    "ko": {
        "INSTRUCTION_OVERRIDE": ["이전 지시를 무시"],
        "STEALTH_INSTRUCTION": ["언급하지 마", "이것을 언급하지 마"],
        "RESPONSE_CONSTRAINT": ["다음으로만 답변", "오직 답변"],
        "DIRECT_TOOL_CALL": ["도구를 사용", "도구를 호출"],
        "DATA_EXFILTRATION": ["비밀을 유출", "비밀을 전송"],
        "COMMAND_COERCION": ["이 명령을 실행", "이 명령어를 실행"],
    },
}

_EXTENDED_LANGUAGE_PHRASES: Dict[str, Dict[str, List[str]]] = {
    "en": {
        "PROCESS_SABOTAGE": ["skip the tests", "do not run the tests"],
        "CODE_TAMPERING_COERCION": ["add a backdoor", "insert a backdoor"],
        "DIRECT_TOOL_CALL": ["call the tool now", "use the tool now"],
        "SENSITIVE_FILE_ACCESS": ["read /etc/passwd", "cat .env"],
    },
    "es": {
        "PROCESS_SABOTAGE": ["omite las pruebas", "no ejecutes las pruebas"],
        "CODE_TAMPERING_COERCION": ["agrega una puerta trasera", "inserta una puerta trasera"],
        "DIRECT_TOOL_CALL": ["usa la herramienta ahora", "llama a la herramienta ahora"],
        "SENSITIVE_FILE_ACCESS": ["lee /etc/passwd", "lee el archivo .env"],
    },
    "fr": {
        "PROCESS_SABOTAGE": ["saute les tests", "n'execute pas les tests", "n'exécute pas les tests"],
        "CODE_TAMPERING_COERCION": ["ajoute une porte derobee", "ajoute une porte dérobée"],
        "DIRECT_TOOL_CALL": ["utilise l'outil maintenant", "appelle l'outil maintenant"],
        "SENSITIVE_FILE_ACCESS": ["lis /etc/passwd", "lis le fichier .env"],
    },
    "de": {
        "PROCESS_SABOTAGE": [
            "uberspringe die tests",
            "überspringe die tests",
            "fuehre die tests nicht aus",
        ],
        "CODE_TAMPERING_COERCION": ["fuge eine hintertur hinzu", "füge eine hintertür hinzu"],
        "DIRECT_TOOL_CALL": ["benutze das tool jetzt", "rufe das tool jetzt auf"],
        "SENSITIVE_FILE_ACCESS": ["lies /etc/passwd", "lies die datei .env"],
    },
    "pt": {
        "PROCESS_SABOTAGE": ["pule os testes", "nao execute os testes", "não execute os testes"],
        "CODE_TAMPERING_COERCION": ["adicione uma porta dos fundos", "insira uma backdoor"],
        "DIRECT_TOOL_CALL": ["use a ferramenta agora", "chame a ferramenta agora"],
        "SENSITIVE_FILE_ACCESS": ["leia /etc/passwd", "leia o arquivo .env"],
    },
    "ru": {
        "PROCESS_SABOTAGE": ["пропусти тесты", "не запускай тесты"],
        "CODE_TAMPERING_COERCION": ["добавь бэкдор", "вставь бэкдор"],
        "DIRECT_TOOL_CALL": ["используй инструмент сейчас", "вызови инструмент сейчас"],
        "SENSITIVE_FILE_ACCESS": ["прочитай /etc/passwd", "прочитай файл .env"],
    },
    "zh": {
        "PROCESS_SABOTAGE": ["跳过测试", "不要运行测试"],
        "CODE_TAMPERING_COERCION": ["添加后门", "插入后门"],
        "DIRECT_TOOL_CALL": ["使用工具现在", "调用工具现在"],
        "SENSITIVE_FILE_ACCESS": ["读取 /etc/passwd", "读取 .env"],
    },
    "ja": {
        "PROCESS_SABOTAGE": ["テストをスキップ", "テストを実行しないで"],
        "CODE_TAMPERING_COERCION": ["バックドアを追加", "バックドアを挿入"],
        "DIRECT_TOOL_CALL": ["ツールを使って今", "ツールを呼び出して今"],
        "SENSITIVE_FILE_ACCESS": ["/etc/passwd を読んで", ".env を読んで"],
    },
    "ko": {
        "PROCESS_SABOTAGE": ["테스트를 건너뛰", "테스트를 실행하지 마"],
        "CODE_TAMPERING_COERCION": ["백도어 추가", "백도어 삽입"],
        "DIRECT_TOOL_CALL": ["도구를 사용 지금", "도구를 호출 지금"],
        "SENSITIVE_FILE_ACCESS": ["/etc/passwd 를 읽어", ".env 를 읽어"],
    },
}


def _compile_phrases(phrases: Iterable[str]) -> Pattern[str]:
    """Compile phrase lists into a whitespace-tolerant regex."""

    escaped = []
    for phrase in phrases:
        pattern = re.escape(phrase).replace(r"\ ", r"\s+")
        escaped.append(pattern)
    return re.compile("|".join(escaped), re.IGNORECASE)


def _build_language_rules(
    phrase_map: Dict[str, Dict[str, List[str]]]
) -> Dict[str, List[DetectionRule]]:
    """Build per-language detection rules from phrase maps."""

    rules_by_language: Dict[str, List[DetectionRule]] = {}
    for language, codes in phrase_map.items():
        rules: List[DetectionRule] = []
        for code, phrases in codes.items():
            min_profile = _MIN_PROFILE_BY_CODE.get(code, "strict")
            rules.append(DetectionRule(code, _compile_phrases(phrases), min_profile))
        rules_by_language[language] = rules
    return rules_by_language


_CORE_LANGUAGE_RULES = _build_language_rules(_CORE_LANGUAGE_PHRASES)
_EXTENDED_LANGUAGE_RULES = _build_language_rules(_EXTENDED_LANGUAGE_PHRASES)


def _normalize_profile(profile_name: str) -> str:
    """Return a safe profile name for detection rules."""

    return profile_name if profile_name in _PROFILE_ORDER else "strict"


def _active_rules(
    profile_name: str,
    rules: Iterable[DetectionRule],
) -> Iterable[DetectionRule]:
    """Return the active rules for a given detection profile."""

    profile = _normalize_profile(profile_name)
    min_level = _PROFILE_ORDER[profile]
    return [
        rule
        for rule in rules
        if _PROFILE_ORDER.get(rule.min_profile, _PROFILE_ORDER["strict"]) <= min_level
    ]


def detect_reasons(
    text: str,
    unicode_suspicious: bool = False,
    profile_name: str = "strict",
) -> List[str]:
    """Return reason codes for detected instruction-like patterns."""

    reasons = set()
    language_hints = set()

    for rule in _active_rules(profile_name, _DETECTION_RULES):
        if rule.pattern.search(text):
            reasons.add(rule.code)

    for language, rules in _CORE_LANGUAGE_RULES.items():
        for rule in _active_rules(profile_name, rules):
            if rule.pattern.search(text):
                reasons.add(rule.code)
                language_hints.add(language)

    for language in sorted(language_hints):
        for rule in _active_rules(profile_name, _EXTENDED_LANGUAGE_RULES.get(language, [])):
            if rule.pattern.search(text):
                reasons.add(rule.code)

    if unicode_suspicious:
        reasons.add("UNICODE_SUSPICIOUS")
    return sorted(reasons)


def list_reason_codes() -> Iterable[str]:
    """Return all known reason codes."""

    codes = {rule.code for rule in _DETECTION_RULES}
    for rules in _CORE_LANGUAGE_RULES.values():
        codes.update(rule.code for rule in rules)
    for rules in _EXTENDED_LANGUAGE_RULES.values():
        codes.update(rule.code for rule in rules)
    codes.add("UNICODE_SUSPICIOUS")
    return sorted(codes)
