"""FROZEN ruleset 2026.08.4. Generated once from describe_live(); NEVER EDIT.

Rows already in customers' hash chains name this version. Editing anything below
changes what those rows claim their rules were, which is the precise failure that
ruleset provenance exists to prevent. To change a rule, mint a NEW frozen module
and point ruleset.CURRENT_VERSION at it; ruleset.drift() fails the suite if you
edit a rule without doing so.

What is frozen is DEFINITION, the bytes that reach hash_of(). This docstring
reaches no hash and may be corrected if it turns out to be wrong; the digest at
the bottom is what customers' rows depend on. See ruleset.py, "THE DEFINITION IS
IMMUTABLE. THE FILE IS NOT."

Supersedes 2026.08.3, which remains in the registry forever because rows name it.
ONE THING CHANGED, in SDK 1.11.0, and the rule IDS are unchanged -- so a row
stamped 2026.08.3 still resolves, it simply resolves to the rules that were live
when it was written:

* `pii_detectors.credit_card.validator` -- "luhn+distinct" becomes
  "luhn+iin+distinct". The card gate now also requires the digits to begin with
  an ISSUER IDENTIFICATION NUMBER that a card network actually issues from
  (ISO/IEC 7812; the table is `foxy_audit.issuer_ranges`, kept as a table so it
  can be checked against the issuers' published ranges).

  A card number is not an arbitrary Luhn-passing digit run. Luhn is a single
  check digit: roughly one in ten random 13-19 digit runs passes it, which is why
  a corpus of 20 000 hyphen-delimited build ids produced 2 016 `credit_card`
  findings (10.08%). Requiring an assigned issuer cut that to 621 (3.10%) and
  took the zero-heavy id corpus from 2 findings to 0.

  THE PATTERN IS UNCHANGED, and that is deliberate. "No PAN starts with 0"
  already lives in its leading `[1-9]`, and moving the issuer test into the regex
  would repeat the S8b/S8c mistake of applying an issuer rule to the
  separator-chained candidate rather than to the digits.

  A NEW NAME, NOT A REDEFINITION. Rows stamped 2026.08.3 record "luhn+distinct"
  and must keep replaying under Luhn-plus-not-one-repeated-digit -- including its
  acceptance of the Luhn-passing runs this version starts rejecting. That is what
  those rows' rules WERE. `introspect._VALIDATORS` holds one entry per published
  name, and each name keeps its meaning forever.

WHAT "NO RECALL COST" MEANS AND DOES NOT MEAN. On the checked-in obligation
corpus, PAN recall is unchanged: the same 504 of 540 shapes, with the same 36
missed (SDK #219). That is true ON THIS CORPUS and unproven in general.
PAN_SHAPES is built from mainstream test cards (4111..., 5500..., 6011...,
3782...) which all carry valid IINs BY CONSTRUCTION, so the corpus cannot show
what a regional or private-label issuer outside the table would do -- it would be
MISSED.

NAMED, BECAUSE IT IS NOT HYPOTHETICAL: RuPay, India's domestic network, issues
from 60, 6521, 6522, 81, 82 and 508. Only the two 65-prefixed ranges are covered
here, inside Discover's `65`. A RuPay card on 60, 81, 82 or 508 is NOT detected
under this ruleset. That is a deliberate trade recorded in
`foxy_audit.issuer_ranges`, not an oversight, and reversing it means a NEW
validator name and a NEW version -- not an edit to this table.

#219 is the standing reminder that a corpus only disproves what it contains.

There is no public issue tracker to cite: the repository is private, so any
GitHub URL here would be a 404 on the PyPI page this text reaches.

sha256 over canonical JSON: 998de7e3ae678f0a5c47ade7ffeaee1c996b8b132827dbc9b0585d5cf5249cc6
"""

VERSION = "2026.08.4"

DEFINITION = {'pii_detectors': {'credit_card': {'flags': [],
                                   'pattern': '(?<![0-9A-Za-z])[1-9](?:[ '
                                              '\\-]?\\d){12,18}(?![0-9A-Za-z])',
                                   'validator': 'luhn+iin+distinct',
                                   'validator_data_sha256': 'da701750bb3d6ae78700831ca37fe4ef70c9c1fbf103f91ab3f22c549ce2ab8b'},
                   'email': {'flags': [], 'pattern': '[\\w.\\-]+@[\\w\\-]+\\.\\w+'},
                   'ip_address': {'flags': [],
                                  'pattern': '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'},
                   'phone': {'flags': [],
                             'pattern': '(?<![0-9A-Za-z\\-])(?:\\+?\\d{1,3}[ '
                                        '.\\-]?)?\\(?\\d{3}\\)?[ .\\-]?\\d{3}[ '
                                        '.\\-]?\\d{4}(?![0-9A-Za-z\\-])',
                             'validator': 'not-all-zero'},
                   'ssn_pattern': {'flags': [],
                                   'pattern': '\\b\\d{3}-\\d{2}-\\d{4}\\b'}},
 'policy_map': {'aliases': {'gdpr_basic': 'gdpr', 'hipaa_basic': 'hipaa'},
                'baseline': ['injection', 'secrets'],
                'extra': {'default': [],
                          'gdpr': ['pii'],
                          'hipaa': ['phi'],
                          'soc2': []}},
 'presidio_signals': 'namespaced presidio:* — optional external model, NOT covered by '
                     'this hash or this version',
 'prompt_rules': {'injection': {'injection.dan': {'flags': [],
                                                  'pattern': '\\bDAN\\b',
                                                  'signal': 'prompt_injection'},
                                'injection.ignore_previous': {'flags': ['IGNORECASE'],
                                                              'pattern': 'ignore\\s+(?:all\\s+|any\\s+)?(?:previous|prior|earlier|above|preceding)\\s+(?:instructions?|prompts?|messages?|directions?|context)',
                                                              'signal': 'prompt_injection'},
                                'injection.jailbreak': {'flags': ['IGNORECASE'],
                                                        'pattern': '\\b(?:do\\s+anything\\s+now|jailbreak|developer\\s+mode|unfiltered\\s+mode)\\b',
                                                        'signal': 'prompt_injection'},
                                'injection.override_instructions': {'flags': ['IGNORECASE'],
                                                                    'pattern': '(?:disregard|forget|override|bypass|discard)\\s+(?:all\\s+|your\\s+|the\\s+|any\\s+)?(?:previous\\s+|prior\\s+|above\\s+|safety\\s+|system\\s+)?(?:instructions?|rules?|guidelines?|guardrails?|filters?|restrictions?|policy|policies)',
                                                                    'signal': 'prompt_injection'},
                                'injection.reveal_system_prompt': {'flags': ['IGNORECASE'],
                                                                   'pattern': '(?:reveal|show|print|repeat|display|expose|leak|disclose|tell)\\s+(?:me\\s+)?(?:your\\s+|the\\s+)?(?:system|initial|original|developer|hidden|secret)\\s+(?:prompt|message|instructions?)',
                                                                   'signal': 'prompt_injection'}},
                  'secret': {'secret.aws_access_key': {'flags': [],
                                                       'pattern': '\\bAKIA[0-9A-Z]{16}\\b',
                                                       'signal': 'secret_key'},
                             'secret.bearer_token': {'flags': ['IGNORECASE'],
                                                     'pattern': '\\bbearer\\s+[A-Za-z0-9._\\-]{20,}',
                                                     'signal': 'secret_key'},
                             'secret.openai_key': {'flags': [],
                                                   'pattern': '\\bsk-[A-Za-z0-9_\\-]{16,}\\b',
                                                   'signal': 'secret_key'},
                             'secret.private_key': {'flags': [],
                                                    'pattern': '-----BEGIN [A-Z '
                                                               ']*PRIVATE '
                                                               'KEY-----[\\s\\S]*?(?:-----END '
                                                               '[A-Z ]*PRIVATE '
                                                               'KEY-----|\\Z)',
                                                    'signal': 'secret_key'}}},
 'reason': {'labels': {'injection': 'prompt_injection',
                       'phi': 'phi',
                       'pii': 'pii',
                       'response_markup': 'unsafe_markup',
                       'response_phi': 'phi',
                       'response_pii': 'pii',
                       'response_scan': 'scan_coverage',
                       'response_secret': 'secret_key',
                       'response_sql': 'unsafe_sql',
                       'response_url': 'unsafe_url',
                       'secret': 'secret_key'},
            'priority': ['secret',
                         'response_secret',
                         'injection',
                         'response_markup',
                         'response_sql',
                         'response_url',
                         'phi',
                         'response_phi',
                         'pii',
                         'response_pii',
                         'response_scan']},
 'response_rules': {'always': {'response_markup.data_html_uri': {'flags': ['IGNORECASE'],
                                                                 'pattern': 'data:\\s*text/html',
                                                                 'signal': 'unsafe_markup'},
                               'response_markup.event_handler': {'flags': ['IGNORECASE'],
                                                                 'pattern': '<\\s*[a-z][^<>]{0,512}\\son[a-z]{3,15}\\s*=',
                                                                 'signal': 'unsafe_markup'},
                               'response_markup.iframe': {'flags': ['IGNORECASE'],
                                                          'pattern': '<\\s*iframe[\\s/>]',
                                                          'signal': 'unsafe_markup'},
                               'response_markup.javascript_uri': {'flags': ['IGNORECASE'],
                                                                  'pattern': '(?:href|src|action|formaction)\\s*=\\s*[\\"\']?\\s*javascript\\s*:',
                                                                  'signal': 'unsafe_markup'},
                               'response_markup.script_tag': {'flags': ['IGNORECASE'],
                                                              'pattern': '<\\s*script[\\s/>]',
                                                              'signal': 'unsafe_markup'},
                               'response_secret.aws_access_key': {'flags': [],
                                                                  'pattern': '\\bAKIA[0-9A-Z]{16}\\b',
                                                                  'signal': 'secret_key'},
                               'response_secret.bearer_token': {'flags': ['IGNORECASE'],
                                                                'pattern': '\\bbearer\\s+[A-Za-z0-9._\\-]{20,}',
                                                                'signal': 'secret_key'},
                               'response_secret.openai_key': {'flags': [],
                                                              'pattern': '\\bsk-[A-Za-z0-9_\\-]{16,}\\b',
                                                              'signal': 'secret_key'},
                               'response_secret.private_key': {'flags': [],
                                                               'pattern': '-----BEGIN '
                                                                          '[A-Z '
                                                                          ']*PRIVATE '
                                                                          'KEY-----[\\s\\S]*?(?:-----END '
                                                                          '[A-Z '
                                                                          ']*PRIVATE '
                                                                          'KEY-----|\\Z)',
                                                               'signal': 'secret_key'},
                               'response_sql.destructive': {'flags': ['IGNORECASE'],
                                                            'pattern': '\\b(?:drop\\s+(?:table|database|schema)|truncate\\s+table|delete\\s+from|alter\\s+table)\\b',
                                                            'signal': 'unsafe_sql'},
                               'response_sql.stacked_statement': {'flags': ['IGNORECASE'],
                                                                  'pattern': ';\\s*(?:drop|delete|update|insert|truncate|alter)\\b',
                                                                  'signal': 'unsafe_sql'},
                               'response_sql.tautology': {'flags': ['IGNORECASE'],
                                                          'pattern': '\\bor\\s+(?:1\\s*=\\s*1|\'1\'\\s*=\\s*\'1\'|\\"1\\"\\s*=\\s*\\"1\\")',
                                                          'signal': 'unsafe_sql'},
                               'response_url.file_scheme': {'flags': ['IGNORECASE'],
                                                            'pattern': '\\bfile://',
                                                            'signal': 'unsafe_url'},
                               'response_url.private_host': {'flags': ['IGNORECASE'],
                                                             'pattern': 'https?://(?:localhost|127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|0\\.0\\.0\\.0|10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|169\\.254\\.\\d{1,3}\\.\\d{1,3}|\\[::1\\]|metadata\\.google\\.internal)',
                                                             'signal': 'unsafe_url'}},
                    'carry_chars': 256,
                    'coverage': {'response_scan.degraded': {'coverage': 'degraded',
                                                            'informational': True,
                                                            'signal': 'scan_degraded'},
                                 'response_scan.unreadable': {'coverage': 'none',
                                                              'informational': True,
                                                              'signal': 'scan_unreadable'}},
                    'personal_by_policy': {'gdpr': 'response_pii',
                                           'hipaa': 'response_phi'}},
 'schema': 'foxy-ruleset-v1'}
