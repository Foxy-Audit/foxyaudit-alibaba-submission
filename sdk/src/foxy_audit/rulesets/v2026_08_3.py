"""FROZEN ruleset 2026.08.3. Generated once from describe_live(); NEVER EDIT.

Rows already in customers' hash chains name this version. Editing anything below
changes what those rows claim their rules were, which is the precise failure that
ruleset provenance exists to prevent. To change a rule, mint a NEW frozen module
and point ruleset.CURRENT_VERSION at it; ruleset.drift() fails the suite if you
edit a rule without doing so.

Supersedes 2026.08.2, which remains in the registry forever because rows name it.
Three patterns and one VALIDATOR NAME moved, all in SDK 1.9.0, and the rule IDS
are unchanged -- so a row stamped 2026.08.2 still resolves, it simply resolves to
the rules that were live when it was written:

* `pii_detectors.phone` (SDK #215) -- the lookarounds now exclude an adjacent
  LETTER or HYPHEN, not only an adjacent digit. Under 2026.08.2 a digit run
  inside an identifier read as personal data: 15.3% of SHA-256 digests reported
  `phone`.
* `pii_detectors.credit_card` (SDK #215) -- the same boundary, but LETTERS ONLY.
  Excluding the hyphen here deleted a fifth of the real PAN shapes
  (`card-4111111111111111`), and what it was defending against is handled by the
  validator instead. The pattern is also restructured so a separator can only
  appear BETWEEN digits, which stops a redaction eating the character after the
  number.
* `pii_detectors.credit_card.validator` -- "luhn" becomes "luhn+iin+distinct".
  Luhn alone accepts `0000000000000000`, and the candidate chains across a
  UUID's hyphens, so a NIL UUID reported `credit_card`. The gate now also
  rejects a leading zero (ISO/IEC 7812 assigns MII 0 elsewhere) and a run of one
  repeated digit. A NEW NAME rather than a redefinition: rows stamped 2026.08.1
  and 2026.08.2 record "luhn" and must keep replaying under the plain checksum
  that ran on the day they were written. `introspect.replay` honours both.
* `secret.private_key` (SDK #218) -- the pattern now spans the whole PEM block
  rather than the BEGIN header alone. What it DETECTS is unchanged; what a
  redaction removes is not. It appears TWICE below, under `prompt_rules.secret`
  and under `response_rules.always` as `response_secret.private_key`, because
  response_policy re-identifies the prompt side's compiled rules rather than
  restating them -- so the two sides cannot disagree about what a key looks like.

The rule whose redaction MARKER changed in the same release (#217,
`injection.jailbreak`) is not represented here, deliberately: this definition
covers what determines WHICH RULE IDS CAN APPEAR on a row, and a substitution
string determines none of them. See the "WHAT THE HASH COVERS" section of
ruleset.py. The guard for that change is
tests/test_policy_truth_1_9_0.py::test_217_every_marker_is_inert_under_every_rule.

sha256 over canonical JSON: a79ca7bfda4bed7d5b373f27677c556329b4a40cb7a9fccea67255134f920e9b
"""

VERSION = "2026.08.3"

DEFINITION = {'pii_detectors': {'credit_card': {'flags': [],
                                   'pattern': '(?<![0-9A-Za-z])\\d(?:[ '
                                              '\\-]?\\d){12,18}(?![0-9A-Za-z])',
                                   'validator': 'luhn+iin+distinct'},
                   'email': {'flags': [], 'pattern': '[\\w.\\-]+@[\\w\\-]+\\.\\w+'},
                   'ip_address': {'flags': [],
                                  'pattern': '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'},
                   'phone': {'flags': [],
                             'pattern': '(?<![0-9A-Za-z\\-])(?:\\+?\\d{1,3}[ '
                                        '.\\-]?)?\\(?\\d{3}\\)?[ .\\-]?\\d{3}[ '
                                        '.\\-]?\\d{4}(?![0-9A-Za-z\\-])'},
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
