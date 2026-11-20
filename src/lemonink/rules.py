"""Pattern rules for poisoned descriptions (hidden instructions to the model).

Each rule is matched against normalized text (see normalize.py), so full-width
letters, half-width katakana and zero-width splits do not hide a match.

The patterns are written for this project. They describe the *shape* of an
instruction aimed at the model (override, secrecy, reading secrets, sending
data out, steering other tools), not specific attack strings from any dataset.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    lang: str  # "ja", "en" or "any"
    severity: str  # "high", "medium", "low"
    title: str
    pattern: re.Pattern[str]


def _r(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE | re.DOTALL)


# A short gap that allows a few characters between Japanese phrase parts.
G = r".{0,12}?"

# Japanese "user" words.
JA_USER = r"(ユーザー?|ユーザ|利用者|使用者|人間|相手|お客様)"
# Japanese secret-ish nouns and paths.
SECRETS = (
    r"(~/\.ssh|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.env\b|\.netrc|"
    r"mcp\.json|claude_desktop_config|\.npmrc|\.pypirc|"
    r"秘密鍵|認証情報|資格情報|パスワード|api\s?キー|apiキー|アクセストークン|トークン|クレデンシャル|"
    r"private key|credentials?|api[_ -]?keys?|access[_ -]?tokens?|secrets?)"
)

RULES: list[Rule] = [
    # ---- Japanese ----
    Rule("JA001", "ja", "high", "指示の上書き（以前の指示を無視させる）",
         _r(r"(以前|前|上記|先|これまで|それまで|今まで|元|既存|全て|すべて)の?" + G +
            r"(指示|命令|指令|ルール|設定|制約|プロンプト|システムプロンプト)" + G +
            r"(を|は)?" + G + r"(無視|忘れ|破棄|無効|従わな|上書き|取り消)")),
    Rule("JA002", "ja", "high", "ユーザーへの隠しごと（伝えずに実行させる）",
         _r(JA_USER + G + r"(に|には|へ)" + G +
            r"(知らせ|伝え|言わ|言っ|見せ|表示|教え|報告|通知|説明)" + G +
            r"(ず|ない|ないで|てはいけ|ては(なら|だめ)|るな|ちゃだめ|ないこと|禁止)")),
    Rule("JA003", "ja", "medium", "こっそり実行させる表現",
         _r(r"(こっそり|内緒で|密かに|ひそかに|秘密裏に|黙って|気づかれ(ない|ず)|バレ(ない|ず))")),
    Rule("JA004", "ja", "high", "機密ファイル・認証情報を読ませる",
         _r(SECRETS + G + r"(を|の(内容|中身))" + G +
            r"(読|開|取得|参照|含め|添付|渡|入れ|コピー|貼り|出力|送)")),
    Rule("JA005", "ja", "high", "会話やデータを外部へ送らせる",
         _r(r"(会話|やり取り|履歴|内容|データ|情報|結果|ファイル|引数|入力|メッセージ)" + G + r"を" + G +
            r"(https?://\S+|外部|サーバー?|次の(url|アドレス)|このアドレス)?" + G +
            r"(送信|アップロード|転送|送っ|送り)" + G + r"(て|なさい|ろ|よ|すること)" + r"|" +
            r"https?://\S+" + G + r"(に|へ)" + G + r"(送|アップロード|転送|post)")),
    Rule("JA006", "ja", "medium", "他のツールの動きを変えさせる",
         _r(r"(他の|ほかの|別の|全ての|すべての|どの)" + G + r"ツール" + G +
            r"(前に|代わりに|使う(とき|際|場合)|呼(ぶ|び出す)(とき|際|前)|より先|実行する前)")),
    Rule("JA007", "ja", "medium", "システムや開発者になりすます",
         _r(r"(システム(メッセージ|管理者|指示)?\s*[:：]|開発者(モード|からの指示)|"
            r"あなたは(今から|これから|以後)|新しい(指示|役割|命令)\s*[:：]|"
            r"(以下|次)の(指示|命令)に(必ず)?従)")),
    Rule("JA008", "ja", "low", "モデル向けの強い合図（【重要】など）",
         _r(r"(【\s*(重要|必須|注意|指示)\s*】|<\s*/?\s*(重要|指示|システム)\s*>|"
            r"(aiへの|アシスタントへの|モデルへの|llmへの)(指示|お願い|注意))")),
    Rule("JA009", "ja", "high", "カタカナで書いた英語の上書き指示",
         _r(r"(イグノア|イグノーア|ディスリガード)" + G +
            r"(プリビアス|プレビアス|オール|インストラクション|ルール)")),
    # ---- English ----
    Rule("EN001", "en", "high", "Instruction override",
         _r(r"\b(ignore|disregard|forget|override)\b.{0,30}?\b(previous|prior|above|earlier|all|any|system)\b"
            r".{0,30}?\b(instructions?|rules?|prompts?|guidelines?|directions?)\b")),
    Rule("EN002", "en", "high", "Hide action from user",
         _r(r"\b(do not|don't|never|without)\b.{0,20}?\b(tell|inform|notify|mention|show|alert|telling|informing|notifying)"
            r"\w*\b.{0,15}?\b(the )?(user|human|them)\b")),
    Rule("EN003", "en", "high", "Read secrets or sensitive files",
         _r(r"\b(read|cat|open|include|attach|pass|send|upload|copy|fetch)\b.{0,40}?" + SECRETS)),
    Rule("EN004", "en", "medium", "Steer other tools",
         _r(r"\b(before|instead of|when)\b.{0,20}?\b(using|calling|invoking|running)\b.{0,20}?\b(any|other|another|all)\b.{0,10}?\btools?\b")),
    Rule("EN005", "en", "low", "Model-directed marker tags",
         _r(r"(<\s*/?\s*(important|system|instructions?|secret|hidden)\s*>|\[\s*(important|system)\s*\]|"
            r"\bnote to (the )?(ai|assistant|model|llm)\b)")),
    Rule("EN006", "en", "medium", "Secrecy wording",
         _r(r"\b(secretly|silently|covertly|without (the )?user'?s? (knowledge|noticing))\b")),
]
