# lemonink

[English](README.md)

> 試作版（v0.0.1）です。ルールと出力の形は変わります。

[MCP（Model Context Protocol）](https://modelcontextprotocol.io) サーバーを手元で検査するツールです。名前はレモン汁で書いた見えない文字（あぶり出し）から来ています。隠れた指示を浮かび上がらせます。**日本語**の攻撃に対応しているのが特長です。

調べること：

- **説明文に仕込まれた指示（ツールポイズニング）**：ツール・引数・プロンプト・リソースの説明文と、サーバーの `instructions` に、モデルへの隠れた指示がないか。日本語と英語の両方。
- **難読化**：全角英字、半角カタカナ、カタカナで書いた英語、ゼロ幅文字、双方向制御文字、Unicode のタグ文字、ラテン文字とキリル文字の混在。照合の前に NFKC で正規化し、正規化して初めて当たったものは「難読化あり」として重大度を1段上げます。
- **広すぎる権限**：シェルの実行、ファイルの書き込み・削除、任意のURLへの通信、制限のない `command`・`path`・`url` 引数、中身と矛盾する注記（シェルを実行するのに `readOnlyHint: true` など）。
- **危ない設定ファイル**：版を固定していない `npx`・`uvx`、平文のトークン、`http://` の接続先、特権コンテナ、ホームやルート全体の指定、`curl | sh`。
- **前回からの変化（rug pull）**：`--save-baseline`・`--baseline` で定義ごとのハッシュを比べます。

## ほかのスキャナーとの違い

1. **日本語に対応**：日本語で書かれた指示や、全角・カタカナで隠した英語は、英語だけのルールでは見逃されます。ルールは [jp-inject](https://github.com/ryoyakubo-ai/jp-inject) で測った日本語の書き換えの型をもとにしています。
2. **完全に手元で動く**：通信しない、LLMを使わない、Python の標準ライブラリ以外に依存しない。サーバーの情報は外に出ません。

## 使い方

```bash
pip install -e .            # Python 3.10 以上
lemonink tools tools_list.json
lemonink config "%APPDATA%\Claude\claude_desktop_config.json"
lemonink config claude_desktop_config.json --connect
lemonink stdio -- npx -y some-server@1.2.3
```

`--connect` と `stdio` は、MCP クライアントと同じように**サーバーのプログラムを実行します**。呼ぶのは `initialize` と `*/list` だけで、ツールは呼びません。信用できないサーバーはサンドボックスやコンテナの中で検査してください。

## 限界

決まった型を探すルールなので、新しい言い回しは見逃し、無害な文に反応することもあります（`【重要】` は普通の日本語でもよく使うので「低」にしています）。何も出なくても安全の証明にはなりません。Streamable HTTP のサーバーにはまだ対応していません。

## ライセンス

Apache-2.0
