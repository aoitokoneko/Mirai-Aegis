# 🚀 How to Use（実践ガイド＆設定リファレンス）

BistroHardened & Aegis は、単発の CLI ツールから常駐型の Web/API サーバーまで、ソースコード無改変で段階的に保護できます。

---

## シナリオ 1：一般バイナリ・スクリプト言語の極小コンテナ化

対象バイナリを実行させながら必要な共有ライブラリ・モジュール・システムコールをワンパスで自動学習し、OS レス（`FROM scratch`）の要塞 RootFS を作ります。

```bash
./bistro-builder bundle /usr/bin/python3 --out ./app_rootfs \
  --learn-files \
  --include-ro ./my_script.py:/app/my_script.py \
  -- ./my_script.py
```

* `--learn-files`: 実行中に `open` / `dlopen` された `.so` や設定ファイルを自動で収集し `/etc/aegis.policy` に最小権限（RX/RO）として登録します。
* `--include-ro <src[:dst]>`: 追加のファイルやディレクトリを読み取り専用（RO）で同梱します。
* `--include-rx <src[:dst]>`: 追加の実行バイナリや `.so` を実行可能（RX）で同梱し、その依存ライブラリも自動解決します。
* `--include-rw <dst_dir>`: 実行権限を持たない書き込み専用作業ディレクトリ（RW）を作成します。

---

## シナリオ 2：Web サーバーの時間軸ラチェット（提案B）＋ 無停止仮想パッチ（提案C）統合運用

常駐型サーバーを保護し、稼働中に無停止でパッチを当てられる4段チェイン構成の手順です。

### Step 1: サーバーの自動境界学習とバンドル
学習時のみ1リクエスト処理して終了するテスト引数（またはバックグラウンドからのヘルスチェック通信）を与え、`--allow-net` と `aegis-vpatch` を同梱してバンドルします。

```bash
./bistro-builder bundle /usr/bin/python3 --out ./web_rootfs \
  --learn-files --allow-net \
  --env PYTHONUNBUFFERED=1 \
  --include-rx ./aegis-vpatch:/bin/aegis-vpatch \
  --include-ro ./app.py:/app/app.py \
  --include-ro ./www:/srv/www \
  -- ./app.py --once

mkdir -p ./web_rootfs/etc/patches
```
※学習中に `listen()` が呼ばれると、`bistro-builder` は自動的に **Phase 2（定常状態）** への遷移を検知し、外向き通信（`PHASE2_FREEZE_NET 1`）や新規プロセス生成（`PHASE2_FREEZE_FORK 1`）の凍結可否を自動判定します。

### Step 2: 4段チェイン Dockerfile の作成と起動
`ENTRYPOINT` の先頭に `/bin/aegis-vpatch` を指定します。パッチ用ディレクトリはホスト側から読み取り専用（`:ro`）でマウントするのがベストプラクティスです（ターゲット自身の Landlock 視界外になるため、**パッチ内容自体がアプリ側から完全秘匿**されます）。

```dockerfile
FROM scratch
COPY ./web_rootfs/ /
USER 65532:65532
ENTRYPOINT ["/bin/aegis-vpatch", "--vpatch", "/etc/patches/aegis.vpatch", "/bin/aegis-init", "/usr/bin/python3", "/app/app.py"]
```

```bash
mkdir -p patches
touch patches/aegis.vpatch
chmod -R a+rX patches

sudo docker build -f web_rootfs.Dockerfile -t hardened-web:v1 .
sudo docker run -d --name my-hardened-srv -p 8080:8080 \
  -v "$(pwd)/patches:/etc/patches:ro" hardened-web:v1
```

### Step 3: 脆弱性発覚時の「ダウンタイム 0秒」ライブ仮想パッチ投入
万が一公開後に機密ファイル露出や設定不備、SSRF 等が発覚した場合は、ホスト側の `patches/aegis.vpatch` を編集し、コンテナに **`SIGHUP`** を送るだけで即座にパッチが適用されます（再ビルドもプロセス再起動も不要です）。

```bash
cat << 'EOF' > patches/aegis.vpatch
VPATCH_PATH_DENY  *.env
VPATCH_PATH_REDIR /srv/www/config.json /etc/patches/safe_config.json
VPATCH_NET_DENY   169.254.169.254:0
EOF

# 無停止ホットリロード実行！
sudo docker kill -s HUP my-hardened-srv

# 適用確認
sudo docker logs my-hardened-srv
```

---

## 📖 `aegis.vpatch` ルール構文リファレンス

| ディレクティブ | 書式 | 動作（すべて Zero-TOCTOU で強制） |
| :--- | :--- | :--- |
| `VPATCH_PATH_DENY` | `VPATCH_PATH_DENY <pattern>` | 完全一致 (`/etc/passwd`)、前方一致 (`/secret/*`)、後方一致 (`*.pem`) に一致する `open`/`openat` を `-EACCES` で遮断 |
| `VPATCH_PATH_REDIR` | `VPATCH_PATH_REDIR <src_pat> <safe_dst>` | `<src_pat>` を開こうとした際、透過的に `<safe_dst>` の FD を注入してすり替え |
| `VPATCH_NET_DENY` | `VPATCH_NET_DENY <IPv4>:<Port>` | 指定 IP/Port への `connect` を遮断 (`0.0.0.0` は全IP、Port `0` は全ポート、`::ffff:` 射影IPv6も自動遮断) |
| `VPATCH_ORIGIN_ONLY` | `VPATCH_ORIGIN_ONLY <nr> <elf_path>` | システムコール番号 `<nr>` の発行元 RIP が `<elf_path>` 以外の VMA (ROP等) であれば `-EPERM` で遮断 |
| `VPATCH_SITE_DENY` | `VPATCH_SITE_DENY <nr> <elf> <start_hex> <end_hex>` | `<elf>` 内の特定ファイルオフセット範囲 `[start, end)` にある脆弱関数からの呼び出しのみをピンポイント遮断 |
| `VPATCH_ARG_DENY` | `VPATCH_ARG_DENY <nr> <arg_idx> <val_hex>` | システムコール `<nr>` の第 `<arg_idx>` 引数 (0〜5) が `<val_hex>` と一致した場合に `-EPERM` で遮断 |
