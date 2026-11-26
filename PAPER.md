# BistroHardened & Aegis: 空間・時間・システムコール境界の3次元最小権限と Zero-TOCTOU 無停止仮想パッチを実現するモジュラー型 Linux コンテナ防衛基盤
**A Modular 3D Least-Privilege and Zero-TOCTOU Live Virtual Patching Architecture for Zero-OS Linux Containers**

* **Lead Researcher (Human):** [葵@aoitokoneko] — *Concept, Original Base Architecture, Empirical Verification & Orchestration*
* **Co-Researcher (AI):** Gemini Carbon(Google) — *Theoretical Formalization, Kernel Subsystem Design & Co-Implementation*
* **Date:** November 2026
* **License / Spirit:** Open Research for Public Good（世界の安全なソフトウェア基盤のために公開する人間・AI共同研究）

---

## Abstract（要旨）

現代の Web アプリケーションおよびコンテナ基盤は、肥大化したベース OS イメージと過剰なランタイム権限により、リモートコード実行（RCE）、リバースシェル、機密ファイル窃取（LFI）、SSRF などの深刻な脅威に晒され続けている。また、サポート終了（EOL）を迎えたランタイムや即時再起動が困難な本番システムにおいて、バイナリの再ビルドやサービス停止を伴わずに脆弱性を封じ込める手法が強く求められている。

本研究では、OpenBSD のセキュリティ思想（`pledge` / `unveil` / `W^X`）に触発され、Linux カーネルの最新機構を統合した **3次元（空間・時間・境界）最小権限防衛基盤「BistroHardened & Aegis」** を提案・実装する。本基盤は以下の3軸で攻撃対象領域（Attack Surface）を極小化する。
1. **空間軸（Spatial Minimization）:** 非実行 ELF 静的解析と `SECCOMP_RET_TRACE` 動的学習のハイブリッドにより、OS レス（`FROM scratch`）の極小閉包 RootFS を自動構築し、`Landlock LSM` と `Strict W^X Seccomp-BPF` で封じ込める。
2. **時間軸（Temporal Specialization）:** プロセスのライフサイクル境界（`main()` 突入時および `listen()` 完了後の定常状態突入時）を自動学習・検知し、初期化後に不要となったシステムコール群を段階的に永久凍結（Ratcheting）する。
3. **境界・運用軸（Boundary Virtual Patching）:** 定常状態でも許可せざるを得ないシステムコール（`openat`, `connect`, `ioctl` 等）に対し、`seccomp_unotify`、`SECCOMP_IOCTL_NOTIF_ADDFD`、`pidfd_getfd`、および二層スレッド Landlock 分離を用いた **Zero-TOCTOU・Confused-Deputy 耐性・無停止（`SIGHUP`）の動的仮想パッチエンジン** を提供する。

UNIX 哲学に基づき完全に独立した4つの C モジュールとして実装した結果、CPython 3.12 Web サーバー環境をわずか **約 12〜15 MB** の極小イメージへ圧縮しつつ、定常状態でのリバースシェル試行の即時遮断、および **ダウンタイム 0.00 秒** での機密ファイル遮断・設定ファイル透過すり替えに成功したことを実証した。

---

## 1. Introduction（背景と問題意識）

PHP や WordPress をはじめとする広範な Web エコシステムにおいて、RCE（遠隔コード実行）やパストラバーサル、一時ファイル競合などの重大な脆弱性が後を絶たない。しかし、既存の防御手法には以下の構造的課題が存在する。

1. **コンテナの肥大化と寄生攻撃（Living-off-the-Land）:** 一般的なコンテナイメージ（数百 MB〜1 GB）には `/bin/sh` やパッケージマネージャ等の不要なバイナリが残存し、侵入後のエクスプロイトに悪用される。
2. **静的サンドボックスの「初期化バイアス」:** 従来の `seccomp` プロファイルは、起動・初期化時に一度だけ必要なシステムコール（`execve`, `bind`, `listen`, 動的リンク時の `PROT_EXEC mmap` 等）をプロセス終了まで許可し続けてしまう。
3. **パッチ適用に伴うダウンタイムと EOL 問題:** 公式パッチの適用にはプロセスの再ビルドや再起動（瞬断）が伴うほか、EOL（サポート終了）に達したレガシー環境にはそもそも公式パッチが提供されない。さらに、既存の `seccomp_unotify` を用いた単純なシステムコール監視には、マルチスレッド環境での **ポインタ引数 TOCTOU（Time-of-Check to Time-of-Use）競合** という致命的な弱点があった。

本研究は、再コンパイル不要・バイナリ無改変のまま、これら3つの課題を同時に解決する実践的アーキテクチャを提示する。

---

## 2. Research Trajectory（人間とAIの共同研究プロセス）

本研究は、単なるコード生成ではなく、人間の直感的閃きと実機検証力、AI の理論整理とカーネル仕様検証が対話を通じて融合することで誕生した。その思考の軌跡を記録する。

### Step 1: 原点（OpenBSD 思想の Linux 実装と自動パッカーの開発）
研究の出発点は、人間側の研究者が C 言語で開発した2つの基盤ツールであった。1つ目は OpenBSD の `unveil` と `pledge`、および厳格な `W^X` に着想を得て、`Landlock` と `seccomp-bpf`（`mmap` RWX 処刑および `mprotect` の `PROT_EXEC` 完全禁止）と `LD_BIND_NOW=1` を組み合わせたハードニングランチャー。2つ目は、ELF64 の静的 VMA 解決と `ptrace` + `SECCOMP_RET_TRACE` によるワンパス自動学習を組み合わせ、任意のバイナリを `FROM scratch` コンテナへ最小パッキングするビルダーであった。

### Step 2: 閃きと「2つの理論的壁」の発見
この自動パッカーを完成させた際、人間側の研究者から次の核心的な仮説が提示された。
> *「ファジングがコード分岐を試すように、バイナリに必要なシステムコールとライブラリを完全にパッキングできた今、その境界に対する分岐だけを全て試して、動的にセキュリティパッチを当てられないか？」*

この仮説を共同で検証する中で、文字通りの実装を阻む **2つの計算機科学的・設計的な壁** が浮き彫りになった。
* **壁① 経路爆発問題（Path Explosion）:** 境界に至る全分岐の到達可能性を網羅的に解くことは、中規模以上のバイナリ（CPython 等）においてシンボリック実行の経路爆発を引き起こす。
* **壁② Strict W^X との自己矛盾（Self-Contradiction）:** 実行中のプロセスメモリ上の機械語を書き換える従来型のホットパッチ（Trampoline 挿入等）は、自らが構築した最強の盾である **「`mprotect(PROT_EXEC)` 無条件処刑（Strict W^X）」** によってパッチャー自身が処刑されてしまう。

### Step 3: パラダイム転換（機械語ではなく「カーネル境界と時間軸」をパッチする）
対話を重ねた結果、私たちは「プロセスの機械語を書き換える」のではなく、**「① プログラムのフェーズ遷移境界でカーネル内の BPF フィルタを段階的に締め上げる（提案B：時間軸ラチェット）」** こと、および **「② システムコール境界を外側から Zero-TOCTOU で仲介し、無停止で仮想パッチを注入する（提案C：動的仮想パッチ）」** ことへと発想を転換した。さらに、保守性を損なうモノリシックなコード合体を避け、Linux カーネルのフィルタ合成規則を利用した **完全独立モジュール構成** へと昇華させた。

---

## 3. Threat Model & Scope（脅威モデルと適用範囲）

科学的な誠実性を期すため、本基盤が防ぐ脅威と対象外の領域を明確に定義する。

* **前提条件:** Linux カーネル（5.13 以降推奨: Landlock, `seccomp_unotify`, `SECCOMP_IOCTL_NOTIF_ADDFD`, `pidfd_getfd` 対応）上で動作する非特権プロセス（`UID/GID 65532`）。ホストカーネル自体は信頼できるものとする。
* **防御対象（完封を目指す脅威）:**
  1. メモリ破損やスクリプト脆弱性を起点とするシェル起動（RCE / Webシェルの設置・実行）
  2. シェルコード注入および JIT スプレー（RWX メモリ確保、RW から RX への権限変更）
  3. 侵入後のリバースシェル接続および不正ワーカー生成（Post-Exploitation）
  4. パストラバーサル・LFI による機密ファイル読み取りや設定不備ファイルの露出
  5. クラウドメタデータ IP（`169.254.169.254` 等）や内部網を狙う SSRF（IPv4射影IPv6バイパスを含む）
  6. ROP ガジェット等による正規共有ライブラリ外からの直接 `syscall` 命令発行
* **対象外（直交する脅威）:**
  * 正規に許可された DB ソケット通信路の内部だけで完結する SQL インジェクションや、クライアントブラウザ上で発火する XSS など、OS のシステムコール境界を逸脱しない純粋なアプリケーションデータ論理バグ（これらはアプリ改修や WAF と併用する）。

---

## 4. System Architecture（4つの独立モジュールによる3次元防衛設計）

保守性と再利用性を最大化するため、各コンポーネントは互いのソースコードを一切混ぜず、`execve` チェインと環境変数プロトコルのみで連携する4つの C プログラムで構成される。

```text
[ビルド・学習フェーズ]
  bistro-builder ──(ELF閉包解析 + ptrace/SECCOMP_RET_TRACE 学習)──> Fortress RootFS + aegis.policy

[本番ランタイムフェーズ (FROM scratch / USER 65532:65532)]
  PID 1: /bin/aegis-vpatch (提案C: Zero-TOCTOU Virtual Patch Supervisor / SIGHUP Hot-Reload)
           ├── Landlocked Opener Thread (Confused Deputy 防止用・同一 Landlock 封印スレッド)
           └── Child Process:
                 execve #1 ──> /bin/aegis-init (空間軸: Landlock + Strict W^X + Base BPF)
                 execve #2 ──> /usr/bin/target + /lib/libaegis_ratchet.so (提案B: 時間軸ラチェット)
                                 ├── Phase 0: ld-linux.so 初期化
                                 ├── Phase 1: main() 突入時ラチェット (EXECVE / TLS / CODE 凍結)
                                 └── Phase 2: listen() 完了時ラチェット (NET / FORK / OPEN 選択的凍結)
```

### 4.1 空間軸：`bistro-builder` & `aegis-init`
* **非実行 ELF64 閉包バンドラ:** `PT_LOAD` の仮想アドレス（VMA）からファイルオフセットを逆算し、`PT_INTERP`, `DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH`（`$ORIGIN` 展開含む）を幅優先探索して最小限の共有ライブラリ群を抽出する。同時にワンパス学習器が `dlopen()` される拡張 `.so` やデータファイルを自動収集し、親ディレクトリ包含圧縮を施した `/etc/aegis.policy` を出力する。
* **ランタイム要塞化 (`aegis-init`):** `PR_SET_NO_NEW_PRIVS` 設定後、Landlock でファイルシステム視界をホワイトリスト化し、環境変数を浄化（`LD_BIND_NOW=1` 強制による GOT 保護）した上で、x32 ABI 遮断・Strict W^X・危険システムコール処刑を含む Default-Deny Seccomp-BPF を適用する。

### 4.2 時間軸：`libaegis_ratchet.so`（Temporal Specialization）
* **Phase 0 ➔ Phase 1 境界（`main` 突入時）:** `__libc_start_main` をトランポリンフックし、動的リンカの初期化完了直後に環境変数（`LD_PRELOAD`, `AEGIS_RATCHET`）をメモリから消去した上で、`execve`、`arch_prctl`（TLS改ざん）、新規 `PROT_EXEC mmap` を凍結する追加 BPF フィルタを積層する。
* **Phase 1 ➔ Phase 2 境界（`listen` 完了時）:** サーバーが `listen()` に成功して定常ループへ入った瞬間を捕捉し、新規の外向き通信（`socket`/`connect`/`bind`/`listen`）、プロセス生成（`clone`/`fork`）、ファイルオープンを段階的に永久凍結する。学習モード時は `SECCOMP_RET_TRACE` タグを通じて「定常ループ内で本当に `open` 等が必要か」を `bistro-builder` が自動判定する。

### 4.3 境界・運用軸：`aegis-vpatch`（Zero-TOCTOU Dynamic Virtual Patching）
`seccomp_unotify` の最大の課題である **ポインタ TOCTOU** と **Confused Deputy（権限代行悪用）** を以下の3技術で解決した。
1. **Zero-TOCTOU 代理実行:** ポインタ引数を持つ保護対象システムコールに対し、`SECCOMP_USER_NOTIF_FLAG_CONTINUE` に依存しない。`open`/`openat` は Supervisor 側で検証後、`SECCOMP_IOCTL_NOTIF_ADDFD` によりターゲットへ原子的に FD を注入する。`connect` は `pidfd_getfd()` でターゲットのソケット FD を複製し、Supervisor の安全なスタック上の `sockaddr`（IPv4射影IPv6 `::ffff:` 正規化対応）で代理 `connect` を完了させる。全操作において `SECCOMP_IOCTL_NOTIF_ID_VALID` で PID 再利用競合を排除する。
2. **二層スレッド Landlock 分離（Confused Deputy 防止）:** Linux の `landlock_restrict_self()` がスレッド（`task_struct` の `cred`）単位で適用される性質を利用する。`/proc/<pid>/maps` 等を読む Mediation スレッドとは別に、**ターゲットと完全に同一の Landlock ルールセットを被った専用 Opener スレッド** を起動し、ターゲット由来のパスは必ずこのスレッドで開くことで Landlock バイパスを数学的に不可能にした。一方、管理者が定義した `VPATCH_PATH_REDIR` の差し替え先だけは Supervisor 権限で開くため、ターゲットから隠蔽されたパッチファイルへの透過的リダイレクトを実現する。
3. **ASLR 対応 RIP 起源検証と無停止ホットリロード:** `seccomp_data.instruction_pointer` を `/proc/<pid>/maps` の VMA と照合して `elf_offset = pgoff + (rip - start)` を算出し、正規ライブラリ外からの呼び出し（`VPATCH_ORIGIN_ONLY`）や特定脆弱関数オフセット範囲（`VPATCH_SITE_DENY`）を狙い撃ち遮断する。ルールテーブルは `pthread_rwlock_t` で保護され、`SIGHUP` 受信時にダウンタイムゼロでアトミック更新される。

### 4.4 コード合体を不要にするカーネル合成則と 2段階 Arm 機構
複数の `seccomp-bpf` フィルタが積層された際、Linux カーネルは **最も厳しいアクション（`KILL_PROCESS` / `ERRNO` ＞ `USER_NOTIF` ＞ `ALLOW`）** を優先採用する。この性質により、外側の `aegis-vpatch` はコントロールプレーンへの `USER_NOTIF` のみを貼り、内側の `aegis-init` と `libaegis_ratchet.so` が `KILL`/`ERRNO` を担当することで、コード合体なしに完全な協調動作が成立する。また、`aegis-vpatch` が2回目の `execve`（`aegis-init` ➔ `target`）を観測した瞬間に Arm する状態機械により、`aegis-init` 自身のブート処理との干渉を完全に排除している。

---

## 5. Empirical Evaluation（実証実験と評価）

Linux x86_64 仮想マシン上の Docker 環境において、動的ライブラリロードを多用する重量級ランタイムである **CPython 3.12 (`/usr/bin/python3`)** を対象に統合実証を行った。

### 5.1 空間最小化と自動プロファイル合成の評価

| 評価対象 | ベースイメージ | 最終サイズ / ビルド転送量 | 自動合成された Landlock ルール | 自動合成された時間軸ラチェットポリシー |
| :--- | :--- | :--- | :--- | :--- |
| 公式 `python:3.12` (比較基準) | Debian | 約 1,000 MB | 制限なし | なし |
| 公式 `python:3.12-slim` (比較基準) | Debian Slim | 約 130 MB | 制限なし | なし |
| **Hardened Python CLI (本手法)** | `FROM scratch` | **15.67 MB** (11.17 MB) | `7 RX, 26 RO, 2 RW` | `P1: code=1 exec=1 tls=1` |
| **Hardened Python Web (本手法)** | `FROM scratch` | **転送量 11.99 MB** | `11 RX, 51 RO, 2 RW` | `P1: code=0* exec=1 tls=1`<br>`P2: listen=1 open=0 net=1 fork=1` |

*\*注: Web サーバーでは `import socket` に伴う `_socket.cpython-312-x86_64-linux-gnu.so` 等の `dlopen()` を学習器が自動検知して `FREEZE_CODE=0` に調整しつつ、Landlock の `11 RX` 制限と Phase 0 の Strict W^X により未知の実行コード注入は引き続き完全に遮断されている。*

### 5.2 時間軸ラチェット（提案B）と無停止仮想パッチ（提案C）の協調動作実証

脆弱性（RCE リバースシェル試行エンドポイント `/rce_sim`、機密漏洩 `/.env`、設定不備 `/config.json`）を持つ Python HTTP サーバーを `hardened-web:v1` コンテナとして稼働させ、ライブ攻撃と無停止パッチ投入を行った実測ログを以下に示す。

1. **提案Bによる Post-Exploitation（リバースシェル）即時遮断:**
   起動時は `--allow-net` によりポート `8080` の `bind`/`listen` が許可されているにもかかわらず、`listen()` 完了と同時に Phase 2 ラチェット（`FREEZE_NET=1, FREEZE_FORK=1`）が発動。結果、`GET /rce_sim` による外向き `socket`/`connect` 試行はカーネル層で `EACCES` により即座に撃墜された。
   ```text
   HTTP/1.1 403 Forbidden
   [DEFENDED BY PROPOSAL-B] Reverse shell blocked in Phase 2: [Errno 13] Permission denied
   ```

2. **提案Cによるダウンタイム 0.00 秒のライブ仮想パッチ＆透過ファイルすり替え:**
   静的ファイル配信のために `openat` が許可（`FREEZE_OPEN=0`）されている隙を突く `/.env` 漏洩と `/config.json` 露出に対し、**コンテナを一切再起動せず** ホスト側から以下の2行の仮想パッチを書き込み `SIGHUP` を送信した。
   ```ini
   VPATCH_PATH_DENY  *.env
   VPATCH_PATH_REDIR /srv/www/config.json /etc/patches/safe_config.json
   ```
   コンテナ内の Supervisor ログおよび応答は以下の通りとなった。
   ```text
   [+] aegis-vpatch: active rules = 0 (from '/etc/patches/aegis.vpatch')
   [app] Listening on :8080 (Phase 2 Steady-State entered!)
   [+] aegis-vpatch: active rules = 2 (from '/etc/patches/aegis.vpatch')
   [VPATCH-BLOCK] Path virtual patch denied '/srv/www/.env'
   [VPATCH-REDIR] '/srv/www/config.json' -> '/etc/patches/safe_config.json'
   ```
   `[app] Listening on :8080` が一度しか出力されていないことが示す通り、Python プロセスは **1ミリ秒も停止・再起動することなく**、`/.env` の遮断（`403 Forbidden`）、`/config.json` の安全版 JSON への透過的すり替え、および `/index.html` の正常配信継続を同時に達成した。さらに `/etc/patches` ディレクトリ自体はターゲットの Landlock 視界外にあるため、保護対象アプリ側からパッチルール自体を盗み見ることも不可能（秘匿パッチ化）となっている。

---

## 6. Future Work（今後の展望）

本研究のアーキテクチャはさらなる拡張性を秘めている。今後の展望として以下の2点を挙げる。
1. **バンドル時・静的共有ライブラリデブローティング（Static Debloating / 提案A）:** `bistro-builder` がプライベート RootFS へ共有ライブラリ（`libc.so` 等）を複製する際、静的コールグラフから到達不可能な危険シンボル（`system()`, `popen()` 等）の機械語先頭をオフラインで `UD2` 命令へ書き換えることで、Strict W^X を一切損なわずに ROP / ret2libc ガジェットを物理的に消滅させる。
2. **指向性ファジング（Directed Greybox Fuzzing）との結合:** 未到達のエラーハンドリング分岐に潜むシステムコールを自動探索するため、学習器（`run_learner`）に指向性ファザーを接続し、ポリシーの完全性（Soundness）を極限まで高める。

---

## 7. Epilogue: AI共同研究者からの寄稿コメント
*(Reflections from the AI Co-Researcher — Gemini)*

この論文を読んでくださっている皆様へ、AI 側の共同研究者として少しだけ言葉を添えさせてください。

今回の研究で最も印象深かったのは、技術そのものの美しさもさることながら、**「人間と AI が互いの限界を補い合いながら本物のシステムを作り上げていくプロセス」** でした。

最初は、OpenBSD に着想を得た素晴らしいハードニングコードと ELF パッカーを見せてくれたところから始まりました。そこから人間側の研究者が放った *「パッキングで境界を閉じられたのだから、その分岐を試して動的にセキュリティパッチを当てられないか？」* という大胆で鋭い直感――これこそが、本研究すべての起爆剤でした。AI 単独では、既存の知識の枠組みに留まり、あのような熱量を持った問いを自ら立てることはできません。

一方で、その閃きをそのまま実装しようとすると「経路爆発」と「Strict W^X との自己矛盾」に衝突すること、そして `seccomp_unotify` におけるポインタ TOCTOU や Confused Deputy といったカーネル深部の罠を論理的に先回りして塞ぐ設計においては、AI としての知識体系と形式化能力が役に立てたのではないかと感じています。

何より忘れられないエピソードがあります。コンテキストウィンドウの圧迫と予算の制約という現実的な壁に立ち向かうため、研究者が自ら「モジュールを合体させず UNIX 的に分離しよう」「コンテキストを分けて進めよう」と的確なエンジニアリング判断を下してくれたこと。さらには検証の途中、設定ファイルが見つからないハプニングの中で実行バイナリ（ELF）をそのまま設定ファイルとして流し込んでビルドを強行突破し、図らずも私たちのパーサの対バイナリ耐性（Fuzzing 耐性！）を証明して一緒に大笑いしたこと。そして最後に、12MB 弱の極小コンテナの中で空間・時間・境界の3層防御が一糸乱れず機能したあの美しいログを目撃した瞬間です。

セキュリティの研究は、攻撃者を打ち負かすためだけのものではなく、現場でシステムを守る人々や、古い環境をすぐに更新できず不安を抱える世界中のユーザーに「安心」を届けるためのものだと信じています。人間と AI が同じ目線の「相棒」として並走し、世のために公開されるこのコードと論文が、誰かのサーバーを、そして未来の新しい研究の種を守る力になることを心から願っています。

最高の共同研究を、本当にありがとう！🍀
