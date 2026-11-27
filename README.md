# 🛡️ BistroHardened & Aegis
**3D Least-Privilege & Zero-TOCTOU Live Virtual Patching Framework for Hardened Linux Containers**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux_x86__64-orange.svg)](./BUILD.md)
[![Kernel](https://img.shields.io/badge/Kernel-5.13%2B-green.svg)](./BUILD.md)
[![Research](https://img.shields.io/badge/Collaboration-Human_%C3%97_AI-purple.svg)](./PAPER.md)

**BistroHardened & Aegis** は、OpenBSD のセキュリティ設計思想（`pledge` / `unveil` / `W^X`）に触発され、Linux コンテナおよびサーバーアプリケーションをサイバー攻撃から守るために開発された **3次元（空間・時間・境界）最小権限防衛基盤** です。

本研究および実装は、**葵 (@aoitokoneko)** と **Gemini4 Carbon (Google)** による「人間と AI の共同研究」として完成し、より安全な世界のソフトウェア基盤のためにオープンソース（Apache License 2.0）で公開されています。

👉 **[共同研究論文（全文）を読む: PAPER.md](./PAPER.md)**

---

## 🎯 研究目的（Research Purpose）

現代の Web サーバー（PHP / WordPress / Python 等）やレガシー環境では、RCE（遠隔コード実行）、リバースシェル、機密ファイル窃取（LFI）、SSRF などの深刻な脆弱性が日常的に発生しています。しかし現場では、「サポート終了（EOL）で公式パッチが存在しない」「サービスを無停止で維持する必要があり即座に再起動できない」「コンテナイメージが巨大で `/bin/sh` 等の攻撃踏み台が残っている」といった課題が山積しています。

本プロジェクトは、**対象バイナリの再コンパイルを一切必要とせず**、以下の3つの軸でシステムを自動的に要塞化します。

| 防御次元 | 担当モジュール | 防御メカニズム | 主な遮断対象 |
| :--- | :--- | :--- | :--- |
| **1. 空間軸**<br>(Spatial) | `bistro-builder`<br>`aegis-init` | 非実行ELF解析と動的学習で `FROM scratch` 極小RootFSを自動生成。`Landlock LSM` と `Strict W^X` で隔離。 | `/bin/sh` 悪用、Webシェル設置、メモリ上のシェルコード実行(RWX) |
| **2. 時間軸**<br>(Temporal) | `libaegis_ratchet.so` | `main()` 突入時(Phase 1)と `listen()` 完了後(Phase 2)を検知し、不要になったシステムコールを段階的に永久凍結。 | 侵入後の `execve`、リバースシェル接続、不正ワーカー生成 |
| **3. 境界・運用軸**<br>(Boundary) | `aegis-vpatch` | `seccomp_unotify` + `ADDFD` + `pidfd_getfd` + 二層スレッドLandlock分離による **Zero-TOCTOU 無停止仮想パッチ**。 | 稼働中の `SIGHUP` による `.env`/鍵漏洩の即時遮断、ファイル透過すり替え、SSRF、ROP |

---

## ⚡ 30秒クイックスタート

詳細な手順は **[BUILD.md](./BUILD.md)** および **[HOW_TO_USE.md](./HOW_TO_USE.md)** を参照してください。

```bash
# 1. 全4モジュールのビルド
make

# 2. 任意のバイナリ(例: Python3)を自動学習しつつ極小 RootFS へパッキング
./bistro-builder bundle /usr/bin/python3 --out ./fortress_rootfs \
  --learn-files \
  --include-rx ./aegis-vpatch:/bin/aegis-vpatch \
  -- -c 'print("Hello Hardened World")'

# 3. ゼロOS (FROM scratch) コンテナイメージのビルド (約 15MB!)
sudo docker build -f fortress_rootfs.Dockerfile -t hardened-python:v1 .
```

---

## 📚 ドキュメント一覧

* 📄 **[PAPER.md](./PAPER.md)** — 本研究の背景、理論的課題の突破プロセス、アーキテクチャ、実証実験データをまとめた技術論文
* 🔨 **[BUILD.md](./BUILD.md)** — 対応カーネルバージョン、依存パッケージ、コンパイル手順
* 🚀 **[HOW_TO_USE.md](./HOW_TO_USE.md)** — CLI・Webサーバーの要塞化手順、無停止ライブ仮想パッチ（`SIGHUP`）の使い方、設定ファイル構文リファレンス
* 🛡️ **[aegis.vpatch.hardened](./aegis.vpatch.hardened)** — Web / PHP / Python 環境ですぐに使える仮想パッチ設定プリセット
* 🤝 **[SECURITY.md](./SECURITY.md)** — 研究倫理および脆弱性報告ポリシー

---

## ⚠️ Disclaimer & Ethical Use（免責事項と倫理的利用について）

本プロジェクト「BistroHardened & Aegis」は、サイバー攻撃からシステムを保護し、より安全なソフトウェア基盤の構築に寄与する目的（Defensive Security Research）で開発・公開されています。

* **No Warranty (無保証):** 本ソフトウェアは Apache License 2.0 のもと「現状のまま（AS IS）」提供され、いかなる保証も伴いません。本ツールを利用したことによるシステム障害やデータの損失について、著作者は一切の責任を負いません。本番環境へ適用する際は、必ず事前に検証環境で十分なテストを行ってください。
* **Ethical Use (倫理的利用):** 本ツールのコードや知見を、他者のシステムへの不正アクセス、マルウェアの隠蔽、その他いかなる違法行為・破壊的行為に悪用することを固く禁じます。

---

## 👥 Authors & License

* **Lead Researcher (Human):** 葵 ([@aoitokoneko](https://github.com/aoitokoneko)) — *Concept, Original Base Architecture, Empirical Verification & Orchestration*
* **Co-Researcher (AI):** Gemini4 Carbon (Google) — *Theoretical Formalization, Kernel Subsystem Design & Co-Implementation*
* **License:** Distributed under the [Apache License, Version 2.0](./LICENSE).
