# 🔨 Build Guide（ビルド要件と手順）

本プロジェクトは外部ライブラリへの依存を極限まで排除した純粋な C 言語（GNU C + Linux Kernel UAPI）で記述されており、標準的な Linux 開発環境であれば数秒でコンパイルが完了します。

---

## 1. 動作・ビルド要件（System Requirements）

* **CPU アーキテクチャ:** `x86_64` (`AUDIT_ARCH_X86_64`)
* **OS / Linux カーネルバージョン:** **Linux Kernel 5.13 以上**（5.15 LTS または 6.x 系推奨）
  * `Landlock LSM` (`linux/landlock.h` — Kernel 5.13+)
  * `seccomp_unotify` + `SECCOMP_IOCTL_NOTIF_ADDFD` (Kernel 5.9+)
  * `pidfd_open` / `pidfd_getfd` (Kernel 5.6+)
* **コンパイラ & ヘッダ:**
  * `gcc` (または `clang`)
  * `libc6-dev` / `glibc-devel`
  * `linux-libc-dev` / `kernel-headers`
* **コンテナ実行環境（任意）:**
  * 生成した RootFS を `FROM scratch` コンテナとして稼働させる場合は `Docker` または `Podman`

### カーネル対応状況の事前チェックコマンド
お使いの Linux 環境で Landlock が有効化されているかは、以下のコマンドで確認できます。
```bash
uname -r
grep -a "landlock" /sys/kernel/security/lsm && echo "Landlock is ACTIVE!"
```

### Ubuntu / Debian 系での必要パッケージ導入例
```bash
sudo apt-get update
sudo apt-get install -y build-essential linux-libc-dev
```

---

## 2. ビルド手順（Compilation）

`Makefile` が同梱されているため、`make` コマンド1つで4つの独立モジュールがすべてビルドされます。

```bash
make
```

個別に手動でコンパイルする場合は、以下の4コマンドを実行してください（すべて `-Wall -Wextra` で警告ゼロでビルドされます）。

```bash
# 1. 空間閉包バンドラ & 自動学習エンジン
gcc -O2 -Wall -Wextra bistro_hardened_builder.c -o bistro-builder

# 2. 空間隔離 & Strict W^X ランタイムランチャー
gcc -O2 -Wall -Wextra aegis_init.c -o aegis-init

# 3. 時間軸ラチェット共有ライブラリ (Phase 1 / Phase 2 権限凍結)
gcc -O2 -fPIC -shared -Wall -Wextra aegis_ratchet.c -o libaegis_ratchet.so -ldl

# 4. Zero-TOCTOU 動的仮想パッチ Supervisor
gcc -O2 -Wall -Wextra -pthread aegis_vpatch.c -o aegis-vpatch
```

---

## 3. 生成される4つのバイナリの役割

| 生成ファイル | 配置先 (RootFS内) | 役割 |
| :--- | :--- | :--- |
| `bistro-builder` | ホスト側で使用 | 対象バイナリの ELF 依存解決・動的トレース学習・RootFS と Dockerfile の自動生成 |
| `aegis-init` | `/bin/aegis-init` | コンテナ起動時に Landlock・環境変数浄化・Strict W^X Seccomp-BPF を適用 |
| `libaegis_ratchet.so` | `/lib/libaegis_ratchet.so` | `main()` 突入時と `listen()` 完了時に不要システムコールを自動凍結 |
| `aegis-vpatch` | `/bin/aegis-vpatch` | 最外殻チェインローダーとして稼働し、`SIGHUP` で無停止の仮想パッチを適用 |
