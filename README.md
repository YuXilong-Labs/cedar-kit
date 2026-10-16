# LookInsideServer — special CA 构建

自动跟踪 [LookInsideApp/LookInside-Release](https://github.com/LookInsideApp/LookInside-Release/releases/latest)，将 Server 内置根证书与 SHA-256 pin 替换为本仓库公开测试 CA，并发布 CocoaPods 可用的 XCFramework。保留原有证书链与挑战签名验证逻辑，不把私钥放进仓库或 Actions。

## CocoaPods

在 [Releases](https://github.com/YuXilong-Labs/cedar-kit/releases) 选择版本，把对应 podspec URL 放入 Podfile：

```ruby
pod 'LookInsideServer',
    :podspec => 'https://github.com/YuXilong-Labs/cedar-kit/releases/download/1.0.1-special.2/LookInsideServer.podspec',
    :configurations => ['Debug']
```

执行 `pod install`。删除同名官方依赖，避免重复链接。podspec 直接从本仓库 Release 下载 ZIP，并校验 SHA-256；无需 CocoaPods trunk 账号或私有 Specs 源。支持 iOS 15+、macOS 14+，包中保留真机、模拟器、Catalyst、macOS 切片。此仓库不把大二进制提交到 Git，因此不要使用 `:git` 集成。

Server 的根仅信任相应测试 CA；客户端仍须拥有该 CA 签发的证书以及匹配的私钥。仓库没有实现签发服务、客户端接口重定向或官方许可证激活。修改过的 framework 使用 ad-hoc 代码签名，嵌入真机 App 时由工程重新签名；不保留官方 Team ID，不能假设通过原生 Injector 的团队签名检查。

## 自动发布

`.github/workflows/release.yml` 每 6 小时（UTC 00:23 / 06:23 / 12:23 / 18:23）检查一次，也支持 `workflow_dispatch` 和 main 分支推送。GitHub 定时任务可能延迟；公共仓库长期无活动时可能暂停定时执行，可手动启用。

1. 运行失败场景单元测试。
2. 从 GitHub API 获取上游最新稳定 Release，验证 asset 名称、URL 与 API 提供的 SHA-256。
3. 若 `<上游版本>-special.<patch_revision>` 已发布则跳过；未完成的草稿可重试。
4. macOS runner 解压 XCFramework，对每个架构用 `nm` 定位 `_kLKSRootCertDER`、`_kLKSRootCertDERLength`，经 Mach-O segment 映射得到文件偏移。
5. 验证旧 DER 摘要与配置一致，确认旧 pin 唯一、新 DER 不超过槽位，再替换 DER、长度、pin。其余字节必须保持一致。
6. 每个 framework 执行 ad-hoc codesign，再验证签名及全部架构中的根证书、长度、摘要。
7. 生成 ZIP、podspec、`manifest.json`、`SHA256SUMS`。先上传草稿，全部完成后公开 Release。

只需要 Actions 的 `GITHUB_TOKEN`（发布 job 的 `contents: write`），不需要额外 PAT 或 CA 私钥 Secret。PR 仅跑测试，不发布。

发布包的全部切片会被检查，但这不等于全部平台均做过运行时测试。未知架构、符号被剥离、根证书轮换、根 DER 放不下、pin 不唯一、缺少上游下载摘要等情况都会失败并停止发布，需人工审查后调整补丁。上游改变二进制布局时不会继续使用旧固定地址。

## CA 与升级

`certs/special-root.der` 是当前配套服务的公开根证书，SHA-256：

```text
d16af470704aeddf4d348993420766e3d391e6480c6f28397117d00d9538688a
```

`config.json` 固定已审查的上游根摘要和special 根摘要。变更special CA 或补丁算法后，递增 `patch_revision` 并手动运行 Actions，生成新版本；不会覆盖已公开 Release。原 CA 私钥仍由配套签发服务单独保管。

构建复现（macOS，Python 3.12+、Xcode Command Line Tools、GitHub CLI、CocoaPods）：

```sh
python3 -m unittest discover -s tests -v
python3 scripts/release.py detect
python3 scripts/release.py build
pod ipc spec build/release/LookInsideServer.podspec
```

使用全新 `build/` 目录重跑构建，避免误用旧输入。下载与签名校验报告位于 `build/release/manifest.json`。

上游 podspec 将 Server 标注为 MIT，并保留 LookInside 作者信息；本仓库不重新授予第三方二进制的权利。仅用于开发测试。

参考：[CocoaPods podspec source](https://guides.cocoapods.org/syntax/podspec.html#source)、[Podfile 外部 podspec](https://guides.cocoapods.org/syntax/podfile.html#pod)、[Actions 定时触发](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)。
