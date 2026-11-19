# DDE 域代码在三种文档容器中的检测规避诊断（oletools msodde）

- 分析对象：`oletools/msodde.py`（v0.60.2）及其依赖 `oletools/ooxml.py`（v0.54.2）、`oletools/rtfobj.py`（v0.60.1）
- 容器范围：OOXML（.docx/.docm，zip+XML）、旧式 OLE（.doc/.dot，复合文件）、RTF（.rtf）
- 运行环境：Python 3.12，olefile 0.47，lxml；全部样本与结论在本地复现，不依赖任何外部服务
- 复现入口：
  - 样本生成 + 期望校验：`work/regression/regression_generate.py`（20 个样本，0 失败）
  - 一次性探针：`work/probes/docx_builder.py`
  - 手工/真实文件样本：`work/samples/`

---

## 1. 三条检测路径的归一化、编码与扫描顺序

同一段逻辑 DDE 域（`DDEAUTO cmd /c calc`）在三种容器里的物理形态完全不同，msodde 用三套互不一致的解析器分别处理。

### 1.1 分派入口

`process_file()`（`msodde.py:873`）按顺序判定：

1. `olefile.isOleFile()` 为真 → OLE 路径（再区分 xls/ppt/word）；
2. 读前 4 字节等于 `RTF_START = b'{\rt'`（`msodde.py:728`）→ RTF 路径；
3. 否则 `ooxml.get_type()` 识别 OOXML/单文件 XML，失败则按 CSV 处理。

注意：RTF 判定只看前 4 字节，OLE 判定只看复合文件魔数。魔数之后的内容畸形不会改变分派，但会在各路径内部以不同方式失败（见第 5 节）。

### 1.2 字段归一化对比

| 维度 | OOXML（`process_docx`, `msodde.py:472`） | OLE（`process_doc`/`process_doc_stream`, `msodde.py:414/335`） | RTF（`process_rtf`+`RtfFieldParser`, `msodde.py:731/697`） |
|---|---|---|---|
| 字段定界 | `w:fldChar` begin/end 计数 + `w:instrText` 拼接；`w:fldSimple@w:instr` 单标签 | 字节 0x13 begin / 0x14 sep / 0x15 end（[MS-DOC] 2.8.25），逐字节状态机 | `{ \fldinst ... }` 目标组（`rtfobj` destination 栈），close 时取 `destination.data` |
| 文本拼接单位 | 跨多个 `w:r` 的 `instrText` 累积进 `ddetext`，end 时入 `all_fields` | begin→sep 之间每个原始字节映射进 `field_contents` | fldinst 组内“明文”字节累积；控制字/组另行处理 |
| 空白处理 | XML 解析器保留文本空白；不做 strip 即送入正则 | 0x0A/0x0D→`\n`；0x00→保留；其余 <0x20→`?`；≥0x80→`?`；可打印 ASCII 原样 | 仅在 close 时 `translate(None, b'\r\n').strip()`（`msodde.py:717`），tab/NBSP 等保留 |
| 编码处理 | ElementTree/lxml 按 XML 声明解码，内部统一 unicode；实体（`&#68;`、`&quot;`）由 XML 层自动还原 | 无编码概念：8 位流按字节处理；UTF-16LE 靠高字节 0x00 被原样保留，再用专门的 `\x00d\x00d\x00e\x00` 前缀兜底（`msodde.py:324`） | **不做解码**：`\'hh`、`\uN`、`\~` 等转义不以 Word 语义还原；最后统一 `field.decode('ascii')`（`msodde.py:738`） |
| QUOTE 域还原 | `unquote()`（`msodde.py:543`）：只要字段里含子串 `"QUOTE"` 就把后续空格分词按 `chr(int())` 拼回字符 | 无此机制 | 无此机制（QUOTE 原样保留） |
| 过滤模式 | 支持 dde-only / 黑名单 / 全部三档 | **无过滤**，`process_doc_field()` 只做前缀判定 | 与 OOXML 相同的三档过滤 |
| DDE 判定 | 正则 `^\s*dde(auto)?\s+`（`msodde.py:217`），要求 dde 后至少一个空白 | `lstrip().lower().startswith('dde')`（`msodde.py:322`），**无词边界、无尾空白要求**；另有 UTF-16 兜底分支 | 同 OOXML 正则 |

### 1.3 扫描顺序（字段顺序为何会变）

- **OOXML**：`iter_xml` 按 zip 中央目录顺序（`ZipFile.namelist()`，`ooxml.py:494`）遍历子文件，每个子文件内按 XML 文档序。已实测：把 `word/header1.xml` 放在 `word/document.xml` 之前写入 zip，输出顺序即为 header 在前（样本 `samples/order/order-zipfirst-header.docx`）。字段顺序因此由归档写盘顺序决定，而非逻辑文档顺序。
- **RTF**：fldinst 目标按其在 RTF 字节流中的出现顺序入列（`msodde.py:719`），即文档序。
- **OLE**：`process_doc` 按复合文件目录项（direntry）顺序遍历**所有流**（`msodde.py:427`），包括孤立目录项；同一逻辑字段只会落在 WordDocument 流，但输出顺序跟随 CFB 目录顺序（实测见 `work/` 探针：`1Table` 排在 `WordDocument` 前时输出随之反转），与阅读顺序无关。

结论：**同一段 DDE 内容经过不同容器后，检测器看到的字段顺序没有统一保证**。任何“取第一个字段/按位置比对”的下游规则都会在容器间产生分歧；msodde 自身只做字符串拼接，顺序差异目前不直接导致漏报，但会破坏基于顺序的关联分析与去重。

### 1.4 编码面的关键事实（实测）

- 随仓库分发的真实 `.doc`：Office 2003/2016 样本的 WordDocument 流字段文本是**单字节**（`\x13DDEAUTO ...`），而韩文样本是 **UTF-16LE**（`D\x00D\x00E\x00...`）。两条路径都能命中，分别走 `startswith('dde')` 与 `\x00d...` 兜底分支。
- OOXML 的字符编码由 XML 层吸收，对上层透明，实体/UTF-8/UTF-16 声明不构成规避面（但命名空间与标签结构会，见第 3 节）。
- RTF 是三者中唯一“完全不做 RTF 语义解码”的路径，这正是其最大规避面。

---

## 2. 格式允许的差异 vs 安全缺口（分类总览）

判定原则：

- **格式允许差异**：规范（ECMA-376 / [MS-DOC] / RTF 1.9.1）明确允许、且 Word 会正常执行的等价表示；msodde 看不到真实语义属于**安全缺口**。
- **安全缺口**：Word 仍执行 DDE，而 msodde 漏报（false negative）、误报（false positive）或整体崩溃/中止的具体条件。
- **健壮性问题**：未必单独构成绕过，但会让扫描中止或产生不一致状态，可被叠加利用。

| # | 容器 | 触发条件（Word 合法） | 现象 | 归类 |
|---|---|---|---|---|
| F1 | RTF | fldinst 内用 `\'44\'44\'45` 写 DDE | 字面量 `'44'44'45`，dde-only 漏报 | **安全缺口（漏报）** |
| F2 | RTF | 用 `\u68\u68\u69` 写 DDE | 留下 `???`，漏报 | **安全缺口（漏报）** |
| F3 | RTF | 关键字中插忽略组 `DD{\*\xx}EAUTO` | 变成 `DD*EAUTO`，漏报 | **安全缺口（漏报）** |
| F4 | RTF | `DDE\~AUTO`（NBSP 作空白） | 变成 `DDE~AUTO`，正则不匹配，漏报 | **安全缺口（漏报）** |
| F5 | RTF | 任一 fldinst 含原始 ≥0x80 字节 | `decode('ascii')` 抛错，**整份文件结果全丢** | **安全缺口（扫描中止）** |
| F6 | OLE | 8 位流字段内 0xA0(NBSP)/0x09(tab) 分隔关键字 | 映射成 `DDE?AUTO`，dde 前缀丢失，漏报 | **安全缺口（漏报）** |
| F7 | OLE | begin 后先放 ≥999 字节再写 DDE | 命中 1000 字节上限后忽略后续，漏报 | **安全缺口（漏报）** |
| F8 | OLE | 8 位流里手工塞 NUL 交错 `D\x00D\x00E...` | 两分支均不匹配，漏报 | **安全缺口（条件漏报）** |
| F9 | OOXML | 同一 `w:r` 内放两个 instrText | 只取第一个，第二个 DDE 漏报 | **安全缺口（漏报）** |
| F10 | OOXML | begin 无配对 end（畸形但 Word 容错） | 缓冲在 EOF 被静默丢弃，漏报 | **安全缺口（漏报）** |
| F11 | OOXML | 额外 XML 部件畸形 | `ooxml.py:611` 裸 `assert(depth==0)` 触发，**整个 docx 扫描中止** | **安全缺口（健壮性→漏报）** |
| F12 | OOXML | `QUOTE 68 68 69 ...` 域 | `unquote` 还原出 `DDE A`，dde-only **误报** | **安全缺口（误报）** |
| F13 | OLE | 字段名为 `DDEAUTOX`/`DDE-foo` | `startswith('dde')` 命中，非 DDE 域被报 | **安全缺口（误报，仅 OLE 语义）** |
| D1 | OOXML | 未知/拼错命名空间 URI | 标签不识别而跳过 | 格式允许（非 Word 接受的命名空间，低风险） |
| D2 | 全部 | 字段输出顺序随容器/归档/目录顺序变化 | 顺序不统一 | 格式允许差异（本身非漏洞，影响关联分析） |
| D3 | OLE | 逐字节扫描所有流（含孤立项）、不做词边界 | 与 XML/RTF 的正则语义不一致 | 实现取舍，伴随 F13 误报 |

---

## 3. 漏报（false negative）的真实条件

### 3.1 RTF：转义从不被语义还原（F1–F4）

`RtfFieldParser` 继承自 `rtfobj.RtfParser`，只重写了 fldinst 目标的开闭与 `control_symbol`（`msodde.py:707-725`）。它把控制符号的“符号本身”追加进数据，但**不解释** RTF 的字符转义：

- `\'hh`（十六进制字符）：基类 `control_symbol` 只在 objdata 目标内特殊处理（`rtfobj.py:740-760`），fldinst 内走 `msodde.py:721-725`，留下字面 `'44`。
- `\uN?`（Unicode 字符）：`\u68` 是控制字，基类 `control_word` 默认空实现，替代符 `?` 作为普通文本保留 → D 变成 `?`。
- 忽略组 `{\*\xx}`：组内 `*` 经 `control_symbol` 注入，闭合后 fldinst 数据里残留 `*`，关键字被切成 `DD*EAUTO`。
- `\~`（NBSP）：同为控制符号，残留 `~`；而 `FIELD_DDE_REGEX` 的空白类只认 ASCII 空白（`\s`），不认 NBSP。

Word 在加载时会把以上全部还原成真正的 DDE 指令并执行，因此四项都是**真实绕过**。实测（`work/samples/rtf/`）：

```
rtf-hex.rtf        dde-only -> ''   blacklist -> "'44'44'45AUTO cmd /c calc"
rtf-unicode.rtf    dde-only -> ''   blacklist -> "???AUTO cmd /c calc"
rtf-groupsplit.rtf dde-only -> ''   blacklist -> "DD*EAUTO cmd /c calc"
rtf-nbsp.rtf       dde-only -> ''   blacklist -> "DDE~AUTO cmd /c calc"
```

注意默认黑名单模式下这些字段仍会被打印（因为它们不是黑名单里的“无害”命令），但 `-d/--dde-only` 与任何只认 dde 前缀的自动化判定都会漏报；且字符串已被污染，无法再做可靠 IOC 提取。

### 3.2 RTF：单字段非 ASCII 让整份扫描崩溃（F5）

`process_rtf` 在解析完成后做列表解码（`msodde.py:738`）：

```python
all_fields = [field.decode('ascii') for field in rtfparser.fields]
```

任一字段含原始 ≥0x80 字节即抛 `UnicodeDecodeError`，该异常**不在 process_rtf 内捕获**，一路冒泡到 `main()`（`msodde.py:1007`）被打印后返回码 1。后果是：排在坏字段之前、已正确解析的好字段（含真正的 DDE）也全部丢失。实测 `rtf-abort.rtf` 含三个字段（好—坏—好），三种过滤模式全部抛异常，`DDE Links:` 输出为空。这是典型的“一颗老鼠屎”可用性/安全缺口。

### 3.3 OLE：字节映射破坏关键字与 1000 字节上限（F6–F8）

`process_doc_stream` 的字节映射规则（`msodde.py:393-403`）：

- `0x00` 原样保留（为 UTF-16LE 高字节设计）；
- `0x0A/0x0D` → `\n`；
- 其余 `<0x20` 与所有 `≥0x80` → `?`；
- 可打印 ASCII 原样。

因此：

- **F6**：8 位（CP1252）流中用 NBSP(0xA0) 或 tab(0x09) 分隔 `DDE` 与 `AUTO`，映射后变成 `DDE?AUTO`，`startswith('dde')` 失败。真实文件级补丁验证：基于 `dde-test-from-office2016.doc` 替换得到的 `samples/p1-nbsp.doc` 输出由完整 DDE 变为空。
- **F7**：字段 begin 后、关键字之前放 ≥999 个填充字节。长度检查在 `len(field_contents) > 1000` 后置 `max_size_exceeded`（`msodde.py:386-389`），此后内容不再累积；若触发时 DDE 关键字尚未进入缓冲，sep/end 时 `process_doc_field('')` 返回空。实测边界：998 个前导空格仍可检出，**999 个即漏报**。真实文件补丁 `samples/p2-pad.doc` 复现。Word 对域指令长度远大于此，填充为合法空白时不影响执行。
- **F8**：该解析器对 UTF-16LE 的支持依赖“高字节恰为 0x00”且走 `\x00d\x00d\x00e\x00` 兜底；在一个本为 8 位的流里手工插入 NUL 交错（`D\x00D\x00E\x00AUTO`），普通分支被 NUL 干扰、UTF-16 兜底要求前缀以 NUL 起头（`\x00d`），两者都不命中 → 漏报（`samples/p4-nuls.doc` 实测为空）。属条件性缺口，取决于 Word 如何解释该片段的字符集。

### 3.4 OOXML：结构性盲区（F9–F11）

- **F9 同一 run 多 instrText**：`process_docx` 在每个 `w:r` 内遇到第一个 fldChar/instrText 即 `break`（`msodde.py:494-498`）。同 run 内第二个 instrText 永不读取。OOXML 规范允许一个 run 含多个子元素，Word 会拼接全部 instrText。实测 `docx-twoinrun.docx` 只报第一个 `HYPERLINK benign`，第二个 `DDEAUTO hidden-second` 漏报。
- **F10 无 end 的 begin**：`ddetext` 只在 fldChar end（`level` 回到 0/-1）时入列（`msodde.py:513-518`）。只有 begin 没有 end 时，缓冲在函数结束时被静默丢弃，无任何告警。
- **F11 畸形部件触发断言**：`ooxml.XmlParser.iter_xml` 在每个子文件解析后有裸 `assert(depth == 0)`（`ooxml.py:611`）。畸形 XML 的 `ET.ParseError` 虽被捕获（`ooxml.py:600-610`），但异常跳出后 `depth` 未归零，断言随即失败，抛 `AssertionError`——它既不是被处理的 `ParseError`，也不被 `process_docx` 捕获，导致**整个包扫描中止**，document.xml 里的合法 DDE 一并漏报。样本 `ooxml-malformed-part.docx` 实测在两种模式下均 RAISES。以 `python -O` 运行时断言被移除，行为又会改变，构成不确定的安全状态。

---

## 4. 误报（false positive）的真实条件

### 4.1 OLE 的 `startswith` 无词边界（F13）

`process_doc_field`（`msodde.py:322`）使用 `data.lstrip().lower().startswith(u'dde')`，而 OOXML/RTF 用的正则要求 `dde(auto)?` 之后至少一个空白（`\s+`）。分歧实测：

| 字段文本 | OLE `process_doc_field` | OOXML/RTF 正则 |
|---|---|---|
| `DDEAUTOX foo` | 命中（报为 DDE） | 不命中 |
| `DDE-whatever` | 命中 | 不命中 |
| `ddefield` | 命中 | 不命中 |
| 裸 `DDE`（无后续空白） | 命中 | 不命中 |

这些都不是合法 DDE 域关键字，OLE 路径会产生误报；同一逻辑字段放进 docx/rtf 又不报，造成跨容器判定不一致。回归样本 `ole-prefix-overmatch.bin` 固化该行为。

### 4.2 OOXML 的 QUOTE 还原误报（F12）

`unquote()`（`msodde.py:543-556`）只要字段字符串中**任意位置**含子串 `QUOTE`，就把其后按空格拆分的 token 用 `chr(int())` 重组。于是：

- 一个完全无害的 `QUOTE 68 68 69 32 65` 域被还原成 `DDE A`，随后被 `FIELD_DDE_REGEX` 命中，在 dde-only 模式下**误报为 DDE**（样本 `ooxml-quote.docx`）。
- 该函数还会被字段中部出现的 `QUOTE` 子串触发（如 `HYPERLINK "x QUOTE 68"` 被改写成 `"xQUOTE68"`），污染输出。
- RTF/OLE 路径没有 QUOTE 还原，同一段 QUOTE 域在 RTF 中保持原样、不会误报——再次形成容器间不一致。

---

## 5. 出错后的扫描状态（逐路径记录）

| 路径 | 错误来源 | 异常处理 | 扫描状态 / 数据去向 |
|---|---|---|---|
| RTF | fldinst 含原始非 ASCII 字节 | `UnicodeDecodeError` 不在 `process_rtf` 捕获 | 已解析字段全部丢弃；`main()` 捕获后打印 traceback，返回码 1，`DDE Links:` 为空；**无部分结果** |
| RTF | RTF 结构畸形 | `rtfobj` 状态机较宽容，`_end_of_file` 强制闭合未关组（`rtfobj.py:610-616`） | 通常不抛错，畸形部分被忽略，其余字段保留 |
| OOXML | 某 zip 部件 XML 畸形 | `ParseError` 被捕获并记录到 `subfiles_no_xml`，但 `depth` 未重置 | 紧随其后的 `assert(depth==0)` 失败，`AssertionError` 中止整个包；正常部件结果丢失 |
| OOXML | begin/end 不配对 | 无异常 | `level` 跨段落甚至跨子文件泄漏（见下）；孤立 begin 的缓冲在 EOF 静默丢失；孤立 end 使 level 变 -1 并追加空字符串（`msodde.py:515-518`） |
| OOXML | zip 损坏/非 zip | `BadZipfile`/csv 嗅探错误 | 冒泡到 `main()`，返回码 1 |
| OLE | 流内任意字节（含垃圾/控制符） | 状态机逐字节容错，**不抛异常** | 单字段失败不影响其它字段与其它流；实测垃圾字节与合法字段并存时合法字段仍命中 |
| OLE | 复合文件本身无法打开 | `olefile.OleFileIO` 异常 | 冒泡到 `main()`，返回码 1；加密文件由 `process_maybe_encrypted` 先尝试解密 |

跨子文件状态泄漏（实测确认）：`process_docx` 的 `level`/`ddetext` 只在“子文件结束 depth==0”时重置（`msodde.py:479-480`）。若 document.xml 以一个未闭合 begin 结束，header 部件里的 instrText 会与前一文件的 `ddetext` 拼接，产生跨部件的混合字段。这破坏了字段边界的可信度，虽不直接漏报，但可被用来制造字段拼接/错位。

另：`LOCATIONS`（`msodde.py:140-142`，列出 document/header/footer/comments 等部件）是**死代码**，全仓库无引用。实际扫描的是 zip 内**所有** XML 部件（攻击者可控、含 header/footer），白名单并未生效——这通常带来“多扫”而非漏扫，但与代码注释/TODO 暗示的意图不符，应明确取舍。

---

## 6. 可复现的本地样本

全部样本均在本地由脚本生成或从仓库自带样本派生，无网络依赖。

### 6.1 一键回归集（推荐）

- 生成器 + 期望校验：`work/regression/regression_generate.py`
  - 运行：`python3 -I work/regression/regression_generate.py`（构建 20 个样本并断言当前行为，当前 0 失败）
  - 仅构建：`--build`，输出到 `work/regression/generated/`
- OOXML 最小包构造器：`work/probes/docx_builder.py`（stdlib `zipfile`，含 complex/fldSimple/多 run 等片段）
- 每个样本在脚本 `SPECS` 表中带 dde-only 与 blacklist 两档期望，崩溃类样本以 `('raises', Exception)` 断言。

### 6.2 手工/真实文件样本（`work/samples/`）

| 目录/文件 | 容器 | 用途 |
|---|---|---|
| `rtf/rtf-baseline.rtf` | RTF | 对照组，正常检出 |
| `rtf/rtf-hex.rtf`、`rtf-unicode.rtf`、`rtf-groupsplit.rtf`、`rtf-nbsp.rtf` | RTF | F1–F4 漏报 |
| `rtf/rtf-abort.rtf` | RTF | F5 整文件扫描中止 |
| `ooxml/docx-baseline.docx`、`docx-simple.docx`、`docx-splitruns.docx` | OOXML | 对照组（含跨 run 正常拼接） |
| `ooxml/docx-twoinrun.docx` | OOXML | F9 同 run 第二 instrText 漏报 |
| `ooxml/docx-orphan.docx` | OOXML | F10 无 end 静默丢弃 |
| `ooxml/docx-badns.docx` | OOXML | D1 未知命名空间跳过 |
| `order/order.docx`、`order.rtf`、`order-zipfirst-header.docx` | 多容器 | 1.3 节字段顺序差异 |
| `dde-test-from-office2003|2016|...korean/...doc` | OLE | 从仓库加密 zip 解出的真实 .doc（8 位与 UTF-16LE 两种编码） |
| `p1-nbsp.doc` | OLE | 基于 2016 真实样本的 NBSP 补丁，F6 全路径漏报 |
| `p2-pad.doc` | OLE | 999 字节前导填充补丁，F7 全路径漏报 |
| `p4-nuls.doc` | OLE | 8 位流 NUL 交错补丁，F8 全路径漏报 |

复现命令示例：

```bash
# 全量回归（断言当前（含缺陷的）行为，修复后需同步更新期望）
python3 -I work/regression/regression_generate.py

# 单独验证某个真实 .doc 补丁
python3 -I -c "from oletools import msodde; print(msodde.process_file('work/samples/p1-nbsp.doc'))"
```

---

## 7. 修复边界与回归基线建议

原则：**不试图完整复刻 Word 的域语法**，只在每条路径上把“Word 会还原为 DDE 指令”的表示归一化到同一判定面，并保证单处畸形不拖垮整体扫描。下列边界明确区分“应修”与“不修”。

### 7.1 RTF 路径

应修：

1. 在 fldinst 目标内实现 RTF 语义解码（修复 F1–F4）：
   - `\'hh` → 对应字节；`\uN` → 码点 N（忽略其后的替代字符）；`\~` → NBSP 并在判定前纳入空白类；忽略组 `{\*...}` 不向字段数据注入字符。
   - 复用/参照 `rtfobj` 已有的控制字框架，避免新写正则解析器。
2. 用容错解码替代 `field.decode('ascii')`（修复 F5）：改为逐字段 `decode('latin-1', errors='replace')` 或在 `RtfFieldParser` 内直接产出 unicode，并把单字段失败隔离为“该字段标记不可信并继续”，保证坏字段不影响其它字段输出。
3. DDE 判定前做与 Word 一致的空白归一化（NBSP/tab 视作空白）。

不修：不模拟 RTF 内嵌 OLE 对象（`\objdata`）里的二级 DDE——那属于 rtfobj/oleobj 的对象解析职责，msodde 维持当前边界。

### 7.2 OLE 路径

应修：

1. 引入真实词边界（修复 F13）：把 `startswith('dde')` 改为与 OOXML 一致的 `^\s*dde(auto)?(\s|$)` 判定，统一三容器语义；保留 UTF-16LE 的 `\x00d...` 兜底但同样加词边界。
2. 调整 1000 字节上限策略（修复 F7）：不要在关键字到达前就永久丢弃；可改为“环形缓冲保留尾部 N 字节”或“仅对字段结果长度设限、指令区始终扫描前缀”，确保前导填充无法把关键字推出窗口。
3. 控制字符/NBSP 归一化（修复 F6）：把 `<0x20` 与 `≥0x80` 的映射从 `?` 改为“空白类→空白、其余→移除或替换但不插入可破坏 token 的字符”，再做前缀匹配。

不修：不解析完整 WordDocument 结构（Fib/ piece table）。当前“全流字节扫描 + 域字符状态机”是有意的粗粒度方案，维持它，只修正归一化与判定；NUL 交错（F8）在真实 UTF-16 文档中由兜底分支覆盖，剩余手工构造的混合编码场景记录为已知限制即可。

### 7.3 OOXML 路径

应修：

1. 同 run 多 instrText（修复 F9）：移除 `msodde.py:494-498` 的提前 `break`，遍历 run 内全部 fldChar/instrText 子元素。
2. 健壮性（修复 F11）：删除/替换 `ooxml.py:611` 的裸 `assert(depth==0)`，在 `ParseError` 处理分支显式 `depth = 0` 并继续下一子文件；确保 `-O` 与常规运行行为一致。
3. 字段生命周期：未闭合 begin 在 EOF 产生告警而非静默丢弃（修复 F10）；在每个子文件边界无条件重置 `level/ddetext`，消除跨部件泄漏（第 5 节）。
4. QUOTE 处理（修复 F12）：`unquote` 仅对“以 QUOTE 为首个关键字”的完整字段生效，并要求全部 token 可解析；不要因字段中部出现 `QUOTE` 子串而触发；QUOTE 还原结果应单独标注，不直接喂给 dde-only 正则。

不修：不基于 `LOCATIONS` 收紧部件范围（保持扫描全部 XML 部件的“多扫”偏安全姿态），但应删除死代码或补上真正的白名单逻辑，二选一，避免意图含糊。未知命名空间（D1）维持跳过——非 OOXML 标准命名空间本就不被 Word 当作 w: 域执行。

### 7.4 回归基线

- 以 `work/regression/regression_generate.py` 的 `SPECS` 作为固化基线：修复一项即把对应期望从“漏报/崩溃/误报”改为“正确检出/正确忽略”，并保留一个断言旧行为的最小负例，防止回退。
- 三容器应共享**同一组逻辑 DDE 载荷**（当前脚本已用同一 `DDEAUTO cmd /c calc` 贯穿），修复后三种容器在 dde-only 模式下的检出集合必须一致——这是防止“容器间字段顺序/归一化分歧”再次出现的核心断言。
- 全部样本离线生成、体积小、无宏无可执行 payload（仅文本指令），可直接纳入 `tests/msodde/`；真实 `.doc` 补丁若进入测试集，应沿用仓库现有“加密 zip + `infected-test` 口令”约定（见 `tests/test_utils/testdata_reader.py`）。
- 建议新增三类断言：(a) 单字段畸形不影响同文件其它字段（针对 F5/F11）；(b) 三容器同载荷检出一致性；(c) 误报负例（`DDEAUTOX`、纯 QUOTE 域）。

---

## 8. 结论

msodde 的三条容器路径在**字段定界、编码解码、空白/词边界归一化、扫描顺序与错误隔离**上各自独立且语义不一致。真正可被利用的安全缺口集中在：

- RTF 完全不做 RTF 转义解码（F1–F4）且 ascii 解码会整体中止（F5）；
- OLE 的字节映射与 1000 字节上限可破坏/截断关键字（F6/F7），加上无词边界的 `startswith` 误报（F13）；
- OOXML 的同 run 子元素盲区（F9）、畸形部件断言崩溃（F11）与 QUOTE 误报（F12）。

字段顺序随容器、zip 归档顺序和 CFB 目录顺序变化属于格式允许差异，本身不是漏洞，但要求下游消费方不得依赖字段位置。所有问题均已用离线样本复现，并由 `work/regression/regression_generate.py` 固化为可重复的回归基线，修复边界与“不完整模拟 Word 语法”的取舍已在第 7 节逐项列明。
