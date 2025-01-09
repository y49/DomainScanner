

# DomainScanner

![License](https://img.shields.io/badge/license-MIT-green)
![Go Version](https://img.shields.io/github/go-mod/go-version/yourusername/DomainScanner)
![Stars](https://img.shields.io/github/stars/yourusername/DomainScanner)

DomainScanner 是一个基于 Go + HTML/JS 的开源域名扫描工具，能够根据自定义的 **Patterns** 和可选后缀，批量检查域名是否可注册，提供暂停、继续、终止等操作，并通过 **SSE** 实时输出扫描日志和结果。

## 功能特性

1. **多种模式**  
   - `old`：标准模式 (A/B/C)  
   - `style`：风格模式 (自由组合 A～Z 占位符)  
   - `literal`：直接将输入字符串视为域名主体

2. **实时输出**  
   - 通过 SSE (Server-Sent Events) 将扫描进度、可注册域名、扫描错误等信息实时推送给前端。

3. **并发控制**  
   - 可指定并发数，平衡扫描速度与资源占用。

4. **可暂停/继续/终止**  
   - 支持在扫描过程中暂停(并不终止 worker)、恢复继续、或直接终止本轮扫描。

5. **可选后缀**  
   - 后缀通过后端 `whoisServers` 自动生成列表，前端可勾选需要的后缀，如 `.com`, `.cn`, `.net` 等。

6. **便捷的前端页面**  
   - 使用 HTML + JS + (可选)Bootstrap 等在线样式库，美观地展示扫描进度与日志。

## 目录结构

```
DomainScanner/
├─ main.go          // Go 后端入口, 路由 + 逻辑
├─ templates/
│   └─ index.html   // 前端页面 (或放在任意静态文件目录)
├─ README.md        // 项目说明文档
└─ ...
```

## 快速开始

1. **克隆项目**  
   ```bash
   git clone https://github.com/yourusername/DomainScanner.git
   cd DomainScanner
   ```

2. **编译 & 运行**  
   - 需要 Go 1.18+ (也可根据实际支持的版本调整)  
   ```bash
   go build -o domain-scanner main.go
   ./domain-scanner
   ```
   启动后，默认监听 `http://127.0.0.1:8080`.

3. **访问前端页面**  
   - 打开浏览器访问 `http://127.0.0.1:8080` 或自行在 `index.html` 中配置相应路径。

> **注意**：若你的项目将前端页面直接内嵌在 `main.go`，可根据实际情况修改部署方式。

## 使用方法

1. **后端地址**  
   - 默认是 `http://127.0.0.1:8080`，可自行修改。

2. **模式**  
   - `old`：`A` 代表 `[a-z]`，`B` 代表 `[0-9]`，`C` 代表 `[a-z0-9]`  
   - `style`：例如 `ABAB` 表示有 2 个占位符 (A, B)，每个可取 `[a-z0-9]` 里的一种，并保持相同的 A/B 位置。  
   - `literal`：直接将输入的字符串视为域名主体，不做变换。

3. **Patterns**  
   - 多个 Pattern 用逗号分隔，示例：`AABB, ABAB, example`  
   - `AABB` -> `aa00~zz99` 大批量组合  
   - `ABAB` (style模式) -> 以 2 个占位符 A/B 组合出大量域名  
   - `example` (literal模式) -> 直接生成 `example.com` 等

4. **可选后缀**  
   - 在前端勾选 `.com`, `.cn`, `.net`, `.org`, 等来自 `whoisServers` 列表。  
   - 扫描时，会将主体 + 后缀组装成 `example.com`, `example.net` 等域名并检查可用性。

5. **并发数**  
   - 默认 5，可根据网络和资源情况调大/调小。

6. **操作**  
   - **开始扫描**：发起请求 `/api/start`  
   - **暂停**：发送 `/api/pause`，不会中断任务，只会让 worker 进入等待  
   - **继续**：发送 `/api/resume`，唤醒暂停的 worker  
   - **终止**：发送 `/api/stop`，彻底结束当前扫描（不可恢复）

7. **查看结果**  
   - 扫描日志实时滚动显示：进度 `[x/y] domain`、可用域名 `[available] domain`、失败 `[fail] domain` 等。  
   - “可注册域名”列表显示所有扫描到可注册的域名。  
   - 日志默认为 500 行循环输出，可在前端修改。

## 部署方式

1. **本地运行**  
   - 直接编译 & 运行 `main.go`，在浏览器访问 `http://localhost:8080`.

2. **Docker**  
   - 你可以编写一个 `Dockerfile`，在容器中运行该服务。示例：  
     ```dockerfile
     FROM golang:1.19-alpine
     WORKDIR /app
     COPY . .
     RUN go build -o domain-scanner main.go
     EXPOSE 8080
     CMD ["./domain-scanner"]
     ```
   - 然后执行  
     ```bash
     docker build -t domain-scanner .
     docker run -p 8080:8080 domain-scanner
     ```

3. **云服务器**  
   - 部署到任意 Linux/Windows 服务器上，注意开启 8080 端口访问。

## 贡献 & 反馈

欢迎提 Issue 或 PR 来贡献新特性、修复问题。你也可以在 [Discussions](https://github.com/yourusername/DomainScanner/discussions) 中分享使用心得或提出需求。

## 许可证

本项目采用 [MIT License](LICENSE) 进行分发，你可以自由复制、修改、分发并用于商业用途，但需保留许可证信息。


