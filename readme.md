# WP Plugin Scanner v1.0.1

All-in-one WordPress plugin scanner & wordlist generator. Detects installed plugins (even behind WAF/Cloudflare), supports fast/stealthy scan, proxy support, and can collect plugin lists from WordPress.org.

## Features
- Multi-threaded, ultra-fast scan (default 50 threads)
- Stealthy mode: random UA, WAF bypass, IP spoofing, cache busting
- Fast mode: 1 request per plugin (7x faster, lower confidence)
- **Proxy support**: HTTP, HTTPS, SOCKS4, SOCKS5 (SSH tunnel compatible)
- Custom wordlist and output support
- Collect mode: tạo wordlist plugin từ WordPress.org (lọc theo số lượng cài đặt)

## Usage

### Scan Mode
```
./wp_scanner -u <target_url> [-w wordlist] [-t threads] [-c custom_plugins] [-o output] [-proxy url]
```

### Collect Mode (Tạo wordlist)
```
./wp_scanner -collect [-min-installs 100] [-full]
```

## Options

- `-u string`         : Target WordPress URL (bắt buộc khi scan)
- `-w string`         : Wordlist file chứa plugin (default: plugins.txt)
- `-c string`         : File plugin custom (bổ sung thêm vào wordlist)
- `-o string`         : Output filename (không có extension, sẽ tạo .json và .txt)
- `-t int`            : Số thread chạy song song (default: 50, nên giảm khi stealthy)
- `-delay int`        : Delay giữa các request (ms, dùng cho stealthy/slow)
- `-timeout int`      : Timeout mỗi request (giây, default: 10)
- `-proxy string`     : Proxy URL (http, https, socks4, socks5)
- `-s`, `-stealthy`   : Bật chế độ stealthy (random UA, WAF bypass, spoof IP, cache bust)
- `-f`, `-fast`       : Bật chế độ fast (1 request/plugin, 7x nhanh hơn, độ chính xác thấp hơn)
- `-collect`          : Chế độ collect (tạo wordlist từ WordPress.org)
- `-min-installs int` : Lọc plugin theo số lượng active installs (dùng với -collect, default: 100)
- `-full`             : Collect toàn bộ plugin (rất chậm, dùng với -collect)
- `-h`                : Hiển thị help

## Examples

### Collect plugin wordlist
```
./wp_scanner -collect
./wp_scanner -collect -min-installs 1000
./wp_scanner -collect -full
```

### Scan target (fast, 50 threads mặc định)
```
./wp_scanner -u https://example.com
./wp_scanner -u https://example.com -t 100
```

### Fast mode (7x nhanh hơn, 1 request/plugin)
```
./wp_scanner -u https://example.com -f
./wp_scanner -u https://example.com -f -t 100
```

### Scan với wordlist và plugin custom
```
./wp_scanner -u https://example.com -w my_plugins.txt -c custom.txt
```

### Scan với output file custom
```
./wp_scanner -u https://example.com -o my_report
```

### Stealthy + Fast (tốt nhất cho site có WAF)
```
./wp_scanner -u https://protected-site.com/ -s -f -t 10
```

### Stealthy mode (bypass WAF/Cloudflare)
```
./wp_scanner -u https://protected-site.com/ -s -t 5 -delay 200
```

### Ultra stealth (WAF mạnh)
```
./wp_scanner -u https://protected-site.com/ -s -t 1 -delay 1000
```

### Scan qua Proxy

#### SOCKS5 proxy (SSH tunnel: `ssh -D 9999 user@server`)
```
./wp_scanner -u https://example.com -proxy socks5://127.0.0.1:9999
```

#### HTTP proxy
```
./wp_scanner -u https://example.com -proxy http://127.0.0.1:8080
```

#### HTTPS proxy
```
./wp_scanner -u https://example.com -proxy https://proxy.example.com:8443
```

#### SOCKS4 proxy
```
./wp_scanner -u https://example.com -proxy socks4://127.0.0.1:1080
```

#### Stealthy + Proxy (ẩn danh tối đa)
```
./wp_scanner -u https://protected-site.com/ -s -f -t 10 -proxy socks5://127.0.0.1:9999
```

## Wordlist

Công cụ cung cấp 3 wordlist chính:

### **plugins.txt** (WordPress.org API)
- Chứa **tất cả plugins phổ biến** (>100 active installs) từ WordPress.org
- Tối ưu cho scan nhanh, phát hiện plugins thường được sử dụng
- Được tạo/cập nhật bằng lệnh: `./wp_scanner -collect`
- Định dạng: `slug|name|version|active_installs`
- Tổng plugins: ~16,000+

### **customs.txt** (WPScan Wordlist)
- Chứa wordlist từ công cụ **WPScan** (nổi tiếng trong pentesting)
- Bao gồm cả plugins ít phổ biến, plugin đã lỗi thời, hoặc có lỗ hổng
- Tối ưu để phát hiện plugin lạ, plugin nguy hiểm
- Định dạng: `slug|name|version|active_installs` hoặc `slug` (một dòng một plugin)
- Tổng plugins: ~100,000+

### **plugins_all.txt** (Combined/Merged)
- File **tổng hợp** từ `plugins.txt` + `customs.txt` (đã loại bỏ duplicates)
- Đầy đủ nhất, phát hiện plugin tối đa nhưng scan chậm hơn
- Sử dụng khi muốn comprehensive scan, bất kể WordPress.org hay wpscan có
- Tổng plugins: ~116,000+

### Cách sử dụng
```bash
# Dùng wordlist mặc định (plugins.txt)
./wp_scanner -u https://example.com

# Dùng WPScan wordlist
./wp_scanner -u https://example.com -w customs.txt

# Dùng full combined wordlist
./wp_scanner -u https://example.com -w plugins_all.txt

# Bổ sung plugin custom
./wp_scanner -u https://example.com -c custom_plugins.txt

# Tự tạo wordlist từ WordPress.org
./wp_scanner -collect
./wp_scanner -collect -min-installs 1000
./wp_scanner -collect -full  # Collect tất cả (~70,000 plugins, rất lâu)
```

## Build & Install

### Build từ source
```
go build -o wp_scanner wp_plugin_scanner.go
```

### Install bằng Go (global)
```
go install
```

Sau khi install, tool có thể chạy từ bất cứ đâu với lệnh `wp_scanner` (cần đảm bảo $GOPATH/bin trong $PATH).

## Disclaimer & Liability

- **Giấy phép sử dụng**: Công cụ này được cung cấp "as-is" cho mục đích kiểm thử bảo mật có trách nhiệm, đánh giá và nghiên cứu. Người sử dụng chịu trách nhiệm hoàn toàn về cách dùng công cụ.
- **Không vì mục đích bất hợp pháp**: Không được dùng công cụ để xâm nhập, quét hoặc khai thác các hệ thống mà bạn không có quyền rõ ràng. Việc sử dụng trái phép có thể dẫn đến trách nhiệm hình sự và dân sự.
- **Không bảo hành**: Tác giả và nhóm phát triển không chịu bất kỳ trách nhiệm nào cho thiệt hại trực tiếp, gián tiếp hay ngẫu nhiên phát sinh từ việc sử dụng công cụ này.
- **Tác giả / Nhóm**: Đây là sản phẩm của vibe-coding.

Vui lòng đọc kỹ và tuân thủ luật pháp địa phương trước khi sử dụng.
## License
MIT
