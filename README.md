# Monitoring
Windows Server Monitoring & Self-Healing System
Hệ thống giám sát tự động và tự phục hồi (Self-healing) dành cho hạ tầng Windows Server, tích hợp cảnh báo thời gian thực qua Telegram và quản lý tập trung bằng Windows Service.

📌 Tổng quan dự án
Dự án này triển khai một giải pháp giám sát chủ động giúp duy trì tính sẵn sàng của các dịch vụ cốt lõi (AD, DNS, DHCP) và theo dõi hiệu suất hệ thống. Thay vì kiểm tra thủ công, hệ thống tự động phát hiện sự cố, tự động khởi động lại dịch vụ và báo cáo tức thời cho quản trị viên.

✨ Tính năng cốt lõi
Vận hành như Windows Service: Sử dụng NSSM để duy trì script chạy ngầm ổn định 24/7.
Tự phục hồi (Self-healing): Tự động khởi động lại các dịch vụ ưu tiên (DNS, DHCP, Netlogon...) khi bị dừng đột ngột.
Cảnh báo Telegram Bảo mật: Sử dụng SecureString để lưu trữ mã Token và ChatID, gửi thông báo chi tiết về sự cố an ninh (Account Lockout) và hiệu suất.
Theo dõi Hiệu suất Nâng cao: Giám sát CPU Queue, RAM Page Faults, và Disk Queue Length để phát hiện thắt cổ chai (Bottleneck).
Quản lý tập trung: Mọi ngưỡng cảnh báo và danh sách dịch vụ được định nghĩa trong tệp JSON.

📂 Cấu trúc thư mục (C:\Monitoring)
Hệ thống được tổ chức chặt chẽ theo cấu trúc sau:
C:\Monitoring\
├── Config\
│   └── monitoring-config.json         # Cấu hình ngưỡng tài nguyên và dịch vụ
├── Data\
│   ├── DC01-healthYYYYMMDD.json       # Dữ liệu hiệu suất lưu trữ hàng ngày
│   └── event-bookmarks.json           # Đánh dấu vị trí log cuối cùng đã đọc
├── Logs\
│   ├── DC01-Health.txt                # Nhật ký hoạt động của hệ thống giám sát
│   ├── Service-stdout.log             # Log đầu ra của Windows Service
│   └── Service-stderr.log             # Log lỗi của Windows Service
├── Scripts\
│   ├── Server\
│   │   └── Monitor-DC01-Service.ps1   # Script logic giám sát chính
│   ├── Install-DC01MonitoringService.ps1 # Script cài đặt Service qua NSSM
│   └── Setup-TelegramSecrets.ps1      # Script thiết lập mã bảo mật Telegram
├── Secure\
│   ├── telegram-bot-token.txt         # Mã Token (đã mã hóa SecureString)
│   └── telegram-chatid.txt            # Chat ID (đã mã hóa SecureString)
└── Tools\
    └── nssm.exe                       # Công cụ quản lý Windows Service

🚀 Quy trình cài đặt và Triển khai
Để vận hành hệ thống, thực hiện theo các bước sau:
1. Thiết lập Bảo mật Telegram
Chạy script sau để nhập Token và ChatID của Bot. Dữ liệu sẽ được mã hóa và lưu vào thư mục Secure\:
.\Scripts\Setup-TelegramSecrets.ps1
2. Cấu hình hệ thống
Chỉnh sửa tệp Config\monitoring-config.json để thiết lập IP Server, dải IP DHCP và các ngưỡng cảnh báo (CPU, RAM, Disk).
3. Cài đặt Windows Service
Sử dụng script cài đặt tự động để đăng ký hệ thống với Windows Service qua NSSM:
.\Scripts\Install-DC01MonitoringService.ps1
Sau khi cài đặt, mở services.msc, tìm "DC01-Monitoring-Service" và Start.

📊 Phân tích & Báo cáo
Dữ liệu thô: Được lưu dưới dạng JSON trong thư mục Data\, cho phép dễ dàng tích hợp với các công cụ phân tích dữ liệu hoặc vẽ biểu đồ sau này.
Nhật ký: Mọi hành động phục hồi (Restart service) và cảnh báo đều được ghi chi tiết trong Logs\DC01-Health.txt.
