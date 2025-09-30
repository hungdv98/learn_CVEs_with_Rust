# Tìm hiểu về CVE (Common Vulnerabilities and Exposures)
## I. Tổng quan
+ Định nghĩa: 
    - Danh sách lỗ hổng công khai
    - Mã định danh chuẩn hóa
    - Ví dụ: CVE-2021-44228
+ Ai quản lý CVE:
    - **MITRE:** tổ chức trung tâm điều phối chương trình CVE
    - **CNA (CVE Numbering Authorities):** đơn vị được ủy quyền cấp CVE
    - Nếu không có CNA nào phục trách, MITRE sẽ tự cấp CVE
+ Cấu trúc CVE:
    - **CVE ID:** CVE-YYYY-NNNNN
    - **Mô tả ngắn:** nêu lỗ hổng là gì, xảy ra ở đâu, và ảnh hưởng thế nào
    - **Tham chiếu:** đường dẫn bản vá
    - CVE chỉ là **mã định danh + mô tả ngắn gọn + tham chiếu**, không chứa điểm số hay kỹ thuật sâu
+ Điểm số CVSS
    - **CVSS (Common Vulnerability Scoring System):** hệ thống chấm điểm 0-10 để đánh giá mức độ nghiêm trọng.
    - Gồm 3 nhóm:
        + **Base:** đặc tính nội tại (tấn công từ xa/lân cận, cần quyền nào)
        + **Temporal:** thay đổi theo thời gian (có exploit chưa, đã patch chưa)
        + **Environmental:** phụ thuộc môi trường 
    - **CVSS giúp ưu tiên vá**, nhưng không thay thế được phân tích rủi ro theo ngữ cảnh
+ Quy trình vòng đời một CVE
    1. Discovery:
        - Phát hiện lỗi
    2. Reporting/Coordination:
        - Gửi báo cáo cho vendor/CNA
    3. CVE ID Request/assignment:
        - CNA/MITRE cấp mã
    4. Fix/patch:
        - Vendor phát hành patch hoặc workaround
    5. Advisory publication:
        - Đưa ra chi tiết, gắn CVE ID
    6. Data aggregation:
        - NVD, scanner ingest dữ liệu
    7. Detection/remediation:
        - Triển khai bản vá và kiểm thử
    8. Post mortem/lessons learned:
        - Rút kinh nghiệm và cập nhật quy trình
+ Các mô hình công bố lỗ hổng
    - **Responsible disclosure/Coordinated disclosure:** báo riêng cho vendor, chờ fix rồi mới công khai
    - **Full disclosure:** công bố ngay lập tức 
    - **Embargo:** giữ bí mật một thời gian theo thỏa thuận
+ Cách dùng CVE trong thực tế
    - **Quản lý tài sản:** quét phần mềm --> map sang CPE (Common Platform Enumeration) --> đối chiếu CVE
    - **Quản lý bản vá:** ưu tiên vá theo CVSS, xác định exploit công khai
    - **Threat Intelligence:** theo dõi CVE nào đang khai thác
    - **Compliance:** PCI DSS, ISO 27001
    - **Supply Chain:** SBOM (Software Bill of Materials) giúp tìm CVE trong dependencies
+ Điểm hạn chế
    ```
    + CVE là mã định danh, không phản ánh mức độ nguy hiểm thực sự
    + Việc gán CVSS có thể chậm hoặc chưa chuẩn
    + Scanner có thể false positive do mapping CPE sai
    + Quá phụ thuộc CVSS nên có thể ưu tiên sai (context quan trọng hơn)
    ```

==> `Tổng kết:`
    
```
+ CVE = mã định danh lỗ hổng bảo mật
+ CVE + CVSS + ngữ cảnh = mức độ rủi ro thực tế
+ Theo dõi MITRE + NVD + Vendor Advisory
+ Luôn ưu tiên vá theo: exploit công khai + internet-facing + business critical
+ Tích hợp quy trình quản lý CVE vào patch management & threat intelligence
```

## II. Khái niệm CVE, CWE, CAPEC và NVD

| Thuộc tính | CVE | CWE | CAPEC | NVD |
| ---------- | --- | --- | ----- | --- |
| Tên đầy đủ | Common Vulnerabilities and Exposures | Common Weakness Enumeration | Common Attack Pattern Enumeration and Classification | National Vulnerability Database |
| Định nghĩa | Mã định danh chuẩn cho lỗ hổng được công khai | Danh mục điểm yếu trong phần mềm hoặc thiết kế | Danh mục các mẫu tấn công thường gặp mà kẻ tấn công dùng để khai thác lỗ hổng | Cơ sở dữ liệu Mỹ, mở rộng thông tin CVE với metadata (CVSS, CPE, tham chiếu) |
| Mục tiêu chính | Chuẩn hóa cách gọi tên lỗ hổng để mọi bên tham chiếu | Chuẩn hóa cách phân loại và mô tả lỗi lập trình/thiết kế | Chuẩn hóa mô tả chiến thuật/kỹ thuật tấn công | Cung cấp dữ liệu chi tiết để hỗ trợ đánh giá, phân tích rủi ro, tự động hóa quét lỗ hổng |
| Ví dụ | CVE-2021-44228 (Log4Shell trong Log4j) | CWE-79 (Cross-site Scripting) | CAPEC-66 (SQL Injection) | NVD entry cho CVE-2021-44228 có CVSS=10, CPE affected, link patch |
| Đối tượng sử dụng | Người nghiên cứu, vendor, quản trị viên, scanner | Lập trình viên, nhà phát triển, QA, AppSec | Chuyên gia pentest, Red team, TI Analyst | Doanh nghiệp, scanner, SIEM, Vulnerability management |
| Mối quan hệ | Xác định sự cố cụ thể | Mô tả loại điểm yếu (nguyên nhân gốc) mà CVE có thể thuộc về | Mô tả cách tấn công khai thác vào CVE | Cơ sở dữ liệu lưu và bổ sung thông tin cho CVE (CVSS, CPE, reference) |

```
Lưu ý:
+ CWE = gốc rễ tạo điểm yếu trong phần mềm
+ CVE = trường hợp cụ thể của lỗi được phát hiện
+ CAPEC = cách hacker khai thác lỗ hổng
+ NVD = "sổ cái" lưu thông tin CVE + chấm điểm + metadata để doanh nghiệp sử dụng
```