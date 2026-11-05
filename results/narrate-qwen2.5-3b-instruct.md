## บทสรุปผู้บริหาร (ร่างโดย LLM ภายในองค์กร ต้องตรวจทาน)

### 1. Executive Summary
The IT department's network security has been assessed and found to have several critical and high-level vulnerabilities. The primary issues include a policy that allows all traffic from any source, an administrator account with no trusted hosts, and management access enabled on an internet-facing interface. These issues could expose the network to unauthorized access and data breaches. Immediate attention is required to address these vulnerabilities to ensure the network's security compliance and protection.

### 2. Prioritized Remediation Plan (Top 5)

1. **FW-ANY-ANY (Critical)**: Modify policy 9 "TEMP-allow-all" to restrict traffic to specific sources and services.
   - **Control**: A.8.20, A.8.22
2. **FW-INBOUND-OPEN (High)**: Restrict inbound traffic to specific services and sources.
   - **Control**: A.8.20, A.8.21
3. **ADM-NO-TRUSTHOST (High)**: Implement trusted hosts for the administrator account.
   - **Control**: A.8.2, A.8.5
4. **MGMT-ON-WAN (High)**: Remove management access from internet-facing interfaces.
   - **Control**: A.8.20, A.8.21, A.8.8
5. **MGMT-CLEARTEXT (High)**: Secure management protocols by enabling HTTPS and disabling Telnet.
   - **Control**: A.8.21, A.8.24

### 3. Residual Risk
After implementing the prioritized remediation plan, residual risks will be significantly reduced, but ongoing monitoring and periodic security assessments will be necessary to maintain the network's security posture.

_model: qwen2.5:3b-instruct, 660.2 s_

# รายงานทบทวนการตั้งค่าไฟร์วอลล์: หลักฐานประกอบ ISO/IEC 27001:2022

## ขอบเขต

| | |
|---|---|
| อุปกรณ์ | FG600F |
| เฟิร์มแวร์ | 7.2.10 build 1706 |
| VDOM | root |
| นโยบายไฟร์วอลล์ | 10 (9 enabled) |
| วันที่วิเคราะห์ | 2026-11-04 |

## สรุป

| ระดับความรุนแรง | จำนวน |
|---|---|
| วิกฤต | 1 |
| สูง | 7 |
| กลาง | 6 |
| ต่ำ | 5 |
| ข้อมูล | 2 |

มาตรการใน Annex A ที่พบประเด็น: A.5.17 ข้อมูลการพิสูจน์ตัวตน; A.5.37 ขั้นตอนการปฏิบัติงานที่เป็นลายลักษณ์อักษร; A.8.2 สิทธิ์การเข้าถึงระดับสูง; A.8.5 การพิสูจน์ตัวตนที่มั่นคงปลอดภัย; A.8.8 การจัดการช่องโหว่ทางเทคนิค; A.8.9 การบริหารจัดการการตั้งค่า; A.8.15 การบันทึกล็อก; A.8.16 การเฝ้าติดตาม; A.8.20 ความมั่นคงปลอดภัยของเครือข่าย; A.8.21 ความมั่นคงปลอดภัยของบริการเครือข่าย; A.8.22 การแบ่งแยกเครือข่าย; A.8.24 การใช้การเข้ารหัสลับ

## ประเด็นที่พบ

### 1. [วิกฤต] นโยบายอนุญาตทุกต้นทาง ทุกปลายทาง ทุกบริการ (FW-ANY-ANY)

- ISO/IEC 27001:2022: A.8.20 ความมั่นคงปลอดภัยของเครือข่าย, A.8.22 การแบ่งแยกเครือข่าย
- เหตุผล: กฎ any-any-ALL ทำให้การแบ่งแยกเครือข่ายระหว่างอินเทอร์เฟซนั้นไม่มีผล

หลักฐาน:

- policy 9 "TEMP-allow-all" (บรรทัด 259): port2 -> port3, srcaddr/dstaddr all, service ALL

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config firewall policy
    edit 9
        set dstaddr "<specific-object>"
        set service "<specific-services>"
    next
end
```

### 2. [สูง] นโยบายขาเข้าจากอินเทอร์เน็ตเปิดทุกต้นทางและทุกบริการ (FW-INBOUND-OPEN)

- ISO/IEC 27001:2022: A.8.20 ความมั่นคงปลอดภัยของเครือข่าย, A.8.21 ความมั่นคงปลอดภัยของบริการเครือข่าย
- เหตุผล: กฎขาเข้าจาก WAN ควรระบุเฉพาะบริการที่เปิดให้บริการจริง

หลักฐาน:

- policy 3 "Web-Portal-Inbound" (บรรทัด 194): from wan1 to Web-Portal on ALL services

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config firewall policy
    edit 3
        set service "HTTPS"
    next
end
```

### 3. [สูง] นโยบายไม่มีวันถูกใช้งาน (ถูกบังโดยนโยบายก่อนหน้าที่มี action ต่างกัน) (FW-SHADOWED)

- ISO/IEC 27001:2022: A.8.9 การบริหารจัดการการตั้งค่า, A.8.20 ความมั่นคงปลอดภัยของเครือข่าย
- เหตุผล: FortiOS ตรวจนโยบายจากบนลงล่าง กฎที่อยู่หลังจึงไม่ถูกใช้ และเจตนาของกฎ (มักเป็นการบล็อก) ไม่ถูกบังคับใช้

หลักฐาน:

- policy 5 "Lab-Block-Telnet" (บรรทัด 216): covered by policy 1 "Student-to-Internet" (accept) above it; the intended block is NOT enforced

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
# Move policy 5 "Lab-Block-Telnet" above policy 1 "Student-to-Internet", or narrow policy 1 "Student-to-Internet"
config firewall policy
    move 5 before 1
end
```

### 4. [สูง] บัญชีผู้ดูแลระบบล็อกอินได้จากทุก IP (ไม่กำหนด trusted host) (ADM-NO-TRUSTHOST)

- ISO/IEC 27001:2022: A.8.2 สิทธิ์การเข้าถึงระดับสูง, A.8.5 การพิสูจน์ตัวตนที่มั่นคงปลอดภัย
- เหตุผล: Trusted host จำกัดตำแหน่งที่รหัสผ่านผู้ดูแลที่ถูกขโมยจะใช้งานได้

หลักฐาน:

- admin "admin" (บรรทัด 57): accprofile super_admin

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config system admin
    edit "admin"
        set trusthost1 <mgmt-subnet> <mask>
    next
end
```

### 5. [สูง] เปิดการจัดการ (HTTPS/SSH/SNMP) บนอินเทอร์เฟซที่ติดอินเทอร์เน็ต (MGMT-ON-WAN)

- ISO/IEC 27001:2022: A.8.20 ความมั่นคงปลอดภัยของเครือข่าย, A.8.21 ความมั่นคงปลอดภัยของบริการเครือข่าย, A.8.8 การจัดการช่องโหว่ทางเทคนิค
- เหตุผล: ช่องโหว่ส่วนจัดการของ FortiOS เช่น CVE-2022-40684 และ CVE-2024-55591 ถูกโจมตีจริงผ่านหน้าจัดการที่เปิดสู่อินเทอร์เน็ต

หลักฐาน:

- interface "wan1" (บรรทัด 17): role/name looks internet-facing; allowaccess ping https ssh

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config system interface
    edit "wan1"
        set allowaccess ping
    next
end
# Manage via a dedicated mgmt interface or VPN instead
```

### 6. [สูง] เปิดโปรโตคอลจัดการแบบไม่เข้ารหัส (HTTP/Telnet) (MGMT-CLEARTEXT)

- ISO/IEC 27001:2022: A.8.21 ความมั่นคงปลอดภัยของบริการเครือข่าย, A.8.24 การใช้การเข้ารหัสลับ
- เหตุผล: รหัสผ่านผู้ดูแลอาจถูกดักจับได้ระหว่างทาง

หลักฐาน:

- interface "port1" (บรรทัด 31): allowaccess ping https http

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config system interface
    edit "port1"
        set allowaccess ping https
    next
end
```

### 7. [สูง] SNMP community ใช้ชื่อค่าเริ่มต้น (public/private) (SNMP-DEFAULT-COMMUNITY)

- ISO/IEC 27001:2022: A.5.17 ข้อมูลการพิสูจน์ตัวตน, A.8.21 ความมั่นคงปลอดภัยของบริการเครือข่าย
- เหตุผล: community ค่าเริ่มต้นเป็นสิ่งแรกที่เครื่องมือสแกนจะลอง

หลักฐาน:

- snmp community 1 (บรรทัด 77): name "public"

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config system snmp community
    edit 1
        set name "<random-32-chars>"
    next
end
# Prefer SNMPv3 (config system snmp user)
```

### 8. [สูง] ไม่ได้ส่งล็อกออกไปเก็บภายนอก (FortiAnalyzer, syslog หรือ FortiCloud) (LOG-NO-REMOTE)

- ISO/IEC 27001:2022: A.8.15 การบันทึกล็อก, A.8.16 การเฝ้าติดตาม
- เหตุผล: ล็อกอยู่บนไฟร์วอลล์เท่านั้น SIEM จึงมองไม่เห็นและล็อกอาจสูญหายหรือถูกแก้ไข

หลักฐาน:

- log settings: no FortiAnalyzer/syslog/FortiCloud destination with status enable

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config log syslogd setting
    set status enable
    set server "<siem-collector-ip>"
    set mode reliable
end
```

### 9. [กลาง] นโยบายอนุญาตไม่บันทึกล็อกทราฟฟิก (FW-NO-LOG)

- ISO/IEC 27001:2022: A.8.15 การบันทึกล็อก, A.8.16 การเฝ้าติดตาม
- เหตุผล: หากไม่มีล็อก SIEM/SOC จะสืบสวนทราฟฟิกที่กฎนี้อนุญาตไม่ได้

หลักฐาน:

- policy 4 (บรรทัด 214): set logtraffic disable

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config firewall policy
    edit 4
        set logtraffic all
    next
end
```

### 10. [กลาง] บัญชี super_admin ไม่ใช้การยืนยันตัวตนสองปัจจัย (ADM-NO-MFA)

- ISO/IEC 27001:2022: A.8.5 การพิสูจน์ตัวตนที่มั่นคงปลอดภัย
- เหตุผล: บัญชีสิทธิ์สูงควรบังคับใช้ MFA

หลักฐาน:

- admin "admin" (บรรทัด 57): two-factor disable

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config system admin
    edit "admin"
        set two-factor fortitoken-cloud
    next
end
```

### 11. [กลาง] ปิด strong-crypto (SYS-WEAK-CRYPTO)

- ISO/IEC 27001:2022: A.8.24 การใช้การเข้ารหัสลับ
- เหตุผล: อนุญาต cipher ที่อ่อนแอสำหรับ HTTPS/SSH และบริการอื่น

หลักฐาน:

- system global (บรรทัด 10): set strong-crypto disable

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config system global
    set strong-crypto enable
end
```

### 12. [กลาง] ไม่ได้เปิดใช้นโยบายรหัสผ่านผู้ดูแลระบบ (SYS-PASSWORD-POLICY)

- ISO/IEC 27001:2022: A.5.17 ข้อมูลการพิสูจน์ตัวตน
- เหตุผล: ไม่มีการบังคับความยาวและความซับซ้อนของรหัสผ่านผู้ดูแล

หลักฐาน:

- system password-policy: block not present (default disabled)

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config system password-policy
    set status enable
    set minimum-length 12
    set min-upper-case-letter 1
    set min-number 1
    set min-non-alphanumeric 1
end
```

### 13. [กลาง] IPsec phase 1 อนุญาตอัลกอริทึมที่อ่อนแอ (DES/3DES/MD5/SHA-1 หรือ DH group 1/2/5) (VPN-WEAK-IKE)

- ISO/IEC 27001:2022: A.8.24 การใช้การเข้ารหัสลับ
- เหตุผล: อัลกอริทึมเหล่านี้เลิกแนะนำให้ใช้แล้ว

หลักฐาน:

- vpn ipsec phase1-interface "to-Partner" (บรรทัด 153): proposal aes128-sha1 3des-sha1; dhgrp 5 2

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config vpn ipsec phase1-interface
    edit "to-Partner"
        set proposal aes256gcm-prfsha384 aes256-sha256
        set dhgrp 20 21
    next
end
```

### 14. [กลาง] SSL-VPN เปิดรับการเชื่อมต่อบนอินเทอร์เฟซ (VPN-SSL-EXPOSED)

- ISO/IEC 27001:2022: A.8.8 การจัดการช่องโหว่ทางเทคนิค, A.8.21 ความมั่นคงปลอดภัยของบริการเครือข่าย
- เหตุผล: SSL-VPN มีช่องโหว่ที่ถูกโจมตีจริงหลายครั้ง (เช่น CVE-2023-27997, CVE-2024-21762) ควรยืนยันว่าแพตช์แล้วและวางแผนย้ายไป IPsec/ZTNA

หลักฐาน:

- vpn ssl settings (บรรทัด 162): source-interface wan1

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
# Verify build against FortiGuard PSIRT; plan migration to IPsec dial-up or ZTNA
```

### 15. [ต่ำ] นโยบายออกอินเทอร์เน็ตไม่มี security profile (FW-NO-UTM-WAN)

- ISO/IEC 27001:2022: A.8.20 ความมั่นคงปลอดภัยของเครือข่าย
- เหตุผล: ทราฟฟิกออกอินเทอร์เน็ตไม่ถูกตรวจด้วย IPS, Web filter หรือ Antivirus

หลักฐาน:

- policy 2 "Staff-to-Internet" (บรรทัด 183): -> virtual-wan-link without utm-status enable

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config firewall policy
    edit 2
        set utm-status enable
        set ips-sensor "default"
        set webfilter-profile "default"
        set ssl-ssh-profile "certificate-inspection"
    next
end
```

### 16. [ต่ำ] นโยบายใช้ schedule แบบครั้งเดียวที่หมดอายุแล้ว (FW-EXPIRED-SCHEDULE)

- ISO/IEC 27001:2022: A.8.9 การบริหารจัดการการตั้งค่า
- เหตุผล: กฎนี้ไม่มีผลแล้วและควรลบออก

หลักฐาน:

- policy 6 "Temp-Vendor-SSH" (บรรทัด 235): schedule "Exam-Week-2025" ended

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config firewall policy
    delete 6
end
```

### 17. [ต่ำ] มีนโยบายที่ปิดใช้งานค้างอยู่ (FW-DISABLED)

- ISO/IEC 27001:2022: A.8.9 การบริหารจัดการการตั้งค่า
- เหตุผล: กฎที่ปิดไว้อาจถูกเปิดใช้โดยไม่ตั้งใจ และทำให้การตรวจสอบยุ่งยาก

หลักฐาน:

- policy 7 "Old-Migration-2022" (บรรทัด 238): accept port2 -> port1

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config firewall policy
    delete 7
end
```

### 18. [ต่ำ] นโยบายซ้ำซ้อน (ถูกครอบคลุมโดยนโยบายก่อนหน้าที่มี action เดียวกัน) (FW-REDUNDANT)

- ISO/IEC 27001:2022: A.8.9 การบริหารจัดการการตั้งค่า
- เหตุผล: กฎซ้ำซ้อนทำให้การทบทวนช้าลงและบดบังการเปลี่ยนแปลงจริง

หลักฐาน:

- policy 8 "Staff-Portal-HTTPS" (บรรทัด 249): covered by policy 4 (accept) above it

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config firewall policy
    delete 8
end
```

### 19. [ต่ำ] ตั้งเวลา idle timeout ของผู้ดูแลนานเกิน 15 นาที (SYS-ADMIN-TIMEOUT)

- ISO/IEC 27001:2022: A.8.5 การพิสูจน์ตัวตนที่มั่นคงปลอดภัย
- เหตุผล: เซสชันผู้ดูแลที่ทิ้งไว้ยังใช้งานได้

หลักฐาน:

- system global (บรรทัด 7): admintimeout 60

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config system global
    set admintimeout 10
end
```

### 20. [ข้อมูล] นโยบายอนุญาตไม่มีชื่อและไม่มีคำอธิบาย (FW-UNDOCUMENTED)

- ISO/IEC 27001:2022: A.5.37 ขั้นตอนการปฏิบัติงานที่เป็นลายลักษณ์อักษร, A.8.9 การบริหารจัดการการตั้งค่า
- เหตุผล: ผู้ตรวจและผู้ดูแลคนถัดไปไม่ทราบว่ากฎนี้มีไว้เพื่ออะไรและใครเป็นเจ้าของ

หลักฐาน:

- policy 4 (บรรทัด 206): no name, no comments

แนวทางแก้ไข (ตรวจทานก่อนนำไปใช้):

```
config firewall policy
    edit 4
        set name "<purpose>"
        set comments "Owner: <unit>; Ticket: <ITSM-id>"
    next
end
```

### 21. [ข้อมูล] เวอร์ชันเฟิร์มแวร์ที่ต้องตรวจเทียบกับ FortiGuard PSIRT (FW-VERSION)

- ISO/IEC 27001:2022: A.8.8 การจัดการช่องโหว่ทางเทคนิค
- เหตุผล: เครื่องมือนี้ทำงานแบบออฟไลน์และไม่ทราบประกาศช่องโหว่ล่าสุด

หลักฐาน:

- FG600F FortiOS 7.2.10 build 1706 (บรรทัด 1): check https://www.fortiguard.com/psirt for this version

## วิธีการและข้อจำกัด

- วิเคราะห์แบบสถิตจากไฟล์สำรองการตั้งค่า ไม่มีการเปลี่ยนแปลงอุปกรณ์ใด ๆ
- ไฟล์สำรองไม่มีข้อมูล hit count จึงยังตรวจกฎที่ไม่ถูกใช้งานไม่ได้
- อินเทอร์เฟซที่ติดอินเทอร์เน็ตระบุจาก `set role wan` และชื่ออินเทอร์เฟซ ควรยืนยันอีกครั้ง
- การตรวจกฎที่ถูกบังคำนวณจาก IPv4, service, interface และ schedule โดยข้ามกฎที่มี user, group, ISDB หรือ negate
- ยังไม่วิเคราะห์นโยบาย IPv6

