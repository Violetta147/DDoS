# DDoS Lite Demo (Python)

Hướng dẫn chạy pipeline: train, sniff, detect, and flood test
Vấn đề hiện tại:
- model thì build ngon,feature ngon gần giống paper thầy Vân nhưng kết quả thực tế detect
quá dở khả năng do scapy bắt chậm hoặc dữ liệu dở mặc dù feature ngon
và mình test ko đúng cách (rõ ràng cần có tool ví dụ hping3 hoặc phải làm đúng theo cái dataset trên mạng(tức dữ liệu chuyên nghiệp chứ ko phải mấy trò mèo hping3 hoặc file python của mình))


## 1) Train lite model
- Requires `data/DDoS.csv`.
- Run: `python train_lite_model.py` hoặc chạy từng cell hoặc shift +Enter từng cell tự động xuống cell tiếp theo (ta thì dùng shift + Enter)
- Outputs (in `models/`): `cnn_lite_model.h5`, `cnn_lite_scaler.pkl`, `cnn_lite_feature_names.pkl`.

## 2) Sniffer (capture-only, calibrated)
- dữ liệu sniff được đưa vào `data/live_flow.csv`.
- Run: `python gui_sniffer_final.py`
  - Select interface, click START.
  - File written: `data/live_flow.csv` (lite feature schema).

## 3) Detection (AI + rule hybrid)
- Đọc file CSV và alert per flow.
- Run: `python lite_detection_system.py --csv-path data/live_flow.csv`
  - Default `--batch-size=1` for near real-time.
  - Hybrid logic: AI predicts; if AI says normal but `Total Fwd Packets > 1000`, raise DDoS (High Rate Rule).

## 4) Flood tests (for demo)
- UDP flood (existing): `python flood_test.py` (edit target/duration inside if needed).
- TCP flood (aggressive, multi-thread):  
  `python flood_test_tcp.py --target 127.0.0.1 --port 8080 --duration 10 --size 512 --workers 20 --timeout 0.02`
  - Needs target port open; otherwise sends will fail (0 packets).

## Notes
- Sniffer uses calibration to amplify signals for the model (microsecond timing, packet/byte multipliers).
- Ensure virtual env has required deps (tensorflow, scapy, pandas, sklearn, watchdog, colorama, joblib).  

Vấn đề: "Model AI báo Normal (0.0) dù đang bị tấn công Flood".

Vấn đề cốt lõi không phải do bạn làm sai, mà là do sự "Lệch pha" (Mismatch):

Model: Được học trên dữ liệu chuẩn công nghiệp (tốc độ cao, đơn vị micro-giây).

Thực tế (Demo): Sniffer dùng thư viện Scapy (Python) bắt gói tin chậm, tool tấn công là UDP 1 chiều (khác với TCP DDoS trong tập train).

Dưới đây là 3 Hướng Giải Quyết cụ thể, từ "Dễ nhất" đến "Xịn nhất":

1. Hướng "Data Scientist" (Khuyên dùng nhất cho Demo)
Ý tưởng: "Nhập gia tùy tục". Thay vì ép AI hiểu dữ liệu chuẩn, hãy dạy lại AI bằng chính dữ liệu "chậm" và "đơn giản" mà máy bạn đang tạo ra.

Cách làm:

Dùng gui_sniffer.py để thu thập 1 file normal.csv (lướt web) và 1 file attack.csv (chạy tool flood).

Viết script gộp 2 file này lại và Train một model mới trong 30 giây.

Chạy demo với model mới này.

Ưu điểm: Đảm bảo 100% hoạt động vì dữ liệu lúc train và lúc thi giống hệt nhau. Không cần lo Scapy chậm hay nhanh.

Nhược điểm: Model này chỉ "khôn" trên máy bạn, mang sang môi trường khác có thể cần train lại.

2. Hướng "System Engineer" (Nâng cấp Sniffer)
Ý tưởng: Thay thế "cảm biến" Scapy chậm chạp bằng công nghệ nhanh hơn để bắt trọn vẹn tốc độ tấn công.

Cách làm:

Bỏ thư viện scapy.

Viết lại Sniffer sử dụng Raw Sockets (socket thuần của Python). Đây là cách giao tiếp trực tiếp với card mạng ở tầng thấp, bỏ qua các lớp xử lý rườm rà.

Ưu điểm: Tốc độ bắt gói tin tăng gấp 10-20 lần. Dữ liệu đầu vào sẽ sát với thực tế tấn công hơn. Nhìn code rất "ngầu" và chuyên sâu (Low-level programming).

Nhược điểm: Code phức tạp hơn Scapy một chút (phải tự giải mã byte header IP/TCP).

3. Hướng "Quick Fix" (Hiệu chỉnh / Calibration)
Ý tưởng: Giữ nguyên mọi thứ, chỉ "hack" nhẹ vào số liệu trước khi đưa cho AI.

Cách làm:

Trong code Sniffer: Nếu thấy số lượng gói tin > 10/giây (ngưỡng cao của Scapy), tự động nhân số liệu lên 100 lần, chia nhỏ thời gian IAT đi 100 lần.

Chuyển đổi đơn vị giây -> micro-giây.

Ưu điểm: Sửa nhanh, không cần train lại, không cần viết lại sniffer.

Nhược điểm: Mang tính chất "đối phó", số liệu hiển thị trên màn hình là số ảo (đã nhân lên).