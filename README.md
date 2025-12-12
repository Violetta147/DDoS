# Hệ thống Phát hiện DDoS - CNN Real-time

Hệ thống phát hiện DDoS sử dụng mô hình CNN kết hợp với rule-based detection để phát hiện tấn công trong thời gian thực.

## 🚀 Hướng dẫn nhanh

### 1. Train Model
```bash
python train_lite_model.py
```
**Yêu cầu**: File `data/DDoS.csv`  
**Output**: `models/cnn_lite_model.h5`, `models/cnn_lite_scaler.pkl`, `models/cnn_lite_feature_names.pkl`

### 2. Capture Traffic (Sniffer)
**Option A - Fast Sniffer (Raw Socket, cần Admin):**
```bash
python gui_fast_sniffer.py
```
- Chỉnh interface trong code
- Nhanh hơn nhưng cần quyền Admin trên Windows

**Option B - Scapy Sniffer (không cần Admin):**
```bash
python gui_sniffer_final.py
```
- Chọn interface → Click START
- Chậm hơn nhưng không cần Admin

**Output**: `data/live_flow.csv`

### 3. Detection System
```bash
python lite_detection_system.py --csv-path data/live_flow.csv
```

**Logic Detection:**
- 🔴 **DDoS**: AI detect (proba > 0.5)
- 🟡 **Warning**: AI miss nhưng lưu lượng cao (>2000 pkts)
- 🟢 **Normal**: AI báo normal và lưu lượng thấp

### 4. Test Attack (Demo)
```bash
# TCP Flood
python tcp_flood_pro.py --target 192.168.1.111 --port 8080 --duration 60 --workers 50
```

## 📋 Cấu trúc

```
├── data/
│   ├── DDoS.csv              # Dataset training
│   └── live_flow.csv          # Dữ liệu capture real-time
├── models/                    # Models đã train
├── train_lite_model.py       # Training script
├── gui_fast_sniffer.py       # Fast sniffer (raw socket)
├── gui_sniffer_final.py      # Scapy sniffer
├── lite_detection_system.py  # Detection system
└── tcp_flood_pro.py          # Attack simulator
```

## ⚠️ Lưu ý

- **Quyền Admin**: `gui_fast_sniffer.py` cần quyền Admin trên Windows
- **Dependencies**: `pip install -r requirements.txt`
- **Calibration**: Sniffer sử dụng calibration để amplify signals cho model
- **Pure AI Mode**: Detection system hiện chỉ dùng AI (đã tắt High Rate Rule)

## 🔧 Troubleshooting

- **Lỗi IP không hợp lệ**: Click "Auto-detect" hoặc "List IPs" trong GUI
- **Detection đứng**: File CSV được recreate → Detection tự động reset offset
- **Không có flows**: Kiểm tra network traffic và IP binding
