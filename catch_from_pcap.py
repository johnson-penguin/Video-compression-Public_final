import pyshark
def extract_raw_packets(pcap_file, packet_numbers):
    # 使用 pyshark 讀取 pcap 檔案，設定 use_json=True 和 include_raw=True
    cap = pyshark.FileCapture(pcap_file, keep_packets=True, use_json=True, include_raw=True)

    # 迭代並提取指定的封包編號
    for packet_number in packet_numbers:
        try:
            packet = cap[packet_number]  # 根據封包編號取得封包

            # 獲取封包的原始二進制數據
            raw_data = packet.get_raw_packet()  # 這將返回封包的原始數據
            
            # 顯示封包的原始數據（以十六進位格式呈現）
            print(f"Frame {packet_number}: Length {packet.length} | Raw Data:\n{raw_data.hex()}")

        except IndexError:
            print(f"封包編號 {packet_number} 不存在於檔案中。")




# 設定 pcap 檔案路徑
pcap_file = 'free5gc_oaiGNB_oaiUE.pcap'

# 用來儲存符合條件的封包號碼
matching_packet_numbers = []

# 開啟 pcap 檔案進行過濾，並啟用 JSON 解析與 raw 資料
cap = pyshark.FileCapture(pcap_file, use_json=True)

# 遍歷封包
for packet in cap:
    # 檢查協議層是否為 NGAP
    if packet.highest_layer == 'NGAP':
        # 將符合條件的封包號碼加入陣列
        matching_packet_numbers.append(packet.number)

        # 打印封包的基本資料
        print(f"Packet Number: {packet.number}")
        print(f"Timestamp: {packet.sniff_time}")
        print(f"Protocol: {packet.highest_layer}")  # 顯示協議層次
        print(f"Length: {packet.length} bytes")  # 顯示封包長度

# 輸出符合條件的封包號碼列表
print(f"Matching packet numbers: {matching_packet_numbers}")

# 關閉捕獲
cap.close()
if __name__ == "__main__":
    # 設定正確的 pcap 檔案路徑
    pcap_file = 'free5gc_oaiGNB_oaiUE.pcap'  # 請使用正確的檔案路徑
    
    # 提取這些封包的原始資料
    extract_raw_packets(pcap_file, matching_packet_numbers)
