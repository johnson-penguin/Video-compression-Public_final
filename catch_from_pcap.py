import pyshark

def extract_raw_packets(pcap_file, packet_numbers):
    # 使用 pyshark 讀取 pcap 檔案，設定 use_json=True 和 include_raw=True
    cap = pyshark.FileCapture(pcap_file, keep_packets=True, use_json=True, include_raw=True)

    # 迭代並提取指定的封包編號
    for packet_number in packet_numbers:
        try:
            # 根據封包編號取得封包 (注意 packet_number 是 1-based)
            packet = cap[int(packet_number) - 1]  
            
            # 獲取封包的原始二進制數據
            raw_data = packet.get_raw_packet()  
            
            # 計算封包的原始數據長度
            raw_data_length = len(raw_data)
            
            # 顯示封包的原始數據與長度比較
            print(f"Frame {packet_number}:")
            print(f"  Packet Length (Header Info): {packet.length} bytes")
            print(f"  Raw Data Length (Calculated): {raw_data_length} bytes")
            print(f"  Raw Data (Hex):\n{raw_data.hex()}")

            # 驗證長度一致性
            if raw_data_length != int(packet.length):
                print(f"  警告: 封包長度 ({packet.length} bytes) 與原始數據長度 ({raw_data_length} bytes) 不一致！")
            print("-" * 80)

        except IndexError:
            print(f"封包編號 {packet_number} 不存在於檔案中。")
        except Exception as e:
            print(f"處理封包編號 {packet_number} 時出現錯誤: {e}")
    cap.close()

# 主程式入口
if __name__ == "__main__":
    # 設定正確的 pcap 檔案路徑
    pcap_file = 'free5gc_oaiGNB_oaiUE.pcap'  # 請使用正確的檔案路徑
    
    # 初始化用來儲存符合條件的封包號碼
    matching_packet_numbers = []
    
    # 開啟 pcap 檔案進行過濾，並啟用 JSON 解析
    cap = pyshark.FileCapture(pcap_file, use_json=True)
    
    # 遍歷封包並檢查協議層是否為 NGAP
    for packet in cap:
        if packet.highest_layer == 'NGAP':
            matching_packet_numbers.append(packet.number)
            print(f"Packet Number: {packet.number}")
            print(f"  Timestamp: {packet.sniff_time}")
            print(f"  Protocol: {packet.highest_layer}")
            print(f"  Length: {packet.length} bytes")
            print("-" * 80)

    # 輸出符合條件的封包號碼
    print(f"Matching packet numbers: {matching_packet_numbers}")
    cap.close()

    # 提取這些封包的原始資料
    extract_raw_packets(pcap_file, matching_packet_numbers)
