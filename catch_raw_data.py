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
            print(f"Frame {packet_number}: Length {packet.length} | Raw Data: {raw_data.hex()}")

        except IndexError:
            print(f"封包編號 {packet_number} 不存在於檔案中。")

if __name__ == "__main__":
    # 設定正確的 pcap 檔案路徑
    pcap_file = 'free5gc_oaiGNB_oaiUE.pcap'  # 請使用正確的檔案路徑
    
    # 假設你有一個封包編號的矩陣
    # packet_numbers = [103, 107, 344, 349, 357, 359, 368, 372, 392, 409, 413, 439, 1015, 1017, 1025, 1037]  # 封包編號矩陣
    packet_numbers1 = [103, 107, 344, 349, 357]
    packet_numbers2 = [359, 368, 372, 392, 409]
    packet_numbers3 = [413, 439, 1015, 1017, 1025, 1037]  # 封包編號矩陣

    # 提取這些封包的原始資料
    extract_raw_packets(pcap_file, packet_numbers1)
