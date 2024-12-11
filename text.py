import heapq
from collections import defaultdict, Counter


class HuffmanNode:
    def __init__(self, char, freq):
        self.char = char
        self.freq = freq
        self.left = None
        self.right = None

    def __lt__(self, other):
        return self.freq < other.freq


def build_huffman_tree(frequency):
    heap = [HuffmanNode(char, freq) for char, freq in frequency.items()]
    heapq.heapify(heap)

    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        merged = HuffmanNode(None, left.freq + right.freq)
        merged.left = left
        merged.right = right
        heapq.heappush(heap, merged)

    return heap[0]


def build_huffman_codes(tree, prefix="", codebook={}):
    if tree is None:
        return

    if tree.char is not None:
        codebook[tree.char] = prefix

    build_huffman_codes(tree.left, prefix + "0", codebook)
    build_huffman_codes(tree.right, prefix + "1", codebook)

    return codebook


def huffman_compress(data, codebook):
    return ''.join(codebook[byte] for byte in data)


def huffman_decompress(encoded_data, tree):
    decoded_data = []
    node = tree

    for bit in encoded_data:
        node = node.left if bit == "0" else node.right
        if node.char is not None:
            decoded_data.append(node.char)
            node = tree

    return bytes(decoded_data)


if __name__ == "__main__":
    # 原始封包的十六進位數據
    raw_hex_data = (
        "000c29195a7bac1f6b4004b608004502004c000b40004084a886c0a80835c0a80815e3d3960c248dfe63000000000003002a1bec3096000100090000003c20290016000003000a40020002005540020001003c000300000a0000"
    )
    
    # 將十六進位數據轉換為 bytes
    raw_data = bytes.fromhex(raw_hex_data)

    # 計算字節頻率
    frequency = Counter(raw_data)

    # 建立赫夫曼樹
    huffman_tree = build_huffman_tree(frequency)

    # 生成赫夫曼編碼表
    huffman_codes = build_huffman_codes(huffman_tree)

    # 壓縮數據
    compressed_data = huffman_compress(raw_data, huffman_codes)

    # 顯示壓縮結果
    print(f"原始數據長度: {len(raw_data)} bytes")
    print(f"壓縮後比特數: {len(compressed_data)} bits")
    print(f"壓縮比例: {len(compressed_data) / (len(raw_data) * 8):.2f}")

    # 解壓縮數據
    decompressed_data = huffman_decompress(compressed_data, huffman_tree)

    # 驗證解壓縮是否與原始數據一致
    assert decompressed_data == raw_data, "解壓縮數據與原始數據不一致！"

    print("壓縮與解壓縮成功！")
