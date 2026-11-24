"""Bộ chuyển định dạng CERT r5.x → nghĩa của r4.2 (dùng cho kiểm chứng ngoài)."""
import pyarrow as pa

from cert_features import R5_FILTER, attachment_count


def test_attachment_count_r42_numeric_and_r5_list():
    col = pa.array(["2", "0", None, r"C:\a\doc1.doc(1234);C:\b\x.pdf(99)", ""])
    assert attachment_count(col).tolist() == [2, 0, 0, 2, 0]


def test_r5_filters_keep_only_r42_semantics():
    assert R5_FILTER["file"] == ("to_removable_media", "True")     # chỉ thao tác chép ra USB
    assert R5_FILTER["email"] == ("activity", "Send")             # chỉ email gửi đi
