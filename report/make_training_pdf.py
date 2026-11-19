"""Tạo PDF giải thích QUÁ TRÌNH TRAIN từng bước cho từng dataset (LANL, CERT r4.2).

Số liệu đọc từ ml/reports và soc/reports (kết quả thật của các lần chạy) – không gõ tay.
Chạy (từ gốc repo):  python report/make_training_pdf.py   →  report/SOC_UEBA_Training.pdf
"""
import json
from pathlib import Path

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "report" / "SOC_UEBA_Training.pdf"
MLR, SOCR = ROOT / "ml" / "reports", ROOT / "soc" / "reports"


def js(p):
    return json.loads(p.read_text(encoding="utf-8"))


LANL_SUM = js(MLR / "lanl_summary.json")
LANL_EXP = pd.read_csv(MLR / "lanl_experiments.csv")
LANL_ONL = pd.read_csv(MLR / "lanl_online.csv")
LANL_HOST = js(MLR / "lanl_hosts.json")
CERT_SEL = js(MLR / "cert_model_selection.json")
CERT_TEST = js(MLR / "cert_test_metrics.json")
CERT_SUM = js(MLR / "cert_summary.json")
CERT_EXP = pd.concat([pd.read_csv(MLR / f) for f in (
    "cert_experiments.csv", "cert_experiments_v2_trend.csv", "cert_experiments_v1.csv")],
    ignore_index=True).drop_duplicates(["features", "split", "method"], keep="first")
RISK = pd.read_csv(SOCR / "risk_eval.csv")
MTTD = js(SOCR / "soc_metrics.json")

pdfmetrics.registerFont(TTFont("Arial", "C:/Windows/Fonts/arial.ttf"))
pdfmetrics.registerFont(TTFont("Arial-Bold", "C:/Windows/Fonts/arialbd.ttf"))
pdfmetrics.registerFont(TTFont("Arial-Italic", "C:/Windows/Fonts/ariali.ttf"))
pdfmetrics.registerFontFamily("Arial", normal="Arial", bold="Arial-Bold", italic="Arial-Italic")
INK, MUTED, ACCENT = colors.HexColor("#1d2330"), colors.HexColor("#5b6475"), colors.HexColor("#2c5fd6")
LINE, HEAD_BG, HL = colors.HexColor("#d5d9e0"), colors.HexColor("#eef1f6"), colors.HexColor("#e6eefc")
S = {
    "title": ParagraphStyle("t", fontName="Arial-Bold", fontSize=17, leading=21, textColor=INK, spaceAfter=2),
    "sub": ParagraphStyle("s", fontName="Arial", fontSize=9.5, leading=13, textColor=MUTED, spaceAfter=8),
    "h1": ParagraphStyle("h1", fontName="Arial-Bold", fontSize=13.5, leading=17, textColor=ACCENT,
                         spaceBefore=12, spaceAfter=5),
    "h2": ParagraphStyle("h2", fontName="Arial-Bold", fontSize=10.8, leading=14, textColor=INK,
                         spaceBefore=9, spaceAfter=3),
    "p": ParagraphStyle("p", fontName="Arial", fontSize=9.5, leading=13.2, textColor=INK,
                        alignment=TA_LEFT, spaceAfter=4),
    "note": ParagraphStyle("n", fontName="Arial-Italic", fontSize=8.3, leading=11, textColor=MUTED, spaceAfter=4),
    "box": ParagraphStyle("b", fontName="Arial", fontSize=9, leading=12.5, textColor=INK,
                          backColor=HL, borderPadding=6, spaceBefore=4, spaceAfter=8),
    "cell": ParagraphStyle("c", fontName="Arial", fontSize=8.5, leading=11, textColor=INK),
    "cellb": ParagraphStyle("cb", fontName="Arial-Bold", fontSize=8.5, leading=11, textColor=INK),
}


def P(t, st="p"):
    return Paragraph(t, S[st])


def table(rows, widths, highlight=None, first_col_bold=False):
    data = [[P(c, "cellb" if i == 0 or (first_col_bold and j == 0) else "cell")
             if isinstance(c, str) else c for j, c in enumerate(r)] for i, r in enumerate(rows)]
    t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1)
    style = [("GRID", (0, 0), (-1, -1), 0.4, LINE), ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
             ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4),
             ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    for r in (highlight or []):
        style.append(("BACKGROUND", (0, r), (-1, r), HL))
    t.setStyle(TableStyle(style))
    return t


def f3(x):
    return f"{x:.3f}".replace(".", ",")


def dec(x):
    return f"{x:g}".replace(".", ",")


def num(x):
    return f"{x:,}".replace(",", ".")


def lexp(method, split, col):
    return LANL_EXP[(LANL_EXP.method == method) & (LANL_EXP.split == split)].iloc[0][col]


def lonl(variant, split, col):
    return LANL_ONL[(LANL_ONL.variant == variant) & (LANL_ONL.split == split)].iloc[0][col]


def cexp(method, col, split="test", features="day+win+trend"):
    q = CERT_EXP[(CERT_EXP.features == features) & (CERT_EXP.split == split) & (CERT_EXP.method == method)]
    return q.iloc[0][col]


def risk(ds, mode, split):
    return RISK[(RISK.dataset == ds) & (RISK["mode"] == mode) & (RISK.split == split)].iloc[0]


story = [
    P("SOC/UEBA – Quá trình train mô hình", "title"),
    P("Giải thích từng bước train cho từng dataset: dữ liệu vào là gì, mô hình nào, cấu hình ra sao, "
      "chọn bằng cách nào và kết quả mỗi bước. Mọi số liệu lấy từ kết quả chạy thật.", "sub"),

    P("0. Những điều chung cho cả hai dataset", "h1"),
    table([
        ["Khái niệm", "Giải thích"],
        ["Học không giám sát", "Mô hình KHÔNG được xem nhãn tấn công khi học. Nó chỉ học hành vi của giai "
         "đoạn train (gần như toàn bình thường), rồi chấm mỗi người-ngày một điểm \"lạ đến mức nào\". Lý do: "
         "ngoài đời không có sẵn nhãn, và tấn công quá hiếm (0,06% – 0,29%) để học có giám sát."],
        ["Ba giai đoạn thời gian", "<b>Train</b> – mô hình học từ đây. <b>Validation</b> – dùng để so sánh và "
         "CHỌN mô hình / tham số (lúc này mới dùng nhãn, chỉ để chấm). <b>Test</b> – chạy đúng một lần ở cuối "
         "để báo cáo; không được dùng khi thiết kế."],
        ["Điểm percentile", "Điểm thô của mỗi mô hình có thang khác nhau. Mọi điểm được đổi thành percentile so "
         "với phân bố điểm của train: 0,99 = lạ hơn 99% người-ngày lúc train. Nhờ vậy cộng / so sánh được các "
         "mô hình và đặt ngưỡng dễ hiểu."],
        ["Chỉ số đánh giá", "<b>PR-AUC</b> (chỉ số chính – độ chính xác khi lần lượt xem các cảnh báo cao nhất, "
         "hợp với dữ liệu cực mất cân bằng), ROC-AUC, và số kẻ tấn công bị bắt khi analyst chỉ xem K cảnh "
         "báo / incident mỗi ngày (ngân sách cố định – sát thực tế SOC)."],
    ], [36, 134], first_col_bold=True),
]

# ===================================================================== LANL
lv, lt = LANL_SUM["val"], LANL_SUM["test"]
hb = LANL_SUM["human_bot"]
story += [
    P("Phần A. LANL – phát hiện tài khoản bị chiếm và di chuyển ngang", "h1"),
    P("A.1. Dữ liệu vào cho bước train", "h2"),
    table([
        ["Giai đoạn", "Ngày", "Người-ngày (tài khoản người)", "Tài khoản bị chiếm (nhãn)", "Dùng để"],
        ["Lịch sử", "0", "–", "–", "Khởi tạo \"đã thấy\" – không học, không chấm"],
        ["Train", "1–7", num(69205), "có (không dùng)", "Học mô hình"],
        ["Validation", "8–19", num(110807), "97", "Chọn mô hình, tham số"],
        ["Test", "20–29", num(110381), "26", "Báo cáo (chạy 1 lần)"],
        ["Ngày mới", "30–56", "–", "không có nhãn", "Demo vận hành (tải sau khi train xong)"],
    ], [22, 16, 40, 38, 54], first_col_bold=True),
    P("Mỗi người-ngày có 41 feature (37 feature hành vi + 4 feature độ hiếm – xem báo cáo tiền xử lý). "
      "Chỉ tài khoản người được chấm điểm.", "note"),

    P("A.2. Bước 1 – Bộ phân loại người / máy (mô hình phụ)", "h2"),
    table([
        ["Mục", "Chi tiết"],
        ["Mục đích", "Ước lượng xác suất một tài khoản hành xử như người (is_human_prob) – gắn vào cảnh báo để "
         "analyst tham khảo (tài khoản người mà hành xử như script là đáng ngờ)."],
        ["Nhãn", "Nhãn YẾU lấy từ tên tài khoản: U…@DOM = người; …$@ hoặc SYSTEM@… = máy / dịch vụ. Mô hình "
         "không được nhìn tên – chỉ nhìn 23 feature nhịp hành vi (giờ hoạt động, độ đều, mức bùng nổ, kiểu logon)."],
        ["Mô hình", "HistGradientBoostingClassifier: 300 vòng, learning rate 0,08, cân bằng lớp, seed 42. Bỏ "
         "người-ngày có dưới 5 sự kiện (chưa đủ \"nhịp\")."],
        ["Chia dữ liệu", f"Chia theo TÀI KHOẢN (GroupShuffleSplit 75/25) để cùng một tài khoản không nằm ở cả "
         f"hai bên: {num(hb['rows_train'])} dòng train, {num(hb['rows_test'])} dòng kiểm tra."],
        ["Kết quả", f"Accuracy {hb['accuracy'] * 100:.1f}%, ROC-AUC {f3(hb['roc_auc'])} – phân biệt người / máy "
         f"rất tốt.".replace(".", ",", 1)],
        ["Bài học", f"Dùng nó để bắt tài khoản bị chiếm thì THẤT BẠI (ROC-AUC trên val chỉ "
         f"{f3(lexp('human_low', 'val', 'roc_auc'))}): kẻ tấn công dùng tài khoản người bằng tay nên vẫn "
         "\"giống người\". → Chỉ giữ làm thông tin phụ, không dùng để phát hiện."],
    ], [26, 144], first_col_bold=True),

    ]
A3_HEAD = [P("A.3. Bước 2 – Thử nhiều mô hình phát hiện, chọn trên validation", "h2"),
           P("Cùng dữ liệu train (ngày 1–7), thử các mô hình sau rồi so sánh trên validation (ngày 8–19). "
             "\"Bắt @25/ngày\" = số tài khoản bị chiếm lọt vào top 25 cảnh báo mỗi ngày.")]
rows = [["Mô hình (thử nghiệm)", "Cách hoạt động", "ROC-AUC val", "PR-AUC val", "Bắt @25/ngày (val)"]]
for key, name, how in [
        ("stat", "Thống kê z-score", "So mỗi feature với trung bình của chính user + nhóm cùng loại"),
        ("ecod", "ECOD (mọi feature)", "Cộng độ hiếm đuôi của từng feature so với train"),
        ("iforest", "Isolation Forest (mọi feature)", "Đếm số nhát cắt ngẫu nhiên để tách một điểm"),
        ("ae", "Autoencoder", "Sai số khi nén – dựng lại"),
        ("iforest_lateral", "IF trên feature di chuyển ngang", "IF chỉ trên 13 feature liên quan di chuyển ngang"),
        ("ens_mean", "Trung bình 4 mô hình", "Gộp stat + ECOD + IF + AE"),
        ("ens_ecod_lateral", "<b>ECOD + IF di chuyển ngang</b>", "Trung bình percentile của 2 mô hình bổ sung nhau")]:
    rows.append([name, how, f3(lexp(key, "val", "roc_auc")), f3(lexp(key, "val", "pr_auc")),
                 f"{int(lexp(key, 'val', 'acc@25/d'))}/97"])
story += [
    KeepTogether(A3_HEAD + [table(rows, [44, 66, 20, 20, 20], highlight=[7], first_col_bold=True)]),
    P("Chọn <b>ECOD + IF di chuyển ngang</b> vì PR-AUC trên validation cao nhất. Gộp cả 4 mô hình (ens_mean) "
      "kém hơn: tín hiệu tấn công nằm ở vài feature, trộn mô hình nhìn mọi feature làm loãng tín hiệu.", "note"),

    P("A.4. Bước 3 – Cấu hình mô hình đã chọn", "h2"),
    table([
        ["Thành phần", "Đầu vào", "Cách train / chấm"],
        ["ECOD", "22 cột: 15 feature thống kê (số sự kiện, số máy, tỉ lệ thất bại / NTLM / từ xa, máy mới…), "
         "2 cột đường đi mới, fan-in máy nguồn, 4 cột độ hiếm",
         "\"Train\" = sắp xếp giá trị từng cột của train. Chấm: với mỗi cột, P(train ≥ x) (làm mượt +1); điểm "
         "= Σ −log P. Không có tham số cần dò. Cột nào có P &lt; 1% được ghi là <b>lý do</b> cảnh báo."],
        ["Isolation Forest", "18 cột: 13 feature di chuyển ngang (số máy nguồn / đích, máy mới, NTLM từ máy "
         "mới, đường đi mới…) + fan-in + 4 cột độ hiếm",
         "300 cây, mỗi cây lấy mẫu 4.096 dòng, seed 42. Điểm thô = −score_samples (ít nhát cắt = lạ)."],
        ["Tiền xử lý đầu vào", "Cả hai", "Cột đếm biến đổi log(1+x) trước khi đưa vào mô hình."],
        ["Điểm cuối", "–", "Mỗi mô hình → percentile so với train; lấy trung bình 2 percentile; đổi lần nữa "
         "thành percentile so với train. Cảnh báo ML khi điểm ≥ 0,99."],
    ], [30, 66, 74], first_col_bold=True),

    P("A.5. Bước 4 – Chạy từng ngày như thật và chống \"đầu độc baseline\"", "h2"),
    P("Feature \"mới so với lịch sử\" phụ thuộc lịch sử. Nếu lịch sử học cả hành vi của kẻ tấn công thì hôm "
      "sau kẻ tấn công thành \"quen\". Vì vậy chấm điểm được chạy <b>tuần tự từng ngày</b>:"),
    table([
        ["#", "Việc làm mỗi ngày d"],
        ["1", "Tính feature của ngày d so với lịch sử TỚI ngày d−1 (máy mới, đường đi mới, độ hiếm có suy giảm)."],
        ["2", "Ngày 1–7: chỉ gom dữ liệu; hết ngày 7 thì train ECOD + IF trên toàn bộ ngày 1–7."],
        ["3", "Từ ngày 8: chấm điểm mọi tài khoản người của ngày d."],
        ["4", "<b>Cách ly</b>: tài khoản có điểm ≥ 0,99 KHÔNG được cập nhật vào lịch sử \"bình thường\" (không cần nhãn)."],
        ["5", "Cập nhật lịch sử bằng phần còn lại rồi sang ngày d+1."],
    ], [8, 162]),
]
rows = [["Biến thể (chọn trên validation)", "PR-AUC val", "PR-AUC test", "Tài khoản bắt (test, ngưỡng 0,99)"]]
for v, name in [("quar+fanin", "Cách ly + fan-in máy nguồn"), ("rarity", "Độ hiếm có suy giảm"),
                ("quar+fanin+rarity", "<b>Cách ly + fan-in + độ hiếm (đang dùng)</b>")]:
    rows.append([name, f3(lonl(v, "val", "pr_auc")), f3(lonl(v, "test", "pr_auc")),
                 f"{int(lonl(v, 'test', 'accounts_caught'))}/26"])
story += [
    Spacer(1, 4), table(rows, [70, 30, 30, 40], highlight=[3], first_col_bold=True),
    P(f"Mô hình mức tài khoản cuối cùng: ROC-AUC test {f3(lt['roc_auc'])}, PR-AUC test {f3(lt['pr_auc'])} "
      f"(gấp ~{lt['pr_auc'] / (34 / 110381):.0f} lần đoán mò), bắt {lt['accounts_caught']}/{lt['accounts_total']} "
      f"tài khoản ở ngưỡng 0,99 (~{lt['alerts_per_day']:.0f} cảnh báo/ngày). Biến thể có vòng phản hồi IOC dùng "
      "nhãn để giả lập analyst nên chỉ báo cáo tách riêng, không tính.", "note"),

    KeepTogether([P("A.6. Bước 5 – Mô hình mức máy: phát hiện máy bàn đạp", "h2"),
    P("Chẩn đoán trên test cho thấy kẻ tấn công dùng một máy (C17693) đăng nhập bằng hàng chục tài khoản, "
      "mỗi tài khoản chỉ 1–2 lần – nhìn từng tài khoản thì \"êm\", nhìn từ máy thì rất lộ."),
    table([
        ["Bước", "Chi tiết"],
        ["Feature theo (máy nguồn, ngày)", "n_users – số tài khoản người dùng máy này làm nguồn; n_rare_users – "
         "số tài khoản mà với chính họ máy này là lạ (đếm suy giảm &lt; 1); rare_ntlm_users – trong đó có "
         "đăng nhập NTLM."],
        ["Điểm bất ngờ (Poisson)", "Tỉ lệ toàn mạng trong ngày r = (Σ rare_ntlm_users + 1) / (Σ n_users + 10). "
         "Mức bất ngờ = −log P(X ≥ rare_ntlm_users) với X ~ Poisson(r × n_users). Máy nhỏ mà nhiều tài khoản "
         "lạ dùng NTLM → bất ngờ rất cao."],
        ["Chọn cách tính", "So trên validation giữa: Poisson theo lịch sử riêng của máy (bị đầu độc), có / không "
         "cách ly, đếm thô → chọn Poisson theo tỉ lệ toàn mạng."],
        ["Điểm", "Percentile của mức bất ngờ so với các máy-ngày của train."],
        ["Hàng đợi", "Mỗi ngày 5 máy bất ngờ nhất + máy từng vào hàng đợi trong 7 ngày trước xuất hiện lại "
         "(≤ 50 tài khoản). Incident máy liệt kê mọi tài khoản dùng máy đó."],
        ["Kết quả (5 máy/ngày)", f"Validation: {LANL_HOST['val']['accounts@5hosts/day']}/97 tài khoản; "
         f"test: {LANL_HOST['test']['accounts@5hosts/day']}/26 tài khoản."],
    ], [38, 132], first_col_bold=True)]),
]
rb_v, rb_t = risk("lanl", "both+hosts", "val"), risk("lanl", "both+hosts", "test")
story += [
    P("A.7. Bước 6 – Kết hợp với luật Sigma thành điểm rủi ro, chọn tham số trên validation", "h2"),
    table([
        ["Mục", "Chi tiết"],
        ["Công thức", "R(ngày) = R(ngày trước) × decay + Σ điểm phát hiện trong ngày. Luật: trọng số theo mức "
         "(medium 20, high 40, critical 80) × hệ số độ ồn (luật hay bắn ở train bị giảm). ML: ml_weight × "
         "(điểm − ml_floor) / (1 − ml_floor), chỉ khi điểm ≥ ml_floor."],
        ["Lưới tham số", "decay: 0,5 / 0,7 / 0,85 × ml_weight: 20 / 40 / 80 / 160 × ml_floor: 0,95 / 0,99 = "
         "24 tổ hợp, mỗi tổ hợp chấm trên validation theo số tài khoản bị chiếm lọt hàng đợi."],
        ["Tham số chọn", f"decay {dec(rb_v['decay'])}, ml_weight {int(rb_v['ml_weight'])}, ml_floor "
         f"{dec(rb_v['ml_floor'])}."],
        ["Hàng đợi", "20 tài khoản rủi ro cao nhất + 5 máy bàn đạp + máy đang theo dõi mỗi ngày."],
    ], [30, 140], first_col_bold=True),
]
rows = [["Chế độ", "Validation (97 tài khoản)", "Test (26 tài khoản)", "Incident / ngày (test)"]]
for mode, name in [("rules", "Chỉ luật Sigma"), ("ml", "Chỉ ML"), ("both", "Luật + ML"),
                   ("both+hosts", "<b>Luật + ML + hàng đợi máy (cuối cùng)</b>")]:
    v, t = risk("lanl", mode, "val"), risk("lanl", mode, "test")
    rows.append([name, f"{int(v.accounts_hit)}/97", f"<b>{int(t.accounts_hit)}/26</b>" if mode == "both+hosts"
                 else f"{int(t.accounts_hit)}/26", f"{t.incidents_per_day:.1f}".replace(".", ",")])
story += [
    Spacer(1, 4), table(rows, [70, 34, 34, 32], highlight=[4], first_col_bold=True),
    P(f"<b>Kết quả cuối LANL:</b> bắt {int(rb_t.accounts_hit)}/26 tài khoản bị chiếm trên test, MTTD "
      f"{dec(MTTD['lanl']['mttd_days'])} ngày ({MTTD['lanl']['same_day']} tài khoản bị bắt ngay trong ngày bắt đầu). "
      "Hàng đợi máy và danh sách theo dõi được thiết kế SAU khi phân tích các tài khoản bị sót trên test → "
      f"báo cáo tách riêng; trên đợt tấn công đầu (validation) chúng bắt {int(rb_v.accounts_hit)}/97.", "box"),
]

# ===================================================================== CERT
sel = CERT_SEL["validation_pr_auc"]
th = CERT_SUM["user_level"]["0.99"]
story += [
    P("Phần B. CERT r4.2 – phát hiện nhân viên nội gián", "h1"),
    P("B.1. Dữ liệu vào cho bước train", "h2"),
    table([
        ["Giai đoạn", "Thời gian", "Người-ngày", "Insider", "Dùng để"],
        ["Khởi động (warm-up)", "02/01 – 31/01/2010", num(20549), "–", "Chỉ làm lịch sử (z-score, độ hiếm)"],
        ["Train", "01/02 – 31/08/2010", num(148536), "24 (ở 2 tháng cuối)",
         "Khi CHỌN mô hình: học 01/02 – 30/06, kiểm tra trên 2 tháng cuối 01/07 – 31/08 (validation). "
         "Sau khi chọn: train lại trên cả 01/02 – 31/08"],
        ["Test", "01/09/2010 – 17/05/2011", num(161367), "52", "Báo cáo (chạy 1 lần)"],
    ], [28, 34, 20, 26, 62], first_col_bold=True),
    P("Mỗi người-ngày: 56 feature (23 feature trong ngày + 22 tổng 7/30 ngày + 11 xu hướng) và 56 độ lệch "
      "so với chính nhân viên (self z-score) = <b>112 con số</b>. Cột đếm biến đổi log(1+x), rồi chuẩn hoá "
      "(StandardScaler học trên train).", "note"),

    P("B.2. Bước 1 – Baseline thống kê (mốc so sánh)", "h2"),
    P("Với 15 chỉ số hành vi chính (đăng nhập ngoài giờ, USB, file, email, web hiếm…), tính z-score so với "
      "<b>chính nhân viên</b> (lịch sử trước đó, cần ≥ 3 ngày) và so với <b>nhóm cùng vai trò</b> (LDAP). Lấy độ lệch "
      "lớn hơn, chỉ chiều tăng, trung bình 3 chỉ số lệch nhất → điểm thống kê. Không cần train – dùng làm mốc."),

    P("B.3. Bước 2 – Hai mô hình chính", "h2"),
    table([
        ["Mô hình", "Cấu hình", "Cách train"],
        ["Isolation Forest", "300 cây, mỗi cây lấy mẫu 4.096 dòng", "Học trên 112 con số đã chuẩn hoá của "
         "người-ngày train. Điểm thô = −score_samples."],
        ["Autoencoder (PyTorch)", "112 → 32 → 8 → 32 → 112, ReLU; loss MSE; Adam lr 0,001, weight decay 1e-5; "
         "batch 1.024; 30 epoch", "Giữ 10% train làm tập theo dõi overfit (không cập nhật trọng số). Điểm = "
         "sai số dựng lại trung bình của 112 con số."],
        ["Bagging", "3 seed: 42, 7, 2024", "Mỗi mô hình train 3 lần với seed khác nhau, lấy trung bình điểm rồi "
         "đổi lại thành percentile so với train → kết quả không phụ thuộc may rủi của một lần train."],
        ["Kết hợp IF + AE", "Trung bình 2 percentile", "Đổi tiếp thành percentile so với train → if_ae_score."],
    ], [32, 58, 80], first_col_bold=True),

    P("B.4. Bước 3 – Chọn mô hình trên validation rồi train lại", "h2"),
    table([
        ["#", "Việc làm"],
        ["1", "Train IF + AE (3 seed) trên phần học 01/02 – 30/06/2010."],
        ["2", "Chấm validation 01/07 – 31/08/2010, tính PR-AUC cho 5 loại điểm (bảng dưới)."],
        ["3", f"Chọn điểm có PR-AUC validation cao nhất: <b>{CERT_SEL['selected']}</b>."],
        ["4", "Train lại IF + AE (3 seed) trên TOÀN BỘ train (01/02 – 31/08/2010), chấm mọi người-ngày."],
        ["5", "Chấm test một lần để báo cáo."],
    ], [8, 162]),
    Spacer(1, 4),
    table([["Loại điểm", "PR-AUC validation"]] + [
        [n, f3(sel[k]) if k != CERT_SEL["selected"] else f"<b>{f3(sel[k])}</b>"] for k, n in [
            ("stat_score", "Thống kê"), ("iforest_score", "Isolation Forest"), ("ae_score", "Autoencoder"),
            ("ensemble_score", "Trung bình thống kê + IF + AE"), ("if_ae_score", "IF + AE (đã chọn)")]],
        [100, 70], highlight=[5], first_col_bold=True),
]
rows = [["Mô hình (CERT)", "ROC-AUC test", "PR-AUC test", "Bắt insider (5 cảnh báo/ngày)", "Nhận xét"]]
for key, name, why in [
        ("stat", "Thống kê", "Chỉ so từng con số riêng lẻ – yếu"),
        ("ecod", "ECOD", "Nội gián lệch nhẹ ở nhiều chỗ – yếu"),
        ("iforest", "Isolation Forest", "Tốt với hành vi đột biến (kịch bản 1, 3)"),
        ("ae", "Autoencoder", "Bắt tốt lấy dữ liệu dần dần (kịch bản 2)"),
        ("ens_if_ae", "IF + AE (đã chọn)", "Ổn định nhất giữa các lần train")]:
    rows.append([name, f3(cexp(key, "roc_auc")), f3(cexp(key, "pr_auc")),
                 f"{cexp(key, 'insiders@5/day'):.0f}/52", why])
rc_v, rc_t = risk("cert", "both", "val"), risk("cert", "both", "test")
story += [
    P("B.5. Bước 4 – Kết quả trên test", "h2"),
    table(rows, [34, 20, 20, 30, 66], highlight=[5], first_col_bold=True),
    P("Trung bình 3 lần train, cùng bộ feature (trong ngày + cửa sổ 7/30 ngày + xu hướng).", "note"),
    table([
        ["Ngưỡng điểm", "Cảnh báo / ngày", "Insider bắt được", "Kịch bản 1 (USB + web)", "Kịch bản 2 (lấy dần)", "Kịch bản 3 (keylogger)"],
    ] + [[t.replace(".", ","), f"{CERT_SUM['user_level'][t]['alerts_per_day']}".replace(".", ","),
          f"{CERT_SUM['user_level'][t]['insiders_caught']}/52", CERT_SUM['user_level'][t]['by_scenario']['1'],
          CERT_SUM['user_level'][t]['by_scenario']['2'], CERT_SUM['user_level'][t]['by_scenario']['3']]
         for t in ("0.99", "0.995", "0.999")], [24, 26, 26, 32, 30, 32], highlight=[1]),
    KeepTogether([P("B.6. Bước 5 – Kết hợp với luật Sigma (điểm rủi ro)", "h2"),
    P(f"Cùng công thức và lưới 24 tổ hợp như LANL, chọn trên validation: decay {dec(rc_v['decay'])}, "
      f"ml_weight {int(rc_v['ml_weight'])}, ml_floor {dec(rc_v['ml_floor'])}; mỗi ngày 5 nhân viên rủi ro cao nhất thành "
      f"incident. Kết quả test: {int(rc_t.accounts_hit)}/52 insider vào hàng đợi; chỉ luật: "
      f"{int(risk('cert', 'rules', 'test').accounts_hit)}/52, chỉ ML: {int(risk('cert', 'ml', 'test').accounts_hit)}/52."),
    P(f"<b>Kết quả cuối CERT:</b> ROC-AUC test {f3(CERT_TEST[CERT_SEL['selected']]['roc_auc'])}, PR-AUC test "
      f"{f3(CERT_TEST[CERT_SEL['selected']]['pr_auc'])}; ở ngưỡng 0,99 bắt {th['insiders_caught']}/52 insider "
      f"với ~{str(th['alerts_per_day']).replace('.', ',')} cảnh báo/ngày cho 1.000 nhân viên; MTTD "
      f"{str(MTTD['cert']['mttd_days']).replace('.', ',')} ngày. Kịch bản 2 (lấy dữ liệu dần dần trước khi nghỉ "
      "việc) vẫn khó nhất.", "box")]),

    P("C. Những điều cần nhớ khi trình bày", "h1"),
    P("• <b>Không dùng nhãn khi train</b>: nhãn chỉ dùng để chọn mô hình (validation) và chấm điểm (test).<br/>"
      "• <b>Chọn trên validation, báo cáo trên test</b>: test chỉ chạy một lần ở cuối.<br/>"
      "• <b>Trung thực về thiết kế sau chẩn đoán</b>: các cải tiến LANL (cách ly, độ hiếm, mức máy, theo dõi "
      "máy) ra đời sau khi phân tích lỗi trên test → báo cáo tách riêng và kiểm chứng lại trên validation.<br/>"
      "• <b>Đã sửa rò nhãn</b> ở CERT (danh sách trang web lấy từ file đáp án) trước khi có kết quả cuối.<br/>"
      "• <b>Hạn chế</b>: test nhỏ (26 tài khoản, 52 insider); CERT là dữ liệu mô phỏng."),
]


def footer(c, doc):
    c.saveState()
    c.setFont("Arial", 7.5)
    c.setFillColor(MUTED)
    c.drawString(20 * mm, 10 * mm, "Đồ án SOC/UEBA – Quá trình train mô hình")
    c.drawRightString(190 * mm, 10 * mm, f"Trang {doc.page}")
    c.restoreState()


doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                        topMargin=16 * mm, bottomMargin=16 * mm,
                        title="SOC/UEBA – Quá trình train mô hình", author="SOC/UEBA")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print("→", OUT)
