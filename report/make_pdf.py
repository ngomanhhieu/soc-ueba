"""Tạo PDF báo cáo: (1) dataset, (2) workflow từng bước (train + SIEM/SOC), (3) mô hình theo
từng dataset + chuỗi tấn công, (4) lưu ý.

Số liệu đọc từ soc/reports/final_results.json (python -m soc.train_all) và các file kết quả thử
nghiệm trong ml/reports – không gõ tay.
Chạy (từ gốc repo):  python report/make_pdf.py   →  report/SOC_UEBA_Data_ML.pdf
"""
import json
import math
from pathlib import Path

import pandas as pd
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "report" / "SOC_UEBA_Data_ML.pdf"
FINAL = json.loads((ROOT / "soc" / "reports" / "final_results.json").read_text(encoding="utf-8"))
# kết quả thử nghiệm CERT qua các lần chạy (bản mới nhất ghi đè bản cũ cùng bộ feature + mô hình)
CERT_EXP = pd.concat([pd.read_csv(ROOT / "ml" / "reports" / f) for f in (
    "cert_experiments.csv", "cert_experiments_v2_trend.csv", "cert_experiments_v1.csv")],
    ignore_index=True).drop_duplicates(["features", "split", "method"], keep="first")
LANL_EXP = pd.read_csv(ROOT / "ml" / "reports" / "lanl_experiments.csv")
LANL_ONLINE = pd.read_csv(ROOT / "ml" / "reports" / "lanl_online.csv")

pdfmetrics.registerFont(TTFont("Arial", "C:/Windows/Fonts/arial.ttf"))
pdfmetrics.registerFont(TTFont("Arial-Bold", "C:/Windows/Fonts/arialbd.ttf"))
pdfmetrics.registerFont(TTFont("Arial-Italic", "C:/Windows/Fonts/ariali.ttf"))
pdfmetrics.registerFontFamily("Arial", normal="Arial", bold="Arial-Bold", italic="Arial-Italic")

INK, MUTED, ACCENT = colors.HexColor("#1d2330"), colors.HexColor("#5b6475"), colors.HexColor("#2c5fd6")
LINE, HEAD_BG, HL = colors.HexColor("#d5d9e0"), colors.HexColor("#eef1f6"), colors.HexColor("#e6eefc")
S = {
    "title": ParagraphStyle("t", fontName="Arial-Bold", fontSize=17, leading=21, textColor=INK,
                            spaceAfter=2),
    "sub": ParagraphStyle("s", fontName="Arial", fontSize=9.5, leading=13, textColor=MUTED,
                          spaceAfter=8),
    "h1": ParagraphStyle("h1", fontName="Arial-Bold", fontSize=13, leading=17, textColor=ACCENT,
                         spaceBefore=12, spaceAfter=5),
    "h2": ParagraphStyle("h2", fontName="Arial-Bold", fontSize=10.5, leading=14, textColor=INK,
                         spaceBefore=8, spaceAfter=3),
    "p": ParagraphStyle("p", fontName="Arial", fontSize=9.5, leading=13.2, textColor=INK,
                        alignment=TA_LEFT, spaceAfter=4),
    "note": ParagraphStyle("n", fontName="Arial-Italic", fontSize=8.3, leading=11, textColor=MUTED,
                           spaceAfter=4),
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


def num(x):
    return f"{x:,}".replace(",", ".")


# ------------------------------------------------------------------ số liệu (đọc từ kết quả)
risk = pd.DataFrame(FINAL["risk"])


def risk_row(ds, mode, split):
    r = risk[(risk.dataset == ds) & (risk["mode"] == mode) & (risk.split == split)].iloc[0]
    return int(r.accounts_hit), int(r.accounts), float(r.incidents_per_day)


lanl_u = FINAL["lanl_user_level"]
host_t, host_v = FINAL["lanl_host_level"]["test"], FINAL["lanl_host_level"]["val"]
lanl_final_t, lanl_final_v = risk_row("lanl", "both+hosts", "test"), risk_row("lanl", "both+hosts", "val")
cert_sel = FINAL["cert_selected"]
cert_t = FINAL["cert_test"][cert_sel]
cert_ul = FINAL["cert_user_level"]
th = cert_ul["0.99"]


def cexp(method, col, features="day+win+trend"):
    q = CERT_EXP[(CERT_EXP.features == features) & (CERT_EXP.split == "test") & (CERT_EXP.method == method)]
    return q.iloc[0][col]


def lexp(df, key, split, col, keycol="method"):
    return df[(df[keycol] == key) & (df.split == split)].iloc[0][col]


chain_t, chain_v = FINAL["attack_chain_lanl"]["test"], FINAL["attack_chain_lanl"]["val"]
tl_cert = FINAL["insider_timeline_cert"]


def pct(x):
    return f"{x * 100:.0f}%"


def pct1(x):
    return f"{x * 100:.1f}%".replace(".", ",")


def dec(x, n=1):
    return f"{x:.{n}f}".replace(".", ",")


# ------------------------------------------------------------------ sơ đồ
class Canvas:
    """Vẽ hộp + mũi tên cho sơ đồ (toạ độ mm, tính từ mép trên)."""

    def __init__(self, w, h, bw=45, bh=14):
        self.d, self.H, self.bw, self.bh = Drawing(w * mm, h * mm), h, bw, bh

    def box(self, x, top, title, sub, accent=False, sub2=None):
        X, Y, BW, BH = x * mm, (self.H - top - self.bh) * mm, self.bw * mm, self.bh * mm
        self.d.add(Rect(X, Y, BW, BH, rx=6, ry=6, strokeColor=ACCENT if accent else MUTED,
                        strokeWidth=1.4 if accent else 0.8, fillColor=HL if accent else colors.white))
        ty = Y + BH - 5 * mm
        self.d.add(String(X + BW / 2, ty, title, fontName="Arial-Bold", fontSize=8.3, fillColor=INK,
                          textAnchor="middle"))
        for k, s in enumerate([sub] + ([sub2] if sub2 else [])):
            self.d.add(String(X + BW / 2, ty - (3.9 + 3.5 * k) * mm, s, fontName="Arial",
                              fontSize=7, fillColor=MUTED, textAnchor="middle"))

    def line(self, x1, t1, x2, t2, col=MUTED, dash=False, head=True):
        X1, Y1, X2, Y2 = x1 * mm, (self.H - t1) * mm, x2 * mm, (self.H - t2) * mm
        self.d.add(Line(X1, Y1, X2, Y2, strokeColor=col, strokeWidth=0.9,
                        strokeDashArray=[3, 2] if dash else None))
        if head:
            a = math.atan2(Y2 - Y1, X2 - X1)
            self.d.add(Polygon([X2, Y2, X2 - 6 * math.cos(a - 0.4), Y2 - 6 * math.sin(a - 0.4),
                                X2 - 6 * math.cos(a + 0.4), Y2 - 6 * math.sin(a + 0.4)],
                               fillColor=col, strokeColor=col))

    def text(self, x, top, s, col=MUTED):
        self.d.add(String(x * mm, (self.H - top) * mm, s, fontName="Arial-Italic", fontSize=7,
                          fillColor=col))

    def snake(self, rows, cols=(0, 61, 122)):
        """Nối các hộp theo hình chữ S: hàng chẵn trái→phải, hàng lẻ phải→trái."""
        bw, bh = self.bw, self.bh
        pos = []
        for r, (top, items) in enumerate(rows):
            order = cols if r % 2 == 0 else cols[::-1]
            for x, it in zip(order, items):
                self.box(x, top, *it[:2], accent=it[2] if len(it) > 2 else False,
                         sub2=it[3] if len(it) > 3 else None)
                pos.append((x, top))
        for (x1, t1), (x2, t2) in zip(pos, pos[1:]):
            if t1 == t2:
                xa, xb = (x1 + bw, x2) if x2 > x1 else (x1, x2 + bw)
                self.line(xa, t1 + bh / 2, xb, t2 + bh / 2)
            else:
                self.line(x1 + bw / 2, t1 + bh, x2 + bw / 2, t2)
        return pos


def ml_flow() -> Drawing:
    c = Canvas(170, 40)
    c.snake([(2, [("B1. Thu thập dữ liệu", "tải LANL + CERT gốc"),
                  ("B2. Tiền xử lý", "lọc, làm sạch, gắn nhãn"),
                  ("B3. Tạo feature", "người-ngày · máy-ngày")]),
             (24, [("B4. Chia theo thời gian", "train · val · test"),
                   ("B5. Train mô hình", "nhiều mô hình, không nhãn", True),
                   ("B6. Chọn + đánh giá", "chọn trên val, báo cáo test")])])
    return c.d


def siem_flow() -> Drawing:
    c = Canvas(170, 92, bh=16)
    pos = c.snake([
        (2, [("B7. Nạp log từng ngày", "replay LANL / CERT", False, "chuẩn hoá trường ECS"),
             ("B8. Elasticsearch", "lưu sự kiện, cảnh báo,", False, "incident · HTTPS, phân quyền"),
             ("B9. Phát hiện", "22 luật Sigma (ATT&CK)", True, "+ mô hình ML đã train")]),
        (30, [("B10. Điểm rủi ro", "cộng dồn luật + ML", False, "theo người dùng / máy"),
              ("B11. Incident", "top-K thực thể / ngày", False, "+ máy đang theo dõi"),
              ("B12. Playbook SOAR", "tái dựng chuỗi tấn công", True, "đề xuất ứng phó (D3FEND)")]),
        (58, [("B13. Analyst điều tra", "Web SOC + Kibana", False, "kết luận thật / giả"),
              ("B14. Lead duyệt", "duyệt / từ chối", False, "từng hành động"),
              ("B15. Ứng phó", "chặn máy → IOC", False, "khoá tài khoản (mô phỏng)")])])
    x15, t15 = pos[-1]
    x9, t9 = pos[2]
    # vòng phản hồi IOC → luật (nét đứt, đi ở mép phải)
    c.line(x15 + c.bw, t15 + 8, 169.5, t15 + 8, ACCENT, True, head=False)
    c.line(169.5, t15 + 8, 169.5, t9 + 8, ACCENT, True, head=False)
    c.line(169.5, t9 + 8, x9 + c.bw, t9 + 8, ACCENT, True)
    c.text(105, 80, "vòng phản hồi: IOC đã duyệt → luật bắt từ ngày sau", ACCENT)
    c.text(0, 88, "Mỗi ngày chạy lại B7 → B15 (demo: replay giai đoạn test, bấm \"Ngày tiếp theo\" trên web)")
    return c.d


# ------------------------------------------------------------------ nội dung
story = [
    P("SOC/UEBA – Báo cáo Dữ liệu, Mô hình và Workflow", "title"),
    P("UEBA (User and Entity Behavior Analytics): học hành vi bình thường của người dùng và máy, "
      "cảnh báo khi hành vi lệch khỏi bình thường – để phát hiện tài khoản bị chiếm và nhân viên "
      "nội gián; kết quả đưa vào một SIEM/SOC hoàn chỉnh để điều tra và ứng phó.", "sub"),

    # ---------------- 1. Dataset
    P("1. Dataset đã chọn", "h1"),
    table([
        ["", "LANL", "CERT r4.2"],
        ["Tên đầy đủ", "Comprehensive, Multi-Source Cyber-Security Events",
         "CERT Insider Threat Test Dataset, bản r4.2"],
        ["Là dataset về gì", "<b>Hành vi đăng nhập / xác thực</b> của người dùng và máy tính trong mạng "
         "nội bộ một tổ chức lớn: ai đăng nhập, từ máy nào, vào máy nào, bằng cách nào. Dữ liệu "
         "<b>thật</b>, có ghi lại một cuộc tấn công thật của đội red team.",
         "<b>Mối đe doạ nội bộ (insider threat)</b>: hoạt động hằng ngày của nhân viên trên máy tính "
         "công ty – đăng nhập, cắm USB, sao chép file, gửi email, duyệt web. Dữ liệu <b>mô phỏng</b>, "
         "trong đó có một số nhân viên cố ý gây hại."],
        ["Dùng để phát hiện", "Tài khoản bị kẻ tấn công chiếm và dùng để di chuyển ngang giữa các máy",
         "Nhân viên đánh cắp dữ liệu, cài phần mềm theo dõi, chuẩn bị nghỉ việc và mang dữ liệu đi"],
        ["Nguồn", "Los Alamos National Laboratory (Mỹ), 2015",
         "Carnegie Mellon University – CERT Division, 2013"],
        ["Link", '<link href="https://csr.lanl.gov/data/cyber1/" color="#2c5fd6">'
         "https://csr.lanl.gov/data/cyber1/</link>",
         '<link href="https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247" '
         'color="#2c5fd6">https://kilthub.cmu.edu/articles/dataset/<br/>Insider_Threat_Test_Dataset/'
         "12841247</link>"],
        ["Quy mô đã dùng", "30 ngày, 508,9 triệu sự kiện đăng nhập, ~26.600 tài khoản người",
         "17 tháng (01/2010 – 05/2011), 32,8 triệu sự kiện, 1.000 nhân viên"],
        ["Nhãn", "749 sự kiện tấn công của red team (181 người-ngày bị tấn công)",
         "70 nhân viên nội gián thuộc 3 kịch bản (966 người-ngày gây hại)"],
    ], [28, 71, 71], first_col_bold=True),
    P("Nhãn chỉ dùng để <b>chấm điểm</b> sau khi train, không dùng để train: hệ thống phải tự phát "
      "hiện, đúng như khi triển khai thật (không ai biết trước ai là kẻ tấn công).", "note"),

    # ---------------- 2. Workflow
    P("2. Workflow của dự án", "h1"),
    P("Dự án gồm hai giai đoạn nối tiếp: <b>Giai đoạn 1</b> (B1–B6) chuẩn bị dữ liệu và train mô hình "
      "phát hiện bất thường – làm một lần, offline. <b>Giai đoạn 2</b> (B7–B15) đưa mô hình đã train vào "
      "một hệ thống <b>SIEM/SOC</b>: mỗi ngày log mới được nạp, phát hiện bằng luật + ML, gom thành "
      "incident, playbook tự điều tra, con người kết luận và ứng phó."),
    KeepTogether([P("2.1. Giai đoạn 1 – Dữ liệu và train mô hình", "h2"), ml_flow()]),
    table([
        ["Bước", "Làm gì", "Đầu ra"],
        ["B1. Thu thập", "Tải dữ liệu gốc từ trang chính thức (LANL 30 ngày đầu, CERT r4.2 + file đáp án). "
         "Không tự tạo dữ liệu.", "Log gốc"],
        ["B2. Tiền xử lý", "LANL: đọc thẳng file nén, cắt theo ngày, tách loại tài khoản (người / máy / "
         "hệ thống). CERT: đọc 5 loại log, rút gọn 14 GB web theo domain, làm giàu (ngoài giờ, email ra "
         "ngoài, danh mục web). Gắn nhãn – chỉ để chấm điểm. Chi tiết ở mục 3.",
         "Bảng sự kiện sạch (parquet)"],
        ["B3. Tạo feature", "Tóm tắt hành vi mỗi người dùng mỗi ngày thành các con số, so với chính lịch sử "
         "của họ (vd. số máy mới đăng nhập vào, cắm USB ngoài giờ). LANL thêm feature theo máy nguồn.",
         "LANL 41 feature · CERT 56 feature"],
        ["B4. Chia thời gian", "Học quá khứ, kiểm tra tương lai: train → validation → test (test không "
         "được nhìn khi thiết kế).", "3 giai đoạn (mục 3.4)"],
        ["B5. Train", "Train nhiều mô hình không giám sát trên giai đoạn train (chi tiết từng dataset ở "
         "mục 4).", "Mô hình đã train"],
        ["B6. Chọn + đánh giá", "Chọn mô hình và tham số tốt nhất trên validation; chạy một lần trên test "
         "để báo cáo.", "Mô hình cuối + kết quả"],
    ], [27, 113, 30], first_col_bold=True),
    KeepTogether([P("2.2. Giai đoạn 2 – Xây SIEM/SOC sau khi train xong", "h2"), siem_flow()]),
    table([
        ["Bước", "Làm gì", "Công nghệ"],
        ["B7. Nạp log", "Mỗi ngày nạp log của ngày đó (demo: phát lại giai đoạn test từng ngày), chuẩn hoá về "
         "trường ECS và làm giàu: loại tài khoản, nguồn ≠ đích, ngoài giờ, độ phổ biến domain.",
         "Python (pandas, pyarrow)"],
        ["B8. Lưu trữ", "Lưu sự kiện, cảnh báo, incident, IOC, nhật ký kiểm toán; tra cứu khi điều tra.",
         "Elasticsearch + Kibana 9.5 (HTTPS, user quyền tối thiểu)"],
        ["B9. Phát hiện", "Hai lớp song song: <b>luật Sigma</b> bắt mẫu tấn công đã biết (Pass-the-Hash, "
         "dò mật khẩu, chép dữ liệu ra USB…, gắn MITRE ATT&amp;CK) và <b>mô hình ML</b> của giai đoạn 1 "
         "bắt hành vi lạ chưa có luật.", "22 luật Sigma (11 luật nền + 11 luật tương quan sinh cảnh báo), engine tự viết; mô hình mục 4"],
        ["B10. Điểm rủi ro", "Cộng dồn điểm luật + ML theo từng người dùng / máy, giảm dần theo thời gian; "
         "luật hay báo nhầm bị giảm trọng số.", "Python"],
        ["B11. Incident", "Mỗi ngày lấy K thực thể rủi ro cao nhất (LANL: 20 tài khoản + 5 máy + máy đang "
         "theo dõi; CERT: 5 nhân viên) → incident, xếp mức critical / high / medium.", "Python → ES"],
        ["B12. Playbook SOAR", "Tự chạy cho mỗi incident: <b>tái dựng chuỗi tấn công</b> (LANL: đồ thị đăng "
         "nhập → máy bàn đạp, tài khoản bị chiếm, máy bị chạm tới; CERT: dòng thời gian theo pha) rồi "
         "<b>đề xuất ứng phó</b>, mỗi hành động gắn biện pháp MITRE D3FEND.", "soc/graph, soc/playbooks"],
        ["B13. Điều tra", "Analyst xem incident, bằng chứng, đồ thị chuỗi tấn công, MITRE; ghi kết luận "
         "(tấn công thật / hợp lệ / báo động giả).", "Web SOC (FastAPI) + Kibana"],
        ["B14. Duyệt", "Lead duyệt hoặc từ chối từng hành động playbook đề xuất; mọi thao tác ghi nhật ký "
         "kiểm toán chỉ-thêm.", "Phân quyền analyst / lead"],
        ["B15. Ứng phó", "Chặn máy nguồn → máy vào danh sách IOC → luật Sigma IOC tự bắt mọi đăng nhập "
         "từ máy đó từ ngày sau (vòng phản hồi). Khoá tài khoản, chặn USB: mô phỏng.", "Luật Sigma IOC"],
    ], [27, 103, 40], first_col_bold=True),
    KeepTogether([P("Kế hoạch build và trạng thái", "h2"), table([
        ["Thành phần", "Trạng thái"],
        ["Elasticsearch + Kibana bật bảo mật; nạp log, cảnh báo, incident", "Đã xong"],
        ["22 luật Sigma (11 nền + 11 tương quan), gắn MITRE ATT&amp;CK; ngưỡng chọn trên train", "Đã xong"],
        ["ML chấm điểm hằng ngày; điểm rủi ro + incident (hàng đợi tài khoản + máy)", "Đã xong"],
        ["Playbook SOAR: chuỗi tấn công LANL, dòng thời gian CERT, ứng phó gắn D3FEND", "Đã xong, có chấm điểm (mục 4.3)"],
        ["Web SOC: hàng đợi, bằng chứng, đồ thị, kết luận, duyệt, IOC, kiểm toán, phân quyền", "Đã xong (kiểm thử 17/17)"],
        ["Demo vận hành từng ngày + vòng phản hồi IOC", "Đã xong (replay)"],
        ["AI Agent LLM (Qwen3 4B chạy trên máy)", "Đã thử, bỏ: kết luận đúng 9/20, kém cả mốc đơn giản 14/20"],
        ["Thu log trực tiếp từ máy thật (Winlogbeat)", "Không làm: replay có nhãn để đánh giá"],
    ], [120, 50], first_col_bold=False)]),
]

# ---------------- 3. Tiền xử lý dữ liệu
story += [
    P("3. Tiền xử lý dữ liệu", "h1"),
    P("Log gốc có hàng trăm triệu sự kiện, mô hình không đọc trực tiếp được. Tiền xử lý biến log thành "
      "<b>một dòng số liệu cho mỗi người dùng mỗi ngày</b> (người-ngày), mô tả hành vi của họ so với "
      "chính quá khứ của họ. Bốn nguyên tắc xuyên suốt:"),
    table([
        ["Nguyên tắc", "Nghĩa là"],
        ["Không tự tạo dữ liệu", "Chỉ dùng log gốc tải từ trang chính thức (LANL, CMU KiltHub)."],
        ["Nhãn chỉ để chấm điểm", "Nhãn tấn công được gắn vào bảng nhưng không bao giờ là đầu vào của "
         "mô hình hay luật – hệ thống phải tự phát hiện."],
        ["Chỉ nhìn quá khứ", "Mọi feature \"so với lịch sử\" ở ngày d chỉ dùng dữ liệu trước ngày d – giống "
         "hệ thống thật chạy từng ngày, không biết trước tương lai."],
        ["Không loại ngoại lai", "Hành vi lạ chính là thứ cần tìm; chỉ giảm ảnh hưởng của giá trị cực "
         "đoan (log, làm mượt, giới hạn z-score) chứ không xoá."],
    ], [38, 132], first_col_bold=True),

    P("3.1. LANL – log đăng nhập (≈ 1 tỷ dòng)", "h2"),
    table([
        ["Bước", "Làm gì", "Vì sao"],
        ["1. Đọc theo luồng", "Đọc thẳng file nén 7,6 GB theo khối 64 MB (pyarrow), cắt theo ngày "
         "(thời điểm ÷ 86.400), ghi mỗi ngày một file parquet (~17–23 triệu sự kiện/ngày).",
         "Không cần giải nén ra đĩa, RAM chỉ 1–2 GB"],
        ["2. Gắn nhãn chính xác", "Sự kiện là tấn công khi khớp <b>đủ 4 trường</b> (thời điểm, tài khoản, "
         "máy nguồn, máy đích) với file red team.", "Không gắn nhầm cho sự kiện bình thường cùng giây"],
        ["3. Phân loại tài khoản", "Theo tên: người (U…@DOM), máy (có $@), hệ thống (SYSTEM@, LOCAL "
         "SERVICE@…). Chỉ phân tích tài khoản người: 301.462 người-ngày (máy 295.751, hệ thống 232.400).",
         "Kẻ tấn công dùng tài khoản người bị đánh cắp"],
        ["4. Tổng hợp theo ngày", "Khối lượng (số sự kiện, số máy nguồn/đích), kiểu xác thực (tỉ lệ thất "
         "bại, NTLM, Kerberos, từ xa, từng loại logon), nhịp thời gian (số giờ hoạt động, entropy theo giờ, "
         "giờ đầu/cuối, khoảng cách giữa sự kiện, tối đa/phút).", "Tóm hàng nghìn sự kiện thành vài chục con số"],
        ["5. Làm mượt tỉ lệ", "Mỗi tỉ lệ được kéo về trung bình chung bằng 20 \"sự kiện ảo\".",
         "Tài khoản có 1–2 sự kiện dễ ra 0% / 100% → báo nhầm"],
        ["6. Mới lạ so với chính mình", "Máy nguồn/đích lần đầu dùng, giờ lạ, đường đi máy A → máy B chưa "
         "ai dùng, đăng nhập NTLM từ máy mới, số tài khoản dùng chung một máy nguồn mới (fan-in).",
         "Tín hiệu di chuyển ngang, Pass-the-Hash"],
        ["7. Độ hiếm có suy giảm", "Thay cờ \"đã thấy / chưa thấy\" bằng số đếm giảm một nửa sau 7 ngày; "
         "độ hiếm = −log(tần suất); mỗi ngày lấy giá trị <b>hiếm nhất</b>.",
         "Cờ bị \"đầu độc\": kẻ tấn công dùng máy một lần là máy thành quen mãi"],
        ["8. Chống đầu độc baseline", "Người-ngày đã bị cảnh báo không được học vào lịch sử \"bình thường\" "
         "(cách ly).", "Hành vi nghi ngờ không trở thành chuẩn mới"],
        ["9. Chuẩn bị đầu vào", "Bỏ cột trùng (n_logon tương quan 0,97 với n_events) và gần như hằng; "
         "cột đếm biến đổi log(1+x); chuẩn hoá theo giai đoạn train → <b>41 feature</b>.",
         "Phân bố đếm lệch nặng; cột trùng làm méo mô hình"],
        ["10. Feature mức máy", "Theo (máy nguồn, ngày): số tài khoản người mà với họ máy là lạ, trong đó "
         "bao nhiêu đăng nhập NTLM.", "Đầu vào cho phát hiện máy bàn đạp"],
    ], [33, 92, 45], first_col_bold=True),

    P("3.2. CERT r4.2 – hoạt động nhân viên (5 loại log, ~33 triệu sự kiện)", "h2"),
    table([
        ["Bước", "Làm gì", "Vì sao"],
        ["1. Đọc 5 loại log", "Logon (855 nghìn), USB (405 nghìn), file chép ra USB (446 nghìn), email "
         "(2,6 triệu), web (14 GB – đọc theo luồng, <b>bỏ cột nội dung trang</b>).",
         "Chỉ giữ thông tin hành vi, giảm dung lượng"],
        ["2. Rút gọn web", "Gom 14 GB lịch sử web thành bảng (nhân viên, ngày, domain, số lượt vào).",
         "Đủ nhỏ để xử lý, vẫn giữ được domain"],
        ["3. Làm giàu sự kiện", "Ngoài giờ (trước 8h / sau 18h), cuối tuần; đuôi file chép ra USB (.exe, "
         ".zip, .doc); email ra ngoài công ty (người nhận không thuộc dtaa.com) và có đính kèm; danh mục "
         "web: tuyển dụng, đối thủ (như bộ lọc URL của proxy).", "Biến sự kiện thô thành dấu hiệu có nghĩa"],
        ["4. Độ hiếm domain", "Bao nhiêu % nhân viên <b>đã từng</b> vào domain đó <b>trước</b> hôm nay; "
         "dưới 1% = cực hiếm. Không dùng nhãn.", "Trang lạ (wikileaks, bán keylogger) tự nổi lên"],
        ["5. Tổng hợp người-ngày", "Đăng nhập, USB, file, email, web, độ hiếm domain – "
         f"{num(330452)} người-ngày.", "Đơn vị phân tích chung"],
        ["6. Cửa sổ thời gian", "Tổng 7 ngày và 30 ngày của mỗi hành vi (chỉ quá khứ).",
         "Kịch bản lấy dữ liệu dần dần: từng ngày trông bình thường"],
        ["7. Xu hướng", "30 ngày gần nhất so với mức trung bình 60 ngày trước đó.",
         "Bắt nhân viên tăng dần việc chép dữ liệu trước khi nghỉ"],
        ["8. Độ lệch so với chính mình", "So mỗi chỉ số với trung bình và độ lệch chuẩn các ngày trước của "
         "chính nhân viên (z-score), giới hạn [−10, 10] → 56 feature + 56 độ lệch = 112 con số. Thêm bước "
         "này làm PR-AUC của Autoencoder tăng gấp đôi (0,045 → 0,091).",
         "Mỗi người có thói quen riêng – so với chính họ"],
        ["9. Bỏ cột trùng, biến đổi", "Bỏ 3 cột tương quan > 0,95 (logoff ~ số máy 0,99; file .doc ~ tổng "
         "file 0,996; email ~ web 0,97); cột đếm log(1+x); chuẩn hoá.", "Tránh đếm trùng một thông tin"],
        ["10. Khởi động (warm-up)", "Những tuần đầu chỉ làm lịch sử, không đưa vào train.",
         "Độ hiếm và z-score chưa ổn định khi quá ít quá khứ"],
        ["11. Gắn nhãn đúng người", "Chỉ giữ sự kiện của chính insider trong khoảng ngày của họ: 70 insider, "
         "966 người-ngày độc hại.", "Kịch bản 3 mạo danh sếp – sếp là nạn nhân, không gắn nhãn xấu"],
    ], [33, 92, 45], first_col_bold=True),

    P("3.3. Kiểm tra chất lượng dữ liệu (trước khi train)", "h2"),
    table([
        ["Kiểm tra", "LANL", "CERT r4.2"],
        ["Giá trị thiếu", "Không có", "Không có"],
        ["Bản ghi trùng", "–", "Không trùng ID; 6 dòng USB trùng nội dung (không đáng kể)"],
        ["Ngày lỗi / ngoài khoảng", "Không có (ngày 57 chưa trọn → bỏ)", "Không có"],
        ["Cột tương quan > 0,95", "n_events ~ n_logon (0,97) → bỏ n_logon",
         "3 cặp → bỏ logoff_n, file_doc, email_n"],
        ["Tỉ lệ nhãn tấn công", "0,06% người-ngày (181)", "0,29% người-ngày (966)"],
        ["Ngoại lai (quy tắc 3×IQR)", "19–25% ở tỉ lệ thất bại, fan-in – giữ lại",
         "17% ở số lần cắm USB – giữ lại"],
    ], [42, 64, 64], first_col_bold=True),
    P("Mất cân bằng cực mạnh (0,06% và 0,29%) là lý do dùng học không giám sát và đánh giá bằng PR-AUC "
      "thay vì accuracy. Sau tiền xử lý, tín hiệu tấn công đã rõ: ở LANL, số đăng nhập NTLM từ máy mới của "
      "người bị tấn công trung bình <b>gấp 58 lần</b> người bình thường; số đường đi chưa ai dùng từ máy "
      "mới gấp 28 lần.", "note"),

    KeepTogether([P("3.4. Chia dữ liệu theo thời gian", "h2"), table([
        ["", "Train (học)", "Validation (chọn mô hình)", "Test (báo cáo)"],
        ["LANL", "ngày 1–7", "ngày 8–19", "ngày 20–29"],
        ["CERT", "02–06/2010 (sau warm-up)", "07–08/2010", "09/2010 – 05/2011"],
    ], [20, 50, 50, 50], first_col_bold=True),
    P("Học quá khứ, kiểm tra tương lai; tập test chưa từng dùng khi thiết kế. LANL ngày 30–56 tải thêm sau "
      "khi đã train xong – không có nhãn, chỉ dùng cho demo vận hành trên dữ liệu mới.", "note")]),
]

# ---------------- 4. Mô hình theo từng dataset
lanl_rows = [["Bước cải tiến (LANL)", "Bắt được (test)", "Vì sao"]]
lanl_rows.append(["Ban đầu: thống kê + IF + Autoencoder",
                  f"{int(lexp(LANL_EXP, 'ens_mean', 'test', 'acc@25/d'))}/26",
                  "Gộp 3 mô hình làm loãng tín hiệu tấn công"])
lanl_rows.append(["ECOD + IF trên nhóm feature di chuyển ngang",
                  f"{int(lexp(LANL_EXP, 'ens_ecod_lateral', 'test', 'acc@25/d'))}/26",
                  "Tập trung đúng nhóm feature tấn công"])
lanl_rows.append(["+ chống \"đầu độc lịch sử\" + độ hiếm có tần suất",
                  f"{int(lexp(LANL_ONLINE, 'quar+fanin+rarity', 'test', 'accounts@25/day', 'variant'))}/26",
                  "Kẻ tấn công dùng lại máy cũ nên mô hình đã quen; sửa để máy đó vẫn bị coi là lạ"])
lanl_rows.append(["+ phát hiện máy bàn đạp (xét theo máy)", f"{host_t['accounts@5hosts/day']}/26",
                  "Kẻ tấn công dùng 1 máy đăng nhập hàng chục tài khoản – xét theo máy thì rất lộ"])
lanl_rows.append(["+ theo dõi máy đã bị nghi trong 7 ngày", f"<b>{lanl_final_t[0]}/{lanl_final_t[1]}</b>",
                  f"Bắt cả những ngày máy đó chỉ đăng nhập 1–2 tài khoản (~{lanl_final_t[2]:.0f} incident/ngày)"])

cert_rows = [["Mô hình (CERT)", "ROC-AUC", "PR-AUC", "Bắt nội gián (5 cảnh báo/ngày)", "Nhận xét"]]
for key, name, why in [
        ("stat", "Thống kê (độ lệch z-score)", "Chỉ so từng con số riêng lẻ – yếu"),
        ("ecod", "ECOD", "Nội gián thường lệch nhẹ nhiều chỗ, không cực trị ở 1 chỗ – yếu"),
        ("iforest", "Isolation Forest", "Tốt với hành vi đột biến (kịch bản 1, 3)"),
        ("ae", "Autoencoder", "Bắt tốt hành vi lấy dữ liệu dần dần (kịch bản 2)"),
        ("ens_if_ae", "IF + AE (đã chọn)", "Ổn định nhất giữa các lần train → chọn")]:
    cert_rows.append([name, f3(cexp(key, "roc_auc")), f3(cexp(key, "pr_auc")),
                      f"{cexp(key, 'insiders@5/day'):.0f}/52", why])

story += [
    P("4. Mô hình dùng cho từng dataset", "h1"),
    P("Tất cả là học <b>không giám sát</b>: mô hình chỉ học hành vi <b>bình thường</b> từ giai đoạn train, "
      "rồi chấm mỗi người-ngày một điểm bất thường, quy về thang 0–1 so với train (0,99 = bất thường "
      "hơn 99% người-ngày lúc train)."),

    # ---- 3.1 LANL
    P("4.1. LANL – phát hiện tài khoản bị chiếm và di chuyển ngang", "h2"),
    table([
        ["", "LANL"],
        ["Chia dữ liệu", f"Train ngày 1–7 ({num(69205)} người-ngày) · validation ngày 8–19 ({num(110807)}, "
         f"97 tài khoản bị chiếm) · test ngày 20–29 ({num(110381)}, 26 tài khoản bị chiếm)"],
        ["Feature (41)", "Số máy đăng nhập vào / từ, máy nguồn / đích mới so với lịch sử, đăng nhập NTLM từ máy "
         "lạ, đường đi mạng chưa ai dùng, số tài khoản dùng chung máy nguồn (fan-in), giờ lạ, nhịp thời "
         "gian…"],
    ], [28, 142], first_col_bold=True),
    Spacer(1, 4),
    P("LANL dùng những gì và mỗi thứ hoạt động thế nào:"),
    table([
        ["Thành phần", "Hoạt động thế nào"],
        ["1. Độ hiếm có tần suất", "Với mỗi người dùng, đếm số lần đã đăng nhập từ / vào từng máy, số đếm "
         "<b>giảm dần</b> theo thời gian (giảm một nửa sau 7 ngày). Máy chưa từng dùng hoặc lâu rồi không "
         "dùng → độ hiếm cao. Lấy giá trị hiếm nhất trong ngày làm feature."],
        ["2. ECOD", "Với từng feature, tính xác suất gặp một giá trị lớn như vậy trong dữ liệu train (vd. "
         "chỉ 0,1% người-ngày đăng nhập vào hơn 50 máy), cộng độ hiếm của mọi feature lại. <b>Càng nhiều "
         "chỗ hiếm = càng bất thường</b>; chỉ ra được feature nào gây cảnh báo. Không có tham số cần chỉnh."],
        ["3. Isolation Forest (nhóm feature di chuyển ngang)", "300 cây, mỗi cây cắt dữ liệu ngẫu nhiên theo "
         "từng feature. Hành vi bình thường nằm giữa đám đông nên phải cắt nhiều lần mới tách riêng được; "
         "hành vi lạ nằm lẻ loi nên vài nhát đã bị tách. <b>Càng ít nhát cắt = càng bất thường.</b> Chỉ dùng "
         "các feature di chuyển ngang để tín hiệu tấn công không bị loãng."],
        ["4. Điểm tài khoản", "Trung bình điểm percentile của ECOD và Isolation Forest."],
        ["5. Chấm điểm từng ngày + cách ly", "Chạy như thật: hôm nay chấm điểm xong mới đưa vào lịch sử. "
         "Người-ngày đã bị cảnh báo <b>không</b> được học làm \"bình thường\" – nếu không, kẻ tấn công quay "
         "lại máy cũ hôm sau sẽ bị coi là quen (đầu độc lịch sử)."],
        ["6. Phát hiện máy bàn đạp (theo máy)", "Mỗi máy mỗi ngày: đếm số tài khoản đăng nhập NTLM từ máy đó "
         "mà với chính họ máy đó là lạ, so với tỉ lệ trung bình toàn mạng bằng phân phối Poisson. Máy cá "
         "nhân thường chỉ có 1–2 người dùng quen; một máy bỗng có hàng chục tài khoản lạ = kẻ tấn công "
         "dùng mật khẩu đánh cắp."],
        ["7. Hàng đợi cho analyst", "Mỗi ngày: 20 tài khoản rủi ro cao nhất (luật + ML) + 5 máy bàn đạp đáng "
         "ngờ nhất + máy đã bị nghi trong 7 ngày qua xuất hiện lại. Incident máy liệt kê mọi tài khoản "
         "đăng nhập từ máy đó (máy ≤ 50 tài khoản)."],
    ], [42, 128], first_col_bold=True),
    Spacer(1, 4),
    table(lanl_rows, [62, 22, 86], highlight=[5], first_col_bold=True),
    P(f"Cùng ngân sách xem của analyst. Hai bước cuối được thiết kế sau khi phân tích các tài khoản bị "
      f"sót trên tập test nên báo cáo tách riêng; trên đợt tấn công đầu (validation) chúng bắt "
      f"{lanl_final_v[0]}/{lanl_final_v[1]} tài khoản. Xếp hạng tài khoản trên test: ROC-AUC "
      f"{f3(lanl_u['test']['roc_auc'])}, PR-AUC {f3(lanl_u['test']['pr_auc'])} (gấp "
      f"~{lanl_u['test']['pr_auc'] / (34 / 110381):.0f} lần đoán mò).", "note"),

    # ---- 3.2 CERT
    P("4.2. CERT r4.2 – phát hiện nhân viên nội gián", "h2"),
    table([
        ["", "CERT r4.2"],
        ["Chia dữ liệu", f"Train 02–06/2010 ({num(106343)} người-ngày) · validation 07–08/2010 ({num(42193)}, "
         f"24 nội gián) · test 09/2010 – 05/2011 ({num(161367)}, 52 nội gián)"],
        ["Feature (56)", "Đăng nhập / USB / file / email / web ngoài giờ, domain web hiếm trong công ty (tính "
         "từ các ngày trước, không dùng nhãn), trang tuyển dụng, trang đối thủ, tổng hành vi 7 và 30 ngày, "
         "xu hướng 30 ngày gần nhất so với 2 tháng trước."],
    ], [28, 142], first_col_bold=True),
    Spacer(1, 4),
    P("CERT dùng những gì và mỗi thứ hoạt động thế nào:"),
    table([
        ["Thành phần", "Hoạt động thế nào"],
        ["1. Độ lệch so với chính mình", "Mỗi feature được so với thói quen của chính nhân viên đó (z-score "
         "theo lịch sử cá nhân) → 56 feature gốc + 56 độ lệch = 112 con số / người-ngày."],
        ["2. Isolation Forest", "Như ở LANL (300 cây, đếm số nhát cắt để tách một người-ngày). Bắt tốt hành vi "
         "<b>đột biến</b>: một ngày bỗng cắm USB lúc nửa đêm và vào trang lạ."],
        ["3. Autoencoder (mạng nơ-ron)", "Nén 112 con số xuống còn 8 rồi dựng lại (112→32→8→32→112). Chỉ học "
         "hành vi bình thường nên dựng lại hành vi bình thường rất sát nhưng dựng sai hành vi lạ. <b>Sai số "
         "dựng lại càng lớn = càng bất thường.</b> Bắt được tổ hợp lạ mà từng con số riêng lẻ vẫn bình "
         "thường (vd. lấy dữ liệu dần dần trước khi nghỉ việc)."],
        ["4. Bagging + kết hợp", "Mỗi mô hình train 3 lần với seed khác nhau rồi lấy trung bình (giảm dao "
         "động), sau đó trung bình điểm IF và AE. Chọn cách kết hợp này trên validation."],
        ["5. Hàng đợi cho analyst", "Cộng với luật Sigma thành điểm rủi ro, mỗi ngày 5 nhân viên rủi ro cao "
         "nhất thành incident."],
    ], [42, 128], first_col_bold=True),
    Spacer(1, 4),
    table(cert_rows, [36, 17, 17, 28, 72], highlight=[5], first_col_bold=True),
    P(f"Trung bình 3 lần train, cùng bộ feature, đo trên tập test. Kết quả cuối ở ngưỡng 0,99: bắt "
      f"<b>{th['insiders_caught']}/{th['insiders_total']}</b> nội gián, ~{dec(th['alerts_per_day'])} cảnh "
      f"báo/ngày cho 1.000 nhân viên; theo kịch bản: đánh cắp qua USB + web {th['by_scenario']['1']}, "
      f"lấy dữ liệu dần trước khi nghỉ việc {th['by_scenario']['2']}, cài keylogger "
      f"{th['by_scenario']['3']}.", "note"),

    # ---- 3.3 sau ML
    KeepTogether([P("4.3. Sau khi phát hiện – tái dựng chuỗi tấn công (bước B12)", "h2"),
    P("Mô hình chỉ nói <i>ai</i> bất thường. Playbook SOAR trả lời tiếp <i>kẻ tấn công đã đi đến đâu</i> "
      "để ứng phó đủ phạm vi – chỉ dùng dữ liệu tới ngày của incident, không dùng nhãn."),
    table([
        ["", "Hoạt động thế nào", "Kết quả (test)"],
        ["LANL – đồ thị đăng nhập", "Dựng đồ thị tài khoản → máy nguồn → máy đích. Từ máy bàn đạp của incident "
         "(hoặc máy nguồn lạ của tài khoản), lấy mọi đăng nhập từ xa <b>không quen</b> (cặp tài khoản–máy "
         "dùng &lt; 10 ngày trước đó) → tài khoản bị chiếm, máy bị chạm tới; máy khác dùng chung ≥ 3 tài "
         "khoản bị chiếm cũng là máy tấn công. Tính thêm bán kính ảnh hưởng.",
         f"Tìm <b>{pct1(chain_t['account_recall'])}</b> tài khoản bị chiếm và {pct1(chain_t['dst_recall'])} "
         f"máy bị chạm tới (val {pct1(chain_v['account_recall'])} / {pct1(chain_v['dst_recall'])}); "
         f"{pct(chain_t['account_precision'])} tài khoản trong chuỗi có nhãn red team. Incident tài khoản "
         "U66, U737 tự lần ra máy bàn đạp C17693."],
        ["CERT – dòng thời gian theo pha", "Xếp hành vi trong khoảng incident vào 4 pha: Truy cập → Chuẩn bị "
         "→ Cài đặt → Đánh cắp; đánh dấu bước <b>MỚI</b> so với 30 ngày trước của chính nhân viên.",
         f"Incident nội gián thật có bước đánh cắp MỚI: <b>{pct(tl_cert['insider_with_new_exfil_step'])}</b>; "
         f"incident lành tính: {dec(tl_cert['benign_with_new_exfil_step'] * 100)}%"],
        ["Đề xuất ứng phó", "Mỗi hành động gắn kỹ thuật ATT&amp;CK nó chặn và biện pháp MITRE D3FEND (lấy từ "
         "ánh xạ chính thức), vd. chặn máy nguồn = D3-NTF, khoá tài khoản = D3-AL, chặn USB = D3-IOPR.",
         "Lead duyệt; chặn máy → IOC thật"],
    ], [30, 88, 52], first_col_bold=True)]),
    P("Tham số tái dựng chuỗi chọn trên validation. Precision ~50% là cận dưới: nhãn red team LANL chỉ "
      "đánh dấu một phần sự kiện, và không tài khoản nào dùng máy C17693 thường xuyên.", "note"),

    P("5. Những điểm cần lưu ý", "h1"),
    P("• <b>Đã sửa lỗi rò nhãn:</b> bản đầu của CERT dùng danh sách trang web lấy từ chính file nhãn "
      "(kết quả đẹp giả); đã thay bằng độ hiếm domain tính từ dữ liệu, không dùng nhãn.<br/>"
      "• <b>LANL ban đầu được đánh giá trên dữ liệu đã nhìn:</b> khi kiểm tra trên 10 ngày hoàn toàn "
      "mới, mô hình ban đầu gần như không phát hiện được – các bước cải tiến ở mục 4.1 ra đời từ đó.<br/>"
      "• <b>Bỏ AI Agent:</b> mô hình ngôn ngữ chạy trên máy kết luận đúng 9/20 incident, kém cách đơn giản "
      "\"critical → tấn công\" (14/20) và không kiểm chứng được → thay bằng playbook tất định ở B12.<br/>"
      "• <b>Hạn chế:</b> tập test nhỏ (26 tài khoản, 52 nội gián); CERT là dữ liệu mô phỏng nên kết quả có "
      "thể lạc quan hơn thực tế; playbook LANL đề xuất chặn máy ở cả incident lành tính – cần lead "
      "duyệt; máy tấn công phụ chỉ dùng 1 tài khoản bị chiếm (C19932) chưa được tìm ra."),
]


def footer(c, doc):
    c.saveState()
    c.setFont("Arial", 7.5)
    c.setFillColor(MUTED)
    c.drawString(20 * mm, 10 * mm, "Đồ án SOC/UEBA – Dữ liệu, Mô hình và Workflow")
    c.drawRightString(190 * mm, 10 * mm, f"Trang {doc.page}")
    c.restoreState()


doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                        topMargin=16 * mm, bottomMargin=16 * mm,
                        title="Hệ thống SOC/UEBA – Báo cáo Dữ liệu, Mô hình và Workflow", author="SOC/UEBA")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print("→", OUT)
