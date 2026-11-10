// Đặt theme trước khi vẽ trang (tránh nháy): mặc định tối, nhớ lựa chọn trong localStorage.
"use strict";
(function () {
  let t = null;
  try { t = localStorage.getItem("theme"); } catch (e) { /* bị chặn → dùng mặc định */ }
  document.documentElement.dataset.theme = t === "light" ? "light" : "dark";
})();
