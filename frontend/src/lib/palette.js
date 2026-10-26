/**
 * 语义色单一真相（Single Source of Truth）
 *
 * 为什么需要这个文件：
 *   改造前实测同一个"低危"在三个地方是三种颜色 —— KPI 卡蓝色洗色、
 *   环形图图例 #2f6fed（蓝）、表格 chip #067647（绿）。评审无法建立
 *   "颜色 → 严重度"的直觉，颜色就等于失效了。
 *
 * 纪律：
 *   1. 本文件的取值必须与 src/styles/redesign/tokens.css 的语义令牌一致；
 *   2. 视图里禁止再出现颜色字面量，一律从这里取；
 *   3. 装饰性用色不要加进来 —— 这个文件只放"有含义"的颜色。
 */

/** 严重度色阶：五级，从最危险到通过 */
export const SEVERITY = Object.freeze({
  critical: "#b3261e", // 严重
  high: "#a84a09", // 高危
  medium: "#8a6200", // 中危
  low: "#1a6b45", // 低危 / 通过
  pending: "#1c5a86", // 待处理 / 信息
  none: "#8d877e" // 无数据
});

/** 严重度软底（与 tokens.css 的 *-soft 对应） */
export const SEVERITY_SOFT = Object.freeze({
  critical: "#fdeceb",
  high: "#fdf1e6",
  medium: "#fbf5e2",
  low: "#e9f4ee",
  pending: "#eaf1f7",
  none: "#f2f1ed"
});

/** 设备生态：名称固定的四种，不随页面变化 */
export const ECOSYSTEM = Object.freeze({
  openwrt: { color: "#c95012", soft: "#fbf0e9" },
  zephyr: { color: "#1a6b45", soft: "#e9f4ee" },
  ubuntu: { color: "#0f6b78", soft: "#e4f1f3" },
  other: { color: "#6b665f", soft: "#f2f1ed" }
});

/** 分类系列（运行时事件类型等）：一支主导色 + 中性阶梯，不做彩虹 */
export const SERIES = Object.freeze([
  "#0f6b78",
  "#c95012",
  "#4d4843",
  "#8a6200",
  "#1a6b45",
  "#8d877e"
]);

/** 严重度中文标签 → 色值，便于直接按数据里的等级取色 */
export const SEVERITY_BY_LABEL = Object.freeze({
  严重: SEVERITY.critical,
  Critical: SEVERITY.critical,
  高危: SEVERITY.high,
  High: SEVERITY.high,
  中危: SEVERITY.medium,
  Medium: SEVERITY.medium,
  低危: SEVERITY.low,
  Low: SEVERITY.low,
  待审: SEVERITY.pending,
  待处理: SEVERITY.pending
});
