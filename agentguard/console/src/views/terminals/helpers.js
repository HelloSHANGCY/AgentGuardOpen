import { CONTROL_ITEMS } from "../../store/devices";

// 服务端时间为带时区的 ISO 串：按本地时区显示到分钟。
export const short = (ts) => {
  const date = new Date(ts);
  return Number.isNaN(date.getTime()) ? ts : date.toLocaleString("zh-CN", {
    month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
};

export const itemOf = (key) => CONTROL_ITEMS.find((item) => item.key === key);
