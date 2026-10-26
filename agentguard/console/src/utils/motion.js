// CSS 构建会将 400ms 压缩为 .4s；Web Animations 接口统一接收毫秒。
export function motionMilliseconds(value, fallback = 400) {
  const match = String(value).trim().match(/^(\d*\.?\d+)(ms|s)$/);
  if (!match) return fallback;
  return Number(match[1]) * (match[2] === 's' ? 1000 : 1);
}
