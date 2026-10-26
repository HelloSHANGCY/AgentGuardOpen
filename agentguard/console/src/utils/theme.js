// Canvas 不能直接使用 CSS 变量；读取主题中的实色，与页面图例保持一致。
export const themeColor = (token) => getComputedStyle(document.documentElement).getPropertyValue(token).trim();
