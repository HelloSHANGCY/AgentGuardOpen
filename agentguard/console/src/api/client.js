// 统一 JSON 请求：非 2xx 抛出后端 detail，或带 HTTP 状态的兜底错误信息。
export async function requestJson(path, options = {}, fallbackMessage = "") {
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof data.detail === "string" ? data.detail : "";
    const fallback = fallbackMessage ? `${fallbackMessage}（HTTP ${response.status}）` : "HTTP " + response.status;
    const error = new Error(detail || fallback);
    error.status = response.status;
    throw error;
  }
  return data;
}

// 运行时只读接口：同样在非 2xx 时抛错，由调用方决定展示位置。
export const api = (path) => requestJson(path);
