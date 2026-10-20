import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import type {
  Alert,
  AlertDetail,
  AlertPage,
  AuditLog,
  AuditPage,
  AuditStats,
  Catalog,
  DashboardOverview,
  DemoAccount,
  Incident,
  IncidentPage,
  Report,
  ReportFormat,
  ReportPage,
  ReportType,
  Role,
  TokenResponse,
  User,
  UserBrief,
  UserPage,
} from "../types";

const API_BASE = import.meta.env.VITE_API_URL || "/api/v1";
const ACCESS_KEY = "soc_lite_access_token";
const REFRESH_KEY = "soc_lite_refresh_token";

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 60000,
  headers: { "Content-Type": "application/json" },
});

export function getAccessToken() {
  return localStorage.getItem(ACCESS_KEY);
}

export function getRefreshToken() {
  return localStorage.getItem(REFRESH_KEY);
}

export function setSession(tokens: { access_token: string; refresh_token: string }) {
  localStorage.setItem(ACCESS_KEY, tokens.access_token);
  localStorage.setItem(REFRESH_KEY, tokens.refresh_token);
}

export function clearSession() {
  localStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

api.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let refreshPromise: Promise<string> | null = null;

async function refreshAccessToken(): Promise<string> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) throw new Error("Sin refresh token");
  const response = await axios.post<TokenResponse>(`${API_BASE}/auth/refresh`, {
    refresh_token: refreshToken,
  });
  setSession(response.data);
  return response.data.access_token;
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config as (InternalAxiosRequestConfig & { _retry?: boolean }) | undefined;
    if (
      error.response?.status === 401 &&
      original &&
      !original._retry &&
      !original.url?.includes("/auth/")
    ) {
      original._retry = true;
      try {
        refreshPromise = refreshPromise ?? refreshAccessToken();
        const token = await refreshPromise;
        refreshPromise = null;
        original.headers.Authorization = `Bearer ${token}`;
        return api(original);
      } catch (refreshError) {
        refreshPromise = null;
        clearSession();
        window.dispatchEvent(new Event("soc:logout"));
        return Promise.reject(refreshError);
      }
    }
    return Promise.reject(error);
  },
);

export function apiErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map((item) => item.msg ?? String(item)).join(". ");
    }
    if (error.message) return error.message;
  }
  if (error instanceof Error) return error.message;
  return "Ocurrió un error inesperado";
}

type Params = Record<string, string | number | boolean | undefined | null>;

function cleanParams(params?: Params) {
  if (!params) return undefined;
  return Object.fromEntries(
    Object.entries(params).filter(([, value]) => value !== undefined && value !== null && value !== ""),
  );
}

export const authApi = {
  login: (email: string, password: string) =>
    api.post<TokenResponse>("/auth/login", { email, password }).then((res) => res.data),
  me: () => api.get<User>("/auth/me").then((res) => res.data),
  logout: (refreshToken: string | null) =>
    api.post("/auth/logout", { refresh_token: refreshToken }).then((res) => res.data),
  changePassword: (current_password: string, new_password: string) =>
    api.post("/auth/change-password", { current_password, new_password }).then((res) => res.data),
};

export const alertsApi = {
  list: (params?: Params) =>
    api.get<AlertPage>("/alerts", { params: cleanParams(params) }).then((res) => res.data),
  get: (id: string) => api.get<AlertDetail>(`/alerts/${id}`).then((res) => res.data),
  create: (payload: Record<string, unknown>) =>
    api.post<AlertDetail>("/alerts", payload).then((res) => res.data),
  update: (id: string, payload: Record<string, unknown>) =>
    api.patch<AlertDetail>(`/alerts/${id}`, payload).then((res) => res.data),
  triage: (id: string, force = false) =>
    api.post(`/alerts/${id}/triage`, { force }).then((res) => res.data),
  changeStatus: (id: string, status: string, reason = "") =>
    api.post<AlertDetail>(`/alerts/${id}/status`, { status, reason }).then((res) => res.data),
  escalate: (id: string, payload: { title?: string; description?: string }) =>
    api.post<Incident>(`/alerts/${id}/escalate`, payload).then((res) => res.data),
  timeline: (id: string) => api.get<AuditLog[]>(`/alerts/${id}/timeline`).then((res) => res.data),
};

export const incidentsApi = {
  list: (params?: Params) =>
    api.get<IncidentPage>("/incidents", { params: cleanParams(params) }).then((res) => res.data),
  get: (id: string) => api.get<Incident>(`/incidents/${id}`).then((res) => res.data),
  update: (id: string, payload: Record<string, unknown>) =>
    api.patch<Incident>(`/incidents/${id}`, payload).then((res) => res.data),
  close: (id: string) => api.post<Incident>(`/incidents/${id}/close`).then((res) => res.data),
};

export const dashboardApi = {
  overview: (days: number) =>
    api.get<DashboardOverview>("/dashboard/overview", { params: { days } }).then((res) => res.data),
};

export const reportsApi = {
  list: (params?: Params) =>
    api.get<ReportPage>("/reports", { params: cleanParams(params) }).then((res) => res.data),
  create: (payload: {
    report_type: ReportType;
    format: ReportFormat;
    days?: number;
    period_start?: string;
    period_end?: string;
  }) => api.post<Report>("/reports", payload).then((res) => res.data),
  download: async (report: Report) => {
    const response = await api.get(`/reports/${report.id}/download`, { responseType: "blob" });
    const url = URL.createObjectURL(response.data);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = report.file_name;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  },
};

export const usersApi = {
  list: (params?: Params) =>
    api.get<UserPage>("/users", { params: cleanParams(params) }).then((res) => res.data),
  create: (payload: Record<string, unknown>) =>
    api.post<User>("/users", payload).then((res) => res.data),
  update: (id: string, payload: Record<string, unknown>) =>
    api.patch<User>(`/users/${id}`, payload).then((res) => res.data),
  resetPassword: (id: string, new_password: string) =>
    api.post(`/users/${id}/reset-password`, { new_password }).then((res) => res.data),
  roles: () => api.get<Role[]>("/roles").then((res) => res.data),
  assignable: () => api.get<UserBrief[]>("/users/assignable").then((res) => res.data),
};

export const auditApi = {
  list: (params?: Params) =>
    api.get<AuditPage>("/audit", { params: cleanParams(params) }).then((res) => res.data),
  stats: (days = 7) =>
    api.get<AuditStats>("/audit/stats", { params: { days } }).then((res) => res.data),
  options: () =>
    api.get<{ modules: string[]; event_types: string[] }>("/audit/options").then((res) => res.data),
  moduleEvent: (module: string, direction: "IN" | "OUT", detail: Record<string, unknown> = {}) =>
    api.post("/audit/module-event", { module, direction, detail }).then((res) => res.data),
};

export const metaApi = {
  catalog: () => api.get<Catalog>("/meta/catalog").then((res) => res.data),
  demoAccounts: () => api.get<DemoAccount[]>("/meta/demo-accounts").then((res) => res.data),
};
