import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { authApi, clearSession, getAccessToken, getRefreshToken, setSession } from "../lib/api";
import type { User } from "../types";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<User>;
  logout: () => Promise<void>;
  hasPermission: (code: string) => boolean;
  hasAnyPermission: (...codes: string[]) => boolean;
  isAdmin: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    async function restore() {
      if (!getAccessToken()) {
        setLoading(false);
        return;
      }
      try {
        const profile = await authApi.me();
        if (alive) setUser(profile);
      } catch {
        clearSession();
      } finally {
        if (alive) setLoading(false);
      }
    }
    void restore();
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    const handleLogout = () => {
      clearSession();
      setUser(null);
    };
    window.addEventListener("soc:logout", handleLogout);
    return () => window.removeEventListener("soc:logout", handleLogout);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const response = await authApi.login(email, password);
    setSession(response);
    setUser(response.user);
    return response.user;
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout(getRefreshToken());
    } catch {
      // La sesión local se cierra incluso si el servidor no responde.
    } finally {
      clearSession();
      setUser(null);
    }
  }, []);

  const hasPermission = useCallback(
    (code: string) => {
      if (!user) return false;
      if (user.role.name === "admin") return true;
      return user.role.permissions.some((permission) => permission.code === code);
    },
    [user],
  );

  const hasAnyPermission = useCallback(
    (...codes: string[]) => codes.some((code) => hasPermission(code)),
    [hasPermission],
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading,
      login,
      logout,
      hasPermission,
      hasAnyPermission,
      isAdmin: user?.role.name === "admin",
    }),
    [user, loading, login, logout, hasPermission, hasAnyPermission],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth debe usarse dentro de AuthProvider");
  return context;
}
