import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  KeyRound,
  Lock,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldCheck,
  UserCheck,
  UserX,
  Users,
} from "lucide-react";
import { apiErrorMessage, usersApi } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { useModuleAudit } from "../hooks/useModuleAudit";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  Input,
  LoadingBlock,
  Modal,
  PageHeader,
  Pagination,
  Select,
} from "../components/ui";
import type { Role, User } from "../types";
import { ROLE_LABEL, initials, timeAgo } from "../lib/utils";

type Tab = "users" | "roles";

const emptyForm = {
  full_name: "",
  email: "",
  password: "",
  role_id: "",
  job_title: "",
  department: "",
  phone: "",
  is_active: true,
};

export function UsersPage() {
  useModuleAudit("users");
  const { hasPermission, user: me } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("users");
  const [search, setSearch] = useState("");
  const [activeFilter, setActiveFilter] = useState("");
  const [page, setPage] = useState(1);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [saving, setSaving] = useState(false);
  const [resetUser, setResetUser] = useState<User | null>(null);
  const [newPassword, setNewPassword] = useState("");

  const { data: roles } = useQuery({ queryKey: ["roles"], queryFn: usersApi.roles });
  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ["users", page, search, activeFilter],
    queryFn: () =>
      usersApi.list({
        page,
        page_size: 12,
        q: search || undefined,
        active: activeFilter || undefined,
      }),
  });

  const canManage = hasPermission("users:manage");

  useEffect(() => {
    if (roles?.length && !form.role_id) {
      setForm((current) => ({ ...current, role_id: roles.find((role) => role.name === "analyst")?.id || roles[0].id }));
    }
  }, [roles, form.role_id]);

  const openCreate = () => {
    setEditing(null);
    setForm({
      ...emptyForm,
      role_id: roles?.find((role) => role.name === "analyst")?.id || roles?.[0]?.id || "",
    });
    setModalOpen(true);
  };

  const openEdit = (user: User) => {
    setEditing(user);
    setForm({
      full_name: user.full_name,
      email: user.email,
      password: "",
      role_id: user.role.id,
      job_title: user.job_title,
      department: user.department,
      phone: user.phone,
      is_active: user.is_active,
    });
    setModalOpen(true);
  };

  const save = async () => {
    if (!form.full_name.trim() || !form.email.trim()) {
      toast("Nombre y correo son obligatorios", "error");
      return;
    }
    if (!editing && form.password.length < 10) {
      toast("La contraseña debe tener al menos 10 caracteres", "error");
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await usersApi.update(editing.id, {
          full_name: form.full_name,
          role_id: form.role_id,
          job_title: form.job_title,
          department: form.department,
          phone: form.phone,
          is_active: form.is_active,
        });
        toast("Usuario actualizado", "success");
      } else {
        await usersApi.create({
          full_name: form.full_name,
          email: form.email,
          password: form.password,
          role_id: form.role_id,
          job_title: form.job_title,
          department: form.department,
          phone: form.phone,
        });
        toast("Usuario creado. Ya puede iniciar sesión.", "success");
      }
      setModalOpen(false);
      await queryClient.invalidateQueries({ queryKey: ["users"] });
    } catch (err) {
      toast(apiErrorMessage(err), "error");
    } finally {
      setSaving(false);
    }
  };

  const toggleActive = async (user: User) => {
    if (user.id === me?.id) {
      toast("No puede desactivar su propia cuenta", "error");
      return;
    }
    try {
      await usersApi.update(user.id, { is_active: !user.is_active });
      toast(user.is_active ? "Usuario desactivado" : "Usuario activado", "success");
      await queryClient.invalidateQueries({ queryKey: ["users"] });
    } catch (err) {
      toast(apiErrorMessage(err), "error");
    }
  };

  const resetPassword = async () => {
    if (!resetUser) return;
    if (newPassword.length < 10) {
      toast("La contraseña debe tener al menos 10 caracteres", "error");
      return;
    }
    setSaving(true);
    try {
      await usersApi.resetPassword(resetUser.id, newPassword);
      toast(`Contraseña restablecida para ${resetUser.full_name}`, "success");
      setResetUser(null);
      setNewPassword("");
    } catch (err) {
      toast(apiErrorMessage(err), "error");
    } finally {
      setSaving(false);
    }
  };

  const groupedPermissions = useMemo(() => {
    const map = new Map<string, string[]>();
    roles?.forEach((role) => {
      role.permissions.forEach((permission) => {
        const list = map.get(permission.module) || [];
        if (!list.includes(permission.code)) list.push(permission.code);
        map.set(permission.module, list);
      });
    });
    return Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [roles]);

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Administración"
        title="Usuarios y roles"
        subtitle="Control de acceso basado en roles (RBAC), perfiles operativos y segregación de funciones."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => void refetch()} loading={isFetching}>
              <RefreshCw size={14} /> Actualizar
            </Button>
            {canManage && tab === "users" ? (
              <Button size="sm" onClick={openCreate}>
                <Plus size={15} /> Nuevo usuario
              </Button>
            ) : null}
          </>
        }
      />

      <div className="mb-5 flex items-center gap-1 rounded-xl border border-white/[0.07] bg-white/[0.02] p-1">
        <button
          type="button"
          onClick={() => setTab("users")}
          className={`flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition ${
            tab === "users" ? "bg-cyan-400/12 text-cyan-200" : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Users size={14} /> Usuarios
          <span className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[10px] text-slate-400">{data?.total ?? 0}</span>
        </button>
        <button
          type="button"
          onClick={() => setTab("roles")}
          className={`flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition ${
            tab === "roles" ? "bg-cyan-400/12 text-cyan-200" : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Shield size={14} /> Roles y permisos
          <span className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[10px] text-slate-400">{roles?.length ?? 0}</span>
        </button>
      </div>

      {tab === "users" ? (
        <>
          <Card className="mb-5 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative min-w-[220px] flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={15} />
                <input
                  value={search}
                  onChange={(event) => {
                    setSearch(event.target.value);
                    setPage(1);
                  }}
                  placeholder="Buscar por nombre, correo o área…"
                  className="h-10 w-full rounded-lg border border-white/10 bg-slate-950/60 pl-9 pr-3 text-sm text-white placeholder:text-slate-500 focus:border-cyan-400/50 focus:outline-none focus:ring-2 focus:ring-cyan-400/10"
                />
              </div>
              <Select
                value={activeFilter}
                onChange={(event) => {
                  setActiveFilter(event.target.value);
                  setPage(1);
                }}
                className="w-40"
                aria-label="Estado"
              >
                <option value="">Todos</option>
                <option value="true">Activos</option>
                <option value="false">Inactivos</option>
              </Select>
            </div>
          </Card>

          <div className="table-shell">
            {isLoading ? <LoadingBlock label="Cargando usuarios…" /> : null}
            {error ? <ErrorState message={apiErrorMessage(error)} onRetry={() => void refetch()} /> : null}
            {!isLoading && !error && data ? (
              data.items.length ? (
                <>
                  <div className="overflow-x-auto">
                    <table className="table-base">
                      <thead>
                        <tr>
                          <th>Usuario</th>
                          <th>Rol</th>
                          <th className="hidden md:table-cell">Área / cargo</th>
                          <th>Estado</th>
                          <th className="hidden lg:table-cell">Último acceso</th>
                          <th className="text-right">Acciones</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.items.map((user) => (
                          <tr key={user.id}>
                            <td>
                              <div className="flex items-center gap-3">
                                <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-400/25 to-violet-400/20 text-[11px] font-bold text-cyan-100">
                                  {initials(user.full_name)}
                                </span>
                                <div>
                                  <p className="text-[13px] font-medium text-slate-100">
                                    {user.full_name}
                                    {user.id === me?.id ? (
                                      <span className="ml-2 text-[9px] font-semibold uppercase tracking-wider text-cyan-400">tú</span>
                                    ) : null}
                                  </p>
                                  <p className="text-[10px] text-slate-500">{user.email}</p>
                                </div>
                              </div>
                            </td>
                            <td>
                              <Badge
                                tone={
                                  user.role.name === "admin"
                                    ? "violet"
                                    : user.role.name === "supervisor"
                                      ? "cyan"
                                      : user.role.name === "auditor"
                                        ? "warn"
                                        : "neutral"
                                }
                              >
                                {ROLE_LABEL[user.role.name] || user.role.name}
                              </Badge>
                            </td>
                            <td className="hidden md:table-cell">
                              <p className="text-xs text-slate-300">{user.department || "—"}</p>
                              <p className="text-[10px] text-slate-500">{user.job_title || "—"}</p>
                            </td>
                            <td>
                              <Badge tone={user.is_active ? "ok" : "neutral"} dot>
                                {user.is_active ? "Activo" : "Inactivo"}
                              </Badge>
                            </td>
                            <td className="hidden text-[11px] text-slate-500 lg:table-cell">
                              {user.last_login_at ? timeAgo(user.last_login_at) : "Nunca"}
                            </td>
                            <td>
                              <div className="flex items-center justify-end gap-1">
                                {canManage ? (
                                  <>
                                    <Button variant="ghost" size="icon" onClick={() => openEdit(user)} aria-label="Editar">
                                      <Pencil size={14} />
                                    </Button>
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      onClick={() => {
                                        setResetUser(user);
                                        setNewPassword("");
                                      }}
                                      aria-label="Restablecer contraseña"
                                    >
                                      <KeyRound size={14} />
                                    </Button>
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      onClick={() => void toggleActive(user)}
                                      aria-label={user.is_active ? "Desactivar" : "Activar"}
                                      disabled={user.id === me?.id}
                                    >
                                      {user.is_active ? <UserX size={14} /> : <UserCheck size={14} />}
                                    </Button>
                                  </>
                                ) : (
                                  <span className="text-[10px] text-slate-600">Solo lectura</span>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <Pagination
                    page={data.page}
                    pages={data.pages}
                    total={data.total}
                    pageSize={data.page_size}
                    onChange={setPage}
                  />
                </>
              ) : (
                <EmptyState icon={<Users size={20} />} title="Sin usuarios" description="Cree el primer usuario del equipo SOC." />
              )
            ) : null}
          </div>
        </>
      ) : (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
          {roles?.map((role) => (
            <RoleCard key={role.id} role={role} />
          ))}
          <Card className="lg:col-span-2">
            <CardHeader
              title="Matriz de permisos por módulo"
              subtitle="Los roles se asignan a usuarios; el rol admin conserva acceso total."
            />
            <div className="overflow-x-auto p-4">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-[10px] uppercase tracking-[0.1em] text-slate-500">
                    <th className="px-3 py-2">Módulo</th>
                    {roles?.map((role) => (
                      <th key={role.id} className="px-3 py-2 text-center">
                        {ROLE_LABEL[role.name] || role.name}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {groupedPermissions.map(([module, permissions]) => (
                    <tr key={module} className="border-t border-white/[0.04]">
                      <td className="px-3 py-2.5 font-medium capitalize text-slate-300">{module}</td>
                      {roles?.map((role) => {
                        const owned = permissions.filter((code) =>
                          role.permissions.some((permission) => permission.code === code),
                        ).length;
                        return (
                          <td key={role.id} className="px-3 py-2.5 text-center">
                            {owned === permissions.length ? (
                              <Check size={14} className="mx-auto text-emerald-400" />
                            ) : owned > 0 ? (
                              <span className="text-[10px] text-amber-300">{owned}/{permissions.length}</span>
                            ) : (
                              <span className="text-slate-700">—</span>
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editing ? "Editar usuario" : "Nuevo usuario"}
        description={editing ? "Actualice datos, rol o estado de la cuenta." : "La cuenta se crea activa y con el rol seleccionado."}
        width="max-w-xl"
        footer={
          <>
            <Button variant="ghost" onClick={() => setModalOpen(false)}>
              Cancelar
            </Button>
            <Button onClick={() => void save()} loading={saving}>
              {editing ? "Guardar cambios" : "Crear usuario"}
            </Button>
          </>
        }
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <Input
              label="Nombre completo *"
              value={form.full_name}
              onChange={(event) => setForm({ ...form, full_name: event.target.value })}
              placeholder="Camila Torres"
            />
          </div>
          <div className="sm:col-span-2">
            <Input
              label="Correo electrónico *"
              type="email"
              value={form.email}
              onChange={(event) => setForm({ ...form, email: event.target.value })}
              disabled={Boolean(editing)}
              placeholder="analista@soclite.local"
            />
          </div>
          {!editing ? (
            <div className="sm:col-span-2">
              <Input
                label="Contraseña inicial *"
                type="password"
                value={form.password}
                onChange={(event) => setForm({ ...form, password: event.target.value })}
                hint="Mínimo 10 caracteres, con mayúscula, minúscula y número."
              />
            </div>
          ) : null}
          <Select
            label="Rol *"
            value={form.role_id}
            onChange={(event) => setForm({ ...form, role_id: event.target.value })}
          >
            {roles?.map((role) => (
              <option key={role.id} value={role.id}>
                {ROLE_LABEL[role.name] || role.name}
              </option>
            ))}
          </Select>
          <Input
            label="Cargo"
            value={form.job_title}
            onChange={(event) => setForm({ ...form, job_title: event.target.value })}
            placeholder="Analista SOC L2"
          />
          <Input
            label="Área / departamento"
            value={form.department}
            onChange={(event) => setForm({ ...form, department: event.target.value })}
            placeholder="SOC"
          />
          <Input
            label="Teléfono"
            value={form.phone}
            onChange={(event) => setForm({ ...form, phone: event.target.value })}
            placeholder="+51 999 000 000"
          />
          {editing ? (
            <label className="flex items-center gap-2 text-xs text-slate-300 sm:col-span-2">
              <input
                type="checkbox"
                checked={form.is_active}
                onChange={(event) => setForm({ ...form, is_active: event.target.checked })}
                className="h-4 w-4 rounded border-white/20 bg-slate-950 accent-cyan-400"
              />
              Cuenta activa
            </label>
          ) : null}
        </div>
      </Modal>

      <Modal
        open={Boolean(resetUser)}
        onClose={() => setResetUser(null)}
        title="Restablecer contraseña"
        description={resetUser ? `${resetUser.full_name} · ${resetUser.email}` : ""}
        footer={
          <>
            <Button variant="ghost" onClick={() => setResetUser(null)}>
              Cancelar
            </Button>
            <Button onClick={() => void resetPassword()} loading={saving}>
              <Lock size={14} /> Restablecer
            </Button>
          </>
        }
      >
        <Input
          label="Nueva contraseña"
          type="password"
          value={newPassword}
          onChange={(event) => setNewPassword(event.target.value)}
          hint="Se revocarán las sesiones activas del usuario. Mínimo 10 caracteres."
        />
      </Modal>
    </div>
  );
}

function RoleCard({ role }: { role: Role }) {
  const tone =
    role.name === "admin"
      ? "violet"
      : role.name === "supervisor"
        ? "cyan"
        : role.name === "auditor"
          ? "warn"
          : role.name === "analyst"
            ? "ok"
            : "neutral";
  const modules = Array.from(new Set(role.permissions.map((permission) => permission.module)));
  return (
    <Card className="p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="rounded-xl border border-white/10 bg-white/[0.04] p-2.5">
            <ShieldCheck className="text-cyan-300" size={18} />
          </div>
          <div>
            <p className="text-sm font-semibold text-white">{ROLE_LABEL[role.name] || role.name}</p>
            <p className="mt-0.5 text-[11px] text-slate-400">{role.description}</p>
          </div>
        </div>
        <Badge tone={tone as "violet" | "cyan" | "warn" | "ok" | "neutral"}>{role.permissions.length} permisos</Badge>
      </div>
      <div className="mt-4 flex flex-wrap gap-1.5">
        {modules.map((module) => (
          <Badge key={module} tone="neutral" className="text-[9px]">
            {module}
          </Badge>
        ))}
      </div>
      <p className="mt-4 border-t border-white/[0.05] pt-3 text-[10px] text-slate-600">
        {role.is_system ? "Rol de sistema · Protegido" : "Rol personalizado"}
      </p>
    </Card>
  );
}
