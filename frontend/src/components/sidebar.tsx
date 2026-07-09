"use client"

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import {
  Home,
  FolderSearch,
  Network,
  GitBranch,
  FolderOpen,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Shield,
} from "lucide-react";

const navItems = [
  { href: "/", label: "Command Center", icon: Home },
  { href: "/investigations", label: "Investigations", icon: FolderSearch },
  { href: "/attack-graph", label: "Attack Graph", icon: Network },
  { href: "/architecture", label: "Agent Workflow", icon: GitBranch },
  { href: "/evidence", label: "Evidence", icon: FolderOpen },
  { href: "/reports", label: "Reports", icon: FileText },
];

const bottomItems = [
  { href: "/settings", label: "Settings", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  const isActive = (href: string) => {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  };

  return (
    <div
      className={`${
        collapsed ? "w-[72px]" : "w-[240px]"
      } bg-white flex flex-col h-screen transition-all duration-200 ease-in-out shrink-0 relative`}
      style={{ boxShadow: "1px 0 0 var(--border-default), 4px 0 12px rgba(16,24,40,0.03)" }}
    >
      {/* Brand */}
      <div className={`flex items-center gap-3 px-5 pt-6 pb-8 ${collapsed ? "justify-center" : ""}`}>
        <div className="w-9 h-9 rounded-xl bg-[var(--accent-color)] flex items-center justify-center shrink-0">
          <Shield className="w-5 h-5 text-white" />
        </div>
        {!collapsed && (
          <div className="overflow-hidden">
            <h1 className="text-lg font-bold tracking-tight text-[var(--text-primary)] leading-tight">
              YAROX
            </h1>
            <p className="text-[10px] text-[var(--text-secondary)] font-medium leading-tight">
              AI Security Command Center
            </p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="px-3 space-y-1">
        {navItems.map((item) => {
          const active = isActive(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.label : undefined}
              className={`flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-xl transition-all duration-150 relative group ${
                active
                  ? "bg-[var(--accent-light)] text-[var(--accent-color)]"
                  : "text-[var(--text-secondary)] hover:bg-[var(--muted)] hover:text-[var(--text-primary)]"
              } ${collapsed ? "justify-center" : ""}`}
            >
              {/* Active indicator bar */}
              {active && (
                <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 rounded-r-full bg-[var(--accent-color)]" />
              )}
              <item.icon className={`w-[18px] h-[18px] shrink-0 ${active ? "text-[var(--accent-color)]" : ""}`} />
              {!collapsed && <span>{item.label}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Bottom items */}
      <div className="mt-auto px-3 pb-4 space-y-1 border-t border-[var(--border-default)] pt-3">
        {bottomItems.map((item) => {
          const active = isActive(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.label : undefined}
              className={`flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-xl transition-all duration-150 ${
                active
                  ? "bg-[var(--accent-light)] text-[var(--accent-color)]"
                  : "text-[var(--text-secondary)] hover:bg-[var(--muted)] hover:text-[var(--text-primary)]"
              } ${collapsed ? "justify-center" : ""}`}
            >
              <item.icon className="w-[18px] h-[18px] shrink-0" />
              {!collapsed && <span>{item.label}</span>}
            </Link>
          );
        })}

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className={`flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-xl transition-all duration-150 w-full text-[var(--text-secondary)] hover:bg-[var(--muted)] hover:text-[var(--text-primary)] ${
            collapsed ? "justify-center" : ""
          }`}
        >
          {collapsed ? (
            <ChevronRight className="w-[18px] h-[18px] shrink-0" />
          ) : (
            <>
              <ChevronLeft className="w-[18px] h-[18px] shrink-0" />
              <span>Collapse</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}
