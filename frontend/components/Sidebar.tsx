"use client";

import Icon from "./Icon";

export type SidebarItem = { key: string; label: string; icon: any; section?: string };

export default function Sidebar({
  items,
  active,
  onSelect,
}: {
  items: SidebarItem[];
  active: string;
  onSelect: (key: string) => void;
}) {
  let lastSection = "";
  return (
    <nav className="sidebar">
      {items.map((it) => {
        const showSection = it.section && it.section !== lastSection;
        if (it.section) lastSection = it.section;
        return (
          <div key={it.key}>
            {showSection && <div className="nav-section">{it.section}</div>}
            <div
              className={`nav-item${active === it.key ? " active" : ""}`}
              onClick={() => onSelect(it.key)}
            >
              <Icon name={it.icon} />
              {it.label}
            </div>
          </div>
        );
      })}
    </nav>
  );
}