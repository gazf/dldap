import type { ComponentChildren } from "preact";

interface NavbarProps {
  current: string;
  children: ComponentChildren;
}

const NAV_ITEMS = [
  { href: "/status", label: "Status" },
  { href: "/users", label: "Users" },
  { href: "/groups", label: "Groups" },
  { href: "/ous", label: "OUs" },
];

export function Navbar(props: NavbarProps) {
  return (
    <div class="layout">
      <nav class="sidebar">
        <div class="sidebar-title">dldaps</div>
        {NAV_ITEMS.map((item) => (
          <a
            key={item.href}
            href={item.href}
            class={props.current === item.href ? "active" : ""}
          >
            {item.label}
          </a>
        ))}
        <a href="/logout" style="margin-top: auto; color: #888">Logout</a>
      </nav>
      <main class="main-content">
        {props.children}
      </main>
    </div>
  );
}
