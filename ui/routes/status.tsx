import { define } from "../utils.ts";
import { Navbar } from "../components/Navbar.tsx";
import StatusPanel from "../islands/StatusPanel.tsx";

export default define.page(function StatusPage() {
  return (
    <Navbar current="/status">
      <h1 class="page-title">Server Status</h1>
      <StatusPanel />
    </Navbar>
  );
});
