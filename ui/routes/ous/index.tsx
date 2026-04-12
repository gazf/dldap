import { define } from "../../utils.ts";
import { Navbar } from "../../components/Navbar.tsx";
import OuList from "../../islands/OuList.tsx";

export default define.page(function OUsPage() {
  return (
    <Navbar current="/ous">
      <h1 class="page-title">Organizational Units</h1>
      <OuList />
    </Navbar>
  );
});
