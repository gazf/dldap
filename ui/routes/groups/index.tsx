import { define } from "../../utils.ts";
import { Navbar } from "../../components/Navbar.tsx";
import GroupList from "../../islands/GroupList.tsx";

export default define.page(function GroupsPage() {
  return (
    <Navbar current="/groups">
      <h1 class="page-title">Groups</h1>
      <GroupList />
    </Navbar>
  );
});
