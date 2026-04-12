import { define } from "../../utils.ts";
import { Navbar } from "../../components/Navbar.tsx";
import UserList from "../../islands/UserList.tsx";

export default define.page(function UsersPage() {
  return (
    <Navbar current="/users">
      <h1 class="page-title">Users</h1>
      <UserList />
    </Navbar>
  );
});
