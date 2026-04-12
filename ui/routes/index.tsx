import { define } from "../utils.ts";

export const handler = define.handlers({
  GET(ctx) {
    return ctx.redirect("/status");
  },
});

export default define.page(function IndexPage() {
  return <div />;
});
