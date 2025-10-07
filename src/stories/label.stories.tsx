// [build] library: 'shadcn'
import { Label } from "../components/ui/label";

const meta = {
  title: "ui/Label",
  component: Label,
  tags: ["autodocs"],
  argTypes: {},
};
export default meta;

export const Base = {
  render: () => <Label htmlFor="email">Your email address</Label>,
  args: {},
};
