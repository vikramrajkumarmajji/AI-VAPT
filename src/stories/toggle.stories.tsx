// [build] library: 'shadcn'
import { FontItalicIcon, FontBoldIcon } from "@radix-ui/react-icons";
import { Toggle } from "../components/ui/toggle";

const meta = {
  title: "ui/Toggle",
  component: Toggle,
  tags: ["autodocs"],
  argTypes: {},
};
export default meta;

export const Default = {
  render: () => (
    <Toggle aria-label="Toggle bold">
      <FontBoldIcon className="h-4 w-4" />
    </Toggle>
  ),
  args: {},
};

export const Outline = {
  render: () => (
    <Toggle aria-label="Toggle italic" variant="outline">
      <FontItalicIcon className="h-4 w-4" />
    </Toggle>
  ),
  args: {},
};

export const WithText = {
  render: () => (
    <Toggle aria-label="Toggle italic">
      <FontItalicIcon className="h-4 w-4" />
      Italic
    </Toggle>
  ),
  args: {},
};

export const Small = {
  render: () => (
    <Toggle size="sm" aria-label="Toggle bold">
      <FontBoldIcon className="h-4 w-4" />
    </Toggle>
  ),
  args: {},
};

export const Large = {
  render: () => (
    <Toggle size="lg" aria-label="Toggle bold">
      <FontBoldIcon className="h-4 w-4" />
    </Toggle>
  ),
  args: {},
};

export const Destructive = {
  render: () => (
    <Toggle aria-label="Toggle bold" disabled>
      <FontBoldIcon className="h-4 w-4" />
    </Toggle>
  ),
  args: {
    variant: "destructive",
  },
};
