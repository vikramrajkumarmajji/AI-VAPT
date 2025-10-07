// [build] library: 'shadcn'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "../components/ui/sheet";

const meta = {
  title: "ui/Sheet",
  component: Sheet,
  tags: ["autodocs"],
  argTypes: {},
};
export default meta;

export const Default = {
  render: (args: any) => {
    return (
      <Sheet>
        <SheetTrigger>Open Right</SheetTrigger>
        <SheetContent side={args.side}>
          <SheetHeader>
            <SheetTitle>Are you sure absolutely sure?</SheetTitle>
            <SheetDescription>
              This action cannot be undone. This will permanently delete your
              account and remove your data from our servers.
            </SheetDescription>
          </SheetHeader>
        </SheetContent>
      </Sheet>
    );
  },
  args: {
    side: "right",
  },
};

export const Left = {
  render: (args: any) => {
    return (
      <Sheet>
        <SheetTrigger>Open Left</SheetTrigger>
        <SheetContent side={args.side}>
          <SheetHeader>
            <SheetTitle>Are you sure absolutely sure?</SheetTitle>
            <SheetDescription>
              This action cannot be undone. This will permanently delete your
              account and remove your data from our servers.
            </SheetDescription>
          </SheetHeader>
        </SheetContent>
      </Sheet>
    );
  },
  args: {
    side: "left",
  },
};

export const Top = {
  render: (args: any) => {
    return (
      <Sheet>
        <SheetTrigger>Open Top</SheetTrigger>
        <SheetContent side={args.side}>
          <SheetHeader>
            <SheetTitle>Are you sure absolutely sure?</SheetTitle>
            <SheetDescription>
              This action cannot be undone. This will permanently delete your
              account and remove your data from our servers.
            </SheetDescription>
          </SheetHeader>
        </SheetContent>
      </Sheet>
    );
  },
  args: {
    side: "top",
  },
};

export const Bottom = {
  render: (args: any) => {
    return (
      <Sheet>
        <SheetTrigger>Open Bottom</SheetTrigger>
        <SheetContent side={args.side}>
          <SheetHeader>
            <SheetTitle>Are you sure absolutely sure?</SheetTitle>
            <SheetDescription>
              This action cannot be undone. This will permanently delete your
              account and remove your data from our servers.
            </SheetDescription>
          </SheetHeader>
        </SheetContent>
      </Sheet>
    );
  },
  args: {
    side: "bottom",
  },
};
