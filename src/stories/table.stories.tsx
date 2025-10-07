// [build] library: 'shadcn'
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../components/ui/table";

const meta = {
  title: "ui/Table",
  component: Table,
  tags: ["autodocs"],
  argTypes: {},
};
export default meta;

export const Default = {
  render: () => {
    return (
      <Table>
        <TableCaption>A list of your recent invoices.</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Invoice</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Method</TableHead>
            <TableHead className="text-right">Amount</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow key={"INV001"}>
            <TableCell className="font-medium">{"INV001"}</TableCell>
            <TableCell>{"Paid"}</TableCell>
            <TableCell>{"Credit Card"}</TableCell>
            <TableCell className="text-right">{"$250.00"}</TableCell>
          </TableRow>
          <TableRow key={"INV002"}>
            <TableCell className="font-medium">{"INV002"}</TableCell>
            <TableCell>{"Pending"}</TableCell>
            <TableCell>{"PayPal"}</TableCell>
            <TableCell className="text-right">{"$150.00"}</TableCell>
          </TableRow>
          <TableRow key={"INV003"}>
            <TableCell className="font-medium">{"INV003"}</TableCell>
            <TableCell>{"Unpaid"}</TableCell>
            <TableCell>{"Bank Transfer"}</TableCell>
            <TableCell className="text-right">{"$450.00"}</TableCell>
          </TableRow>
          <TableRow key={"INV004"}>
            <TableCell className="font-medium">{"INV004"}</TableCell>
            <TableCell>{"Pending"}</TableCell>
            <TableCell>{"Stripe"}</TableCell>
            <TableCell className="text-right">{"$250.00"}</TableCell>
          </TableRow>
          <TableRow key={"INV005"}>
            <TableCell className="font-medium">{"INV005"}</TableCell>
            <TableCell>{"Paid"}</TableCell>
            <TableCell>{"Credit Card"}</TableCell>
            <TableCell className="text-right">{"$50.00"}</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    );
  },
  args: {},
};
