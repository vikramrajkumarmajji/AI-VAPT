import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap rounded-lg text-sm font-medium transition-all duration-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 transform hover:scale-[1.02] active:scale-[0.98] backdrop-blur-sm",
  {
    variants: {
      variant: {
        default:
          "bg-primary/90 text-primary-foreground shadow-lg hover:bg-primary hover:shadow-xl border border-primary/20",
        destructive:
          "bg-destructive/90 text-destructive-foreground shadow-lg hover:bg-destructive hover:shadow-xl border border-destructive/20",
        outline:
          "border border-border/50 bg-background/50 backdrop-blur-sm shadow-sm hover:bg-accent/50 hover:text-accent-foreground hover:border-border",
        secondary:
          "bg-secondary/90 text-secondary-foreground shadow-sm hover:bg-secondary border border-secondary/20",
        ghost:
          "hover:bg-accent/50 hover:text-accent-foreground backdrop-blur-sm",
        link: "text-primary underline-offset-4 hover:underline",
        scanner:
          "bg-gradient-to-r from-emerald-500/90 to-cyan-500/90 text-white font-semibold shadow-xl hover:from-emerald-500 hover:to-cyan-500 hover:shadow-2xl border border-emerald-400/20",
        critical:
          "bg-gradient-to-r from-red-500/90 to-pink-500/90 text-white font-bold shadow-xl hover:from-red-500 hover:to-pink-500 hover:shadow-2xl border border-red-400/20",
        success:
          "bg-gradient-to-r from-green-500/90 to-emerald-500/90 text-white font-semibold shadow-xl hover:from-green-500 hover:to-emerald-500 hover:shadow-2xl border border-green-400/20",
      },
      size: {
        default: "h-10 px-4 py-2",
        sm: "h-8 rounded-md px-3 text-xs",
        lg: "h-12 rounded-lg px-8 text-base font-semibold",
        icon: "h-10 w-10",
        xl: "h-14 rounded-xl px-10 text-lg font-bold",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  },
);
Button.displayName = "Button";

export { Button, buttonVariants };
