import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 backdrop-blur-sm shadow-sm",
  {
    variants: {
      variant: {
        default:
          "border-primary/20 bg-primary/90 text-primary-foreground shadow-md hover:bg-primary hover:shadow-lg",
        secondary:
          "border-secondary/20 bg-secondary/90 text-secondary-foreground hover:bg-secondary shadow-md",
        destructive:
          "border-destructive/20 bg-destructive/90 text-destructive-foreground shadow-md hover:bg-destructive hover:shadow-lg",
        outline:
          "text-foreground border-border/50 bg-background/50 hover:bg-accent/50 shadow-sm",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
