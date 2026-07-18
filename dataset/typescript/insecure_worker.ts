import { execSync } from "child_process";

const secret: string = "demo-typescript-secret";

export function runTask(input: any): string {
  const command = input.command || "date";
  return execSync(command).toString();
}

