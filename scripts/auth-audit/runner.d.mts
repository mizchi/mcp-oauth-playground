import type { AuditConfig, AuditReport, CheckId } from "./contracts.js";

export declare const CHECK_IDS: CheckId[];
export declare function auditServer(config: AuditConfig): Promise<AuditReport>;
