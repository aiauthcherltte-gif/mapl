// Minimal used surface of the platform, keeping direct dependencies at the approved five.
export interface Cursor<T = Record<string, unknown>> extends Iterable<T> {
    toArray(): T[];
    rowsWritten: number;
    rowsRead: number;
}
export interface Sql {
    exec<T = Record<string, unknown>>(query: string, ...bindings: (string | number | null)[]): Cursor<T>;
}
export interface Storage {
    sql: Sql;
    transactionSync<T>(callback: () => T): T;
}
export interface DOState {
    storage: Storage;
}
export interface Namespace {
    idFromName(name: string): unknown;
    get(id: unknown): {
        fetch(request: Request): Promise<Response>;
    };
}
export interface Env {
    APPROVAL: Namespace;
    MODE: string;
    ORIGIN: string;
    RP_ID: string;
    TEST_ROOT_ID: string;
    SETUP_CODE?: string;
    REQUESTER_TOKEN?: string;
    RUNNER_TOKEN?: string;
    RECOVERY_EPOCH?: string;
    SUBDOMAIN?: string;
    RUNNER_TOKEN_SHA256?: string;
    REQUESTER_TOKEN_SHA256?: string;
    BUILD_COMMIT?: string;
}
