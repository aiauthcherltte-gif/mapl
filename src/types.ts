// JSON is validated at the protocol boundary; these objects mirror the Python contract.
export type Dict = {
    [key: string]: any;
};
export interface MaplRequest extends Dict {
    request_id: string;
    revision: number;
    created_at: string;
    expires_at: string;
    window_utc: [
        string,
        string
    ];
    target: Dict;
    kit: Dict;
    bundle: Dict;
    not_covered: string[];
    recovery: Dict;
}
export class Refusal extends Error {
    constructor(public code: string, public status = 409, public rule?: string) { super(code); }
}
export function need(condition: unknown, code: string, status = 400, rule?: string): asserts condition {
    if (!condition)
        throw new Refusal(code, status, rule);
}
export const clone = <T>(v: T): T => structuredClone(v);
