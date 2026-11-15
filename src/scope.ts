import type { Dict } from './types';
export const SCOPE = ['pointer_bytes', 'pinned_reader', 'collector', 'screen'];
export const WORDS: Dict = {pointer_bytes: '포인터', pinned_reader: '읽기', collector: '수집기', screen: '화면'};
export const orderedScope = (v: unknown): v is string[] => Array.isArray(v) && v.every(x => SCOPE.includes(x)) && JSON.stringify(v) === JSON.stringify(SCOPE.filter(x => v.includes(x)));
export const FLOW_EVENTS = ['check_ok', 'check_failed', 'check_unknown', 'recovery_start', 'recovery_done', 'recovery_failed', 'recovery_unknown'];
