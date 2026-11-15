import { it,expect } from 'vitest';
import { world } from './support';
import { canonical } from '../src/canonical';
it('actual SQLite failure rolls back nonce, approval, credential and history together',()=>world(async w=>{
  const assertion=await w.sign(),before=canonical(w.store.entry(w.rid,1)),keyBefore=canonical(w.store.meta('credential'));
  w.store.storage.sql.exec("CREATE TRIGGER reject_test_approval BEFORE UPDATE ON requests WHEN json_extract(NEW.json, '$.state.approval') = 'approved' BEGIN SELECT RAISE(ABORT, 'local_test_write_failure'); END");
  await expect(w.store.approve(w.rid,assertion)).rejects.toThrow('local_test_write_failure');
  expect(canonical(w.store.entry(w.rid,1))).toBe(before);expect(canonical(w.store.meta('credential'))).toBe(keyBefore);
  w.store.storage.sql.exec('DROP TRIGGER reject_test_approval');await w.store.approve(w.rid,assertion);expect(w.record().approval).toBe('approved');
}));
